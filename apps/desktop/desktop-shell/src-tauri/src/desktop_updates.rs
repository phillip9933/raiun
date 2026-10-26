use crate::desktop_updates_policy::{self, Channel, ReleaseOffer, should_check, should_offer};
use reqwest::{Client, Response, Url, redirect};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs,
    io::Write,
    path::PathBuf,
    sync::Arc,
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Manager};
use tauri_plugin_opener::OpenerExt;
use tauri_plugin_updater::{Update, UpdaterExt};

const MAX_RELEASE_LIST_BYTES: usize = 2 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 512 * 1024;
const MAX_PACKAGE_BYTES: usize = 512 * 1024 * 1024;
const MAX_RELEASES: usize = 100;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(25);
const UPDATE_USER_AGENT: &str = "Raiun-Desktop-Updater";
const UPDATE_PUBLIC_KEY: Option<&str> = option_env!("RAIUN_DESKTOP_UPDATE_PUBKEY");

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Preferences {
    automatic_checks: bool,
    channel: String,
    dismissed_tag: Option<String>,
    last_check_unix: Option<u64>,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            automatic_checks: true,
            channel: "beta".into(),
            dismissed_tag: None,
            last_check_unix: None,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct DesktopUpdateStatus {
    pub state: String,
    pub version: Option<String>,
    pub tag: Option<String>,
    pub release_url: Option<String>,
    pub notes: Option<String>,
    pub error: Option<String>,
    pub automatic_checks: bool,
    pub channel: String,
    pub dismissed_tag: Option<String>,
    pub last_check_unix: Option<u64>,
    pub key_configured: bool,
    pub downloaded: bool,
}

struct CachedUpdate {
    offer: ReleaseOffer,
    update: Update,
    bytes: Arc<[u8]>,
}

pub struct DesktopUpdateState {
    preferences: Mutex<Preferences>,
    status: Mutex<DesktopUpdateStatus>,
    cached: Mutex<Option<CachedUpdate>>,
    transition: Mutex<()>,
    settings_revision: AtomicU64,
    busy: Arc<AtomicBool>,
}

impl DesktopUpdateState {
    pub fn load(app: &AppHandle) -> Self {
        let preferences = load_preferences(app).unwrap_or_default();
        let status = status_from_preferences(&preferences, "idle", None, None);
        Self {
            preferences: Mutex::new(preferences),
            status: Mutex::new(status),
            cached: Mutex::new(None),
            transition: Mutex::new(()),
            settings_revision: AtomicU64::new(0),
            busy: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn lock_transition(&self) -> Result<MutexGuard<'_, ()>, String> {
        self.transition
            .lock()
            .map_err(|_| "Desktop update transition state is unavailable".to_string())
    }
}

pub struct UpdateBusyGuard(Arc<AtomicBool>);

impl Drop for UpdateBusyGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn try_begin_busy(busy: &Arc<AtomicBool>) -> Option<UpdateBusyGuard> {
    (!busy.swap(true, Ordering::AcqRel)).then(|| UpdateBusyGuard(Arc::clone(busy)))
}

pub fn begin_install(app: &AppHandle) -> Result<UpdateBusyGuard, String> {
    let state = app
        .try_state::<DesktopUpdateState>()
        .ok_or_else(|| "Desktop update settings are unavailable".to_string())?;
    try_begin_busy(&state.busy)
        .ok_or_else(|| "Another Desktop update operation is already in progress".to_string())
}

pub fn updater_plugin() -> tauri::plugin::TauriPlugin<tauri::Wry, tauri_plugin_updater::Config> {
    let key = UPDATE_PUBLIC_KEY
        .filter(|key| !key.trim().is_empty())
        .unwrap_or("");
    tauri_plugin_updater::Builder::new().pubkey(key).build()
}

#[tauri::command]
pub fn desktop_update_status(app: AppHandle) -> Result<DesktopUpdateStatus, String> {
    let state = app
        .try_state::<DesktopUpdateState>()
        .ok_or_else(|| "Desktop update settings are unavailable".to_string())?;
    state
        .status
        .lock()
        .map(|status| status.clone())
        .map_err(|_| "Desktop update status is unavailable".to_string())
}

#[tauri::command]
pub fn set_desktop_update_preferences(
    app: AppHandle,
    automatic_checks: bool,
    channel: String,
) -> Result<DesktopUpdateStatus, String> {
    let channel_value = parse_channel(&channel)?;
    let state = app
        .try_state::<DesktopUpdateState>()
        .ok_or_else(|| "Desktop update settings are unavailable".to_string())?;
    let _transition = state.lock_transition()?;
    let mut preferences = state
        .preferences
        .lock()
        .map_err(|_| "Desktop update settings are unavailable".to_string())?;
    let previous = preferences.clone();
    preferences.automatic_checks = automatic_checks;
    preferences.channel = channel_string(channel_value).to_owned();
    if let Err(error) = persist_preferences(&app, &preferences) {
        *preferences = previous;
        return Err(error);
    }
    state.settings_revision.fetch_add(1, Ordering::AcqRel);
    if previous.channel != preferences.channel {
        *state
            .cached
            .lock()
            .map_err(|_| "The downloaded update is unavailable".to_string())? = None;
    }
    let mut status = state
        .status
        .lock()
        .map_err(|_| "Desktop update status is unavailable".to_string())?;
    status.automatic_checks = preferences.automatic_checks;
    status.channel = preferences.channel.clone();
    status.dismissed_tag = preferences.dismissed_tag.clone();
    status.last_check_unix = preferences.last_check_unix;
    Ok(status.clone())
}

#[tauri::command]
pub fn dismiss_desktop_update(app: AppHandle, tag: String) -> Result<DesktopUpdateStatus, String> {
    if tag.len() > 128 || !tag.starts_with("desktop-v") || tag.contains('/') {
        return Err("That Desktop release cannot be dismissed".into());
    }
    let state = app
        .try_state::<DesktopUpdateState>()
        .ok_or_else(|| "Desktop update settings are unavailable".to_string())?;
    let _transition = state.lock_transition()?;
    let mut preferences = state
        .preferences
        .lock()
        .map_err(|_| "Desktop update settings are unavailable".to_string())?;
    let previous = preferences.clone();
    preferences.dismissed_tag = Some(tag);
    if let Err(error) = persist_preferences(&app, &preferences) {
        *preferences = previous;
        return Err(error);
    }
    state.settings_revision.fetch_add(1, Ordering::AcqRel);
    let mut cached = state
        .cached
        .lock()
        .map_err(|_| "The downloaded update is unavailable".to_string())?;
    if cached.as_ref().is_some_and(|cached| {
        Some(cached.offer.tag.as_str()) == preferences.dismissed_tag.as_deref()
    }) {
        *cached = None;
    }
    let mut status = state
        .status
        .lock()
        .map_err(|_| "Desktop update status is unavailable".to_string())?;
    status.dismissed_tag = preferences.dismissed_tag.clone();
    if status.tag == preferences.dismissed_tag {
        status.state = "dismissed".into();
        status.downloaded = false;
    }
    Ok(status.clone())
}

#[tauri::command]
pub fn open_desktop_release(app: AppHandle, tag: String) -> Result<(), String> {
    let version = tag
        .strip_prefix("desktop-v")
        .filter(|value| value.len() <= 96)
        .and_then(|value| semver::Version::parse(value).ok())
        .ok_or_else(|| "That Desktop release link is invalid".to_string())?;
    let canonical_tag = format!("desktop-v{version}");
    if tag != canonical_tag {
        return Err("That Desktop release link is invalid".into());
    }
    let url = Url::parse(&format!(
        "{}/releases/tag/{canonical_tag}",
        desktop_updates_policy::PROJECT_URL
    ))
    .map_err(display_error)?;
    app.opener()
        .open_url(url.as_str(), None::<&str>)
        .map_err(display_error)
}

#[tauri::command]
pub async fn check_desktop_update(
    app: AppHandle,
    manual: bool,
) -> Result<DesktopUpdateStatus, String> {
    check_or_download(&app, manual, false, None).await
}

#[tauri::command]
pub async fn download_desktop_update(
    app: AppHandle,
    expected_tag: String,
) -> Result<DesktopUpdateStatus, String> {
    if !is_canonical_desktop_tag(&expected_tag) {
        return Err("That Desktop release selection is invalid".into());
    }
    check_or_download(&app, true, true, Some(expected_tag)).await
}

pub fn cached_for_install(app: &AppHandle) -> Result<(Update, Arc<[u8]>, String), String> {
    let state = app
        .try_state::<DesktopUpdateState>()
        .ok_or_else(|| "Desktop update settings are unavailable".to_string())?;
    let preferences = state
        .preferences
        .lock()
        .map_err(|_| "Desktop update settings are unavailable".to_string())?
        .clone();
    let mut cache = state
        .cached
        .lock()
        .map_err(|_| "The downloaded update is unavailable".to_string())?;
    let cached = cache
        .as_mut()
        .ok_or_else(|| "Download and verify a Desktop update before installing it".to_string())?;
    let status = state
        .status
        .lock()
        .map_err(|_| "Desktop update status is unavailable".to_string())?;
    if status.state != "downloaded" || status.tag.as_deref() != Some(cached.offer.tag.as_str()) {
        return Err("The downloaded update is no longer the selected verified release".into());
    }
    drop(status);
    let channel = parse_channel(&preferences.channel)?;
    let offer_is_beta = !cached.offer.version.pre.is_empty();
    let installed = semver::Version::parse(env!("CARGO_PKG_VERSION"))
        .map_err(|_| "Installed Desktop version is invalid".to_string())?;
    if (channel == Channel::Stable && offer_is_beta)
        || cached.offer.version <= installed
        || !should_offer(&cached.offer, preferences.dismissed_tag.as_deref())
        || cached.update.version != cached.offer.version.to_string()
        || cached.update.target != update_target()?
    {
        *cache = None;
        return Err("The downloaded update no longer matches the selected release settings".into());
    }
    cached
        .update
        .verify(&cached.bytes)
        .map_err(|error| format!("The downloaded update failed signature verification: {error}"))?;
    Ok((
        cached.update.clone(),
        cached.bytes.clone(),
        cached.offer.tag.clone(),
    ))
}

async fn check_or_download(
    app: &AppHandle,
    manual: bool,
    download: bool,
    expected_tag: Option<String>,
) -> Result<DesktopUpdateStatus, String> {
    let state = app
        .try_state::<DesktopUpdateState>()
        .ok_or_else(|| "Desktop update settings are unavailable".to_string())?;
    let Some(_busy) = try_begin_busy(&state.busy) else {
        return state
            .status
            .lock()
            .map(|status| status.clone())
            .map_err(|_| "Desktop update status is unavailable".to_string());
    };
    let (preferences, settings_revision) = {
        let _transition = state.lock_transition()?;
        let mut preferences = state
            .preferences
            .lock()
            .map_err(|_| "Desktop update settings are unavailable".to_string())?
            .clone();
        let resumed_dismissal = resume_dismissal_for_manual_request(&mut preferences, manual);
        let now = now_unix();
        if !should_check(
            manual,
            preferences.automatic_checks,
            preferences.last_check_unix,
            now,
        ) {
            return desktop_update_status(app.clone());
        }
        preferences.last_check_unix = Some(now);
        persist_preferences(app, &preferences)?;
        if let Ok(mut saved) = state.preferences.lock() {
            *saved = preferences.clone();
        }
        if resumed_dismissal {
            state.settings_revision.fetch_add(1, Ordering::AcqRel);
        }
        (preferences, state.settings_revision.load(Ordering::Acquire))
    };

    let result = check_inner(app, &preferences, download, expected_tag.as_deref()).await;
    let _transition = state.lock_transition()?;
    if state.settings_revision.load(Ordering::Acquire) != settings_revision {
        return desktop_update_status(app.clone());
    }
    let status = match result {
        Ok((mut status, cached)) => {
            if let Ok(mut slot) = state.cached.lock() {
                *slot = cached;
            }
            status.last_check_unix = preferences.last_check_unix;
            status
        }
        Err(error) => status_from_preferences(&preferences, "error", None, Some(error)),
    };
    if let Ok(mut saved) = state.status.lock() {
        *saved = status.clone();
    }
    Ok(status)
}

async fn check_inner(
    app: &AppHandle,
    preferences: &Preferences,
    download: bool,
    expected_tag: Option<&str>,
) -> Result<(DesktopUpdateStatus, Option<CachedUpdate>), String> {
    let channel = parse_channel(&preferences.channel)?;
    let client = github_client(false)?;
    let releases_bytes = bounded_get(
        &client,
        Url::parse(desktop_updates_policy::RELEASES_API).map_err(display_error)?,
        MAX_RELEASE_LIST_BYTES,
    )
    .await?;
    let offer =
        desktop_updates_policy::select_release(&releases_bytes, env!("CARGO_PKG_VERSION"), channel)
            .map_err(|error| format!("Could not read the Desktop release list: {error:?}"))?;
    let Some(offer) = offer else {
        return Ok((
            status_from_preferences(preferences, "current", None, None),
            None,
        ));
    };
    let dismissed = !should_offer(&offer, preferences.dismissed_tag.as_deref());
    let base_status = DesktopUpdateStatus {
        state: if dismissed { "dismissed" } else { "available" }.into(),
        version: Some(offer.version.to_string()),
        tag: Some(offer.tag.clone()),
        release_url: Some(offer.release_url.clone()),
        notes: Some(offer.notes.clone()),
        error: None,
        automatic_checks: preferences.automatic_checks,
        channel: preferences.channel.clone(),
        dismissed_tag: preferences.dismissed_tag.clone(),
        last_check_unix: preferences.last_check_unix,
        key_configured: configured_public_key().is_some(),
        downloaded: false,
    };
    if expected_tag.is_some_and(|expected| expected != offer.tag) {
        return Ok((base_status, None));
    }
    if dismissed {
        return Ok((base_status, None));
    }

    let releases: Value = serde_json::from_slice(&releases_bytes)
        .map_err(|_| "The public Desktop release list is invalid".to_string())?;
    let release = find_release(&releases, &offer.tag)?;
    let manifest_url = match exact_asset_url(release, &offer.tag, "desktop-update.json") {
        Ok(url) => url,
        Err(error) => {
            let mut status = base_status;
            status.state = "unavailable".into();
            status.error = Some(format!(
                "A signed updater manifest is not available for this release. Use the release page to download manually. ({error})"
            ));
            return Ok((status, None));
        }
    };
    let target = match update_target() {
        Ok(target) => target,
        Err(error) => {
            let mut status = base_status;
            status.state = "unavailable".into();
            status.error = Some(format!(
                "Automatic updates are unavailable for this package. Use the release page to download manually. ({error})"
            ));
            return Ok((status, None));
        }
    };
    let manifest_client = github_client(true)?;
    let manifest_bytes = match bounded_get(
        &manifest_client,
        manifest_url.clone(),
        MAX_MANIFEST_BYTES,
    )
    .await
    {
        Ok(bytes) => bytes,
        Err(error) => {
            let mut status = base_status;
            status.state = "unavailable".into();
            status.error = Some(format!(
                "The signed updater manifest could not be read. Use the release page to download manually. ({error})"
            ));
            return Ok((status, None));
        }
    };
    let manifest = match validate_manifest(&manifest_bytes, &offer, &target, release) {
        Ok(manifest) => manifest,
        Err(error) => {
            let mut status = base_status;
            status.state = "unavailable".into();
            status.error = Some(format!(
                "The signed updater manifest is invalid or has no package for this build. Use the release page to download manually. ({error})"
            ));
            return Ok((status, None));
        }
    };
    let Some(public_key) = configured_public_key() else {
        let mut status = base_status;
        status.error = Some("Signed automatic updates are not configured in this build. Use the release page to download updates manually.".into());
        return Ok((status, None));
    };
    if public_key.len() > 1024 || public_key.contains('\n') || public_key.contains('\r') {
        return Err("The embedded Desktop update verification key is invalid".into());
    }

    let endpoint = manifest_url.clone();
    let updater = match app
        .updater_builder()
        .endpoints(vec![endpoint])
        .map_err(display_error)
        .and_then(|builder| {
            builder
                .target(target.clone())
                .timeout(REQUEST_TIMEOUT)
                .configure_client(restricted_redirects)
                .build()
                .map_err(display_error)
        }) {
        Ok(updater) => updater,
        Err(error) => {
            return Ok((
                unavailable_status(
                    base_status,
                    format!(
                        "The signed update could not be prepared. Use the release page to download manually. ({error})"
                    ),
                ),
                None,
            ));
        }
    };
    // Use the bounded manifest already fetched from this exact release rather
    // than making a second, unbounded updater-manifest request.
    let update = match updater.restore_update(manifest.clone()) {
        Ok(Some(update)) => update,
        Ok(None) => {
            return Ok((
                unavailable_status(
                    base_status,
                    "Tauri did not accept the selected release as a safe update. Use the release page to download manually.".into(),
                ),
                None,
            ));
        }
        Err(error) => {
            return Ok((
                unavailable_status(
                    base_status,
                    format!(
                        "The signed update manifest could not be validated. Use the release page to download manually. ({error})"
                    ),
                ),
                None,
            ));
        }
    };
    let selected_platform = manifest
        .get("platforms")
        .and_then(Value::as_object)
        .and_then(|platforms| platforms.get(&target))
        .ok_or_else(|| "The validated Desktop update platform is missing".to_string())?;
    let expected_url = selected_platform
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| "The Desktop update manifest has no package URL".to_string())?;
    let expected_signature = selected_platform
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| "The Desktop update manifest has no package signature".to_string())?;
    if update.version != offer.version.to_string()
        || update.target != target
        || update.download_url.as_str() != expected_url
        || update.signature != expected_signature
        || update.raw_json.get("version").and_then(Value::as_str)
            != Some(offer.version.to_string().as_str())
    {
        return Ok((
            unavailable_status(
                base_status,
                "The signed Desktop update does not match the selected release, platform, or version. Use the release page to download manually.".into(),
            ),
            None,
        ));
    }
    if !download {
        return Ok((base_status, None));
    }

    let package_client = github_client(true)?;
    let package_bytes = match bounded_get(
        &package_client,
        update.download_url.clone(),
        MAX_PACKAGE_BYTES,
    )
    .await
    {
        Ok(bytes) => bytes,
        Err(error) => {
            return Ok((
                unavailable_status(
                    base_status,
                    format!(
                        "The signed package could not be downloaded. Use the release page to download manually. ({error})"
                    ),
                ),
                None,
            ));
        }
    };
    if let Err(error) = update.verify(&package_bytes) {
        return Ok((
            unavailable_status(
                base_status,
                format!(
                    "The downloaded package failed signature verification. Use the release page to download manually. ({error})"
                ),
            ),
            None,
        ));
    }
    let status = DesktopUpdateStatus {
        state: "downloaded".into(),
        version: Some(offer.version.to_string()),
        tag: Some(offer.tag.clone()),
        release_url: Some(offer.release_url.clone()),
        notes: Some(offer.notes.clone()),
        error: None,
        automatic_checks: preferences.automatic_checks,
        channel: preferences.channel.clone(),
        dismissed_tag: preferences.dismissed_tag.clone(),
        last_check_unix: preferences.last_check_unix,
        key_configured: true,
        downloaded: true,
    };
    Ok((
        status,
        Some(CachedUpdate {
            offer,
            update,
            bytes: Arc::from(package_bytes),
        }),
    ))
}

fn validate_manifest(
    manifest_bytes: &[u8],
    offer: &ReleaseOffer,
    target: &str,
    release: &Value,
) -> Result<Value, String> {
    let manifest: Value = serde_json::from_slice(manifest_bytes)
        .map_err(|_| "The Desktop update manifest is not valid JSON".to_string())?;
    if manifest.get("version").and_then(Value::as_str) != Some(offer.version.to_string().as_str()) {
        return Err("The Desktop update manifest version does not match its release tag".into());
    }
    let platforms = manifest
        .get("platforms")
        .and_then(Value::as_object)
        .ok_or_else(|| "The Desktop update manifest has no platform packages".to_string())?;
    let platform = platforms
        .get(target)
        .ok_or_else(|| format!("The Desktop update manifest has no package for {target}"))?;
    let url = platform
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| "The Desktop update package URL is missing".to_string())?;
    let signature = platform
        .get("signature")
        .and_then(Value::as_str)
        .filter(|signature| !signature.trim().is_empty() && signature.len() <= 16 * 1024)
        .ok_or_else(|| {
            "The Desktop update package signature is missing or too large".to_string()
        })?;
    let parsed = Url::parse(url).map_err(display_error)?;
    if parsed.scheme() != "https"
        || parsed.host_str() != Some("github.com")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err("The Desktop update package URL is outside the trusted GitHub release".into());
    }
    let suffix = bundle_suffix(target)?;
    let filename = parsed
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .ok_or_else(|| "The Desktop update package URL has no asset name".to_string())?;
    if !filename.ends_with(suffix)
        || exact_asset_url(release, &offer.tag, filename)?.as_str() != url
    {
        return Err(
            "The Desktop update package does not match the selected platform bundle".into(),
        );
    }
    let _ = signature;
    Ok(manifest)
}

fn bundle_suffix(target: &str) -> Result<&'static str, String> {
    if target.ends_with("-appimage") {
        Ok(".AppImage")
    } else if target.ends_with("-deb") {
        Ok(".deb")
    } else if target.ends_with("-nsis") {
        Ok(".nsis.zip")
    } else {
        Err("Automatic updates are unavailable for this installed package format".into())
    }
}

fn update_target() -> Result<String, String> {
    let base = tauri_plugin_updater::target().ok_or_else(|| {
        "Automatic updates are unavailable for this operating system or architecture".to_string()
    })?;
    let bundle = match tauri::utils::platform::bundle_type() {
        Some(tauri::utils::config::BundleType::AppImage) => "appimage",
        Some(tauri::utils::config::BundleType::Deb) => "deb",
        Some(tauri::utils::config::BundleType::Nsis) => "nsis",
        Some(_) => {
            return Err(
                "Automatic updates are unavailable for this installed package format".into(),
            );
        }
        None => {
            return Err(
                "Automatic updates are available only in a packaged Raiun installation".into(),
            );
        }
    };
    Ok(format!("{base}-{bundle}"))
}

fn configured_public_key() -> Option<&'static str> {
    UPDATE_PUBLIC_KEY.filter(|key| !key.trim().is_empty())
}

fn parse_channel(value: &str) -> Result<Channel, String> {
    match value {
        "stable" => Ok(Channel::Stable),
        "beta" => Ok(Channel::Beta),
        _ => Err("Choose the stable or beta Desktop update channel".into()),
    }
}

fn channel_string(channel: Channel) -> &'static str {
    match channel {
        Channel::Stable => "stable",
        Channel::Beta => "beta",
    }
}

fn find_release<'a>(releases: &'a Value, tag: &str) -> Result<&'a Value, String> {
    releases
        .as_array()
        .filter(|items| items.len() <= MAX_RELEASES)
        .and_then(|items| {
            items.iter().find(|release| {
                release.get("tag_name").and_then(Value::as_str) == Some(tag)
                    && release.get("draft").and_then(Value::as_bool) == Some(false)
            })
        })
        .ok_or_else(|| "The selected Desktop release disappeared from GitHub".to_string())
}

fn exact_asset_url(release: &Value, tag: &str, asset_name: &str) -> Result<Url, String> {
    if asset_name.is_empty()
        || asset_name.len() > 256
        || !asset_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err("The Desktop release contains an invalid update asset name".into());
    }
    let mut expected = Url::parse("https://github.com/phillip9933/raiun/releases/download")
        .map_err(display_error)?;
    expected
        .path_segments_mut()
        .map_err(|_| "The Desktop release asset URL is invalid".to_string())?
        .push(tag)
        .push(asset_name);
    let assets = release
        .get("assets")
        .and_then(Value::as_array)
        .ok_or_else(|| "The selected Desktop release has no asset list".to_string())?;
    let asset = assets
        .iter()
        .find(|asset| asset.get("name").and_then(Value::as_str) == Some(asset_name))
        .ok_or_else(|| format!("The selected Desktop release does not publish {asset_name}"))?;
    let raw_url = asset
        .get("browser_download_url")
        .and_then(Value::as_str)
        .ok_or_else(|| "The selected Desktop release asset has no download link".to_string())?;
    let parsed = Url::parse(raw_url).map_err(display_error)?;
    if parsed != expected {
        return Err(
            "The selected Desktop release asset link does not match its tag and name".into(),
        );
    }
    Ok(expected)
}

fn is_trusted_github_url(url: &Url, allow_api: bool) -> bool {
    let trusted_host = matches!(
        url.host_str(),
        Some("github.com")
            | Some("release-assets.githubusercontent.com")
            | Some("objects.githubusercontent.com")
            | Some("github-releases.githubusercontent.com")
    ) || allow_api && url.host_str() == Some("api.github.com");
    url.scheme() == "https"
        && trusted_host
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none_or(|port| port == 443)
}

fn github_client(allow_release_redirects: bool) -> Result<Client, String> {
    let mut builder = Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .user_agent(UPDATE_USER_AGENT)
        .https_only(true);
    if allow_release_redirects {
        builder = builder.redirect(redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 4 || !is_trusted_github_url(attempt.url(), false) {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }));
    } else {
        builder = builder.redirect(redirect::Policy::none());
    }
    builder.build().map_err(display_error)
}

async fn bounded_get(client: &Client, url: Url, maximum: usize) -> Result<Vec<u8>, String> {
    if !is_trusted_github_url(&url, true) {
        return Err("The Desktop update request is outside the trusted GitHub hosts".into());
    }
    let response = client
        .get(url)
        .header(
            reqwest::header::ACCEPT,
            "application/vnd.github+json, application/octet-stream",
        )
        .send()
        .await
        .map_err(display_error)?;
    read_bounded_response(response, maximum).await
}

async fn read_bounded_response(response: Response, maximum: usize) -> Result<Vec<u8>, String> {
    let response = response.error_for_status().map_err(display_error)?;
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err("The Desktop update response exceeded its size limit".into());
    }
    if !is_trusted_github_url(response.url(), true) {
        return Err("The Desktop update response came from an untrusted host".into());
    }
    let mut response = response;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(display_error)? {
        if bytes.len().saturating_add(chunk.len()) > maximum {
            return Err("The Desktop update response exceeded its size limit".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.is_empty() {
        return Err("The Desktop update response was empty".into());
    }
    Ok(bytes)
}

fn restricted_redirects(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    builder
        .timeout(REQUEST_TIMEOUT)
        .https_only(true)
        .redirect(redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 4 || !is_trusted_github_url(attempt.url(), false) {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
}

fn status_from_preferences(
    preferences: &Preferences,
    state: &str,
    offer: Option<&ReleaseOffer>,
    error: Option<String>,
) -> DesktopUpdateStatus {
    DesktopUpdateStatus {
        state: state.into(),
        version: offer.map(|offer| offer.version.to_string()),
        tag: offer.map(|offer| offer.tag.clone()),
        release_url: offer.map(|offer| offer.release_url.clone()),
        notes: offer.map(|offer| offer.notes.clone()),
        error,
        automatic_checks: preferences.automatic_checks,
        channel: preferences.channel.clone(),
        dismissed_tag: preferences.dismissed_tag.clone(),
        last_check_unix: preferences.last_check_unix,
        key_configured: configured_public_key().is_some(),
        downloaded: false,
    }
}

fn unavailable_status(mut status: DesktopUpdateStatus, error: String) -> DesktopUpdateStatus {
    status.state = "unavailable".into();
    status.error = Some(error);
    status.downloaded = false;
    status
}

fn preferences_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|path| path.join("desktop-updater.json"))
        .map_err(display_error)
}

fn load_preferences(app: &AppHandle) -> Option<Preferences> {
    let path = preferences_path(app).ok()?;
    let bytes = fs::read(path).ok()?;
    if bytes.len() > 32 * 1024 {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

fn persist_preferences(app: &AppHandle, preferences: &Preferences) -> Result<(), String> {
    let path = preferences_path(app)?;
    persist_preferences_at(&path, preferences)
}

fn persist_preferences_at(path: &std::path::Path, preferences: &Preferences) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "The Desktop update settings path is invalid".to_string())?;
    fs::create_dir_all(parent).map_err(display_error)?;
    let bytes = serde_json::to_vec(preferences).map_err(display_error)?;
    if bytes.len() > 32 * 1024 {
        return Err("Desktop update settings exceeded their size limit".into());
    }
    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(display_error)?;
    temporary.write_all(&bytes).map_err(display_error)?;
    temporary.as_file().sync_all().map_err(display_error)?;
    temporary
        .persist(path)
        .map_err(|error| display_error(error.error))?;
    #[cfg(unix)]
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(display_error)?;
    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn is_canonical_desktop_tag(tag: &str) -> bool {
    tag.strip_prefix("desktop-v")
        .and_then(|version| semver::Version::parse(version).ok())
        .is_some_and(|version| tag == format!("desktop-v{version}"))
}

fn resume_dismissal_for_manual_request(preferences: &mut Preferences, manual: bool) -> bool {
    manual && preferences.dismissed_tag.take().is_some()
}

fn display_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn later_suppresses_only_automatic_same_tag_and_manual_check_resumes_it() {
        let tag = "desktop-v1.2.3";
        let mut preferences = Preferences {
            dismissed_tag: Some(tag.into()),
            ..Preferences::default()
        };
        let offer = ReleaseOffer {
            tag: tag.into(),
            version: semver::Version::parse("1.2.3").unwrap(),
            release_url: format!("{}/releases/tag/{tag}", desktop_updates_policy::PROJECT_URL),
            notes: String::new(),
        };
        assert!(!should_offer(&offer, preferences.dismissed_tag.as_deref()));
        assert!(!resume_dismissal_for_manual_request(
            &mut preferences,
            false
        ));
        assert_eq!(preferences.dismissed_tag.as_deref(), Some(tag));
        assert!(!should_offer(&offer, preferences.dismissed_tag.as_deref()));

        assert!(resume_dismissal_for_manual_request(&mut preferences, true));
        assert_eq!(preferences.dismissed_tag, None);
        assert!(should_offer(&offer, preferences.dismissed_tag.as_deref()));
        assert!(is_canonical_desktop_tag(tag));
        assert!(!is_canonical_desktop_tag("desktop-v01.2.3"));
    }

    #[test]
    fn preferences_replace_atomically_and_leave_a_complete_document() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("desktop-updater.json");
        let original = Preferences::default();
        persist_preferences_at(&path, &original).unwrap();

        let updated = Preferences {
            automatic_checks: false,
            channel: "stable".into(),
            dismissed_tag: Some("desktop-v1.2.3".into()),
            last_check_unix: Some(123),
        };
        persist_preferences_at(&path, &updated).unwrap();

        let bytes = fs::read(&path).unwrap();
        let restored: Preferences = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(restored.automatic_checks, updated.automatic_checks);
        assert_eq!(restored.channel, updated.channel);
        assert_eq!(restored.dismissed_tag, updated.dismissed_tag);
        assert_eq!(restored.last_check_unix, updated.last_check_unix);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn updater_settings_transition_excludes_a_second_transition_and_busy_owner() {
        let state = DesktopUpdateState {
            preferences: Mutex::new(Preferences::default()),
            status: Mutex::new(DesktopUpdateStatus::default()),
            cached: Mutex::new(None),
            transition: Mutex::new(()),
            settings_revision: AtomicU64::new(0),
            busy: Arc::new(AtomicBool::new(false)),
        };
        let _transition = state.lock_transition().unwrap();
        assert!(state.transition.try_lock().is_err());

        let busy = try_begin_busy(&state.busy).unwrap();
        assert!(try_begin_busy(&state.busy).is_none());
        drop(busy);
        assert!(try_begin_busy(&state.busy).is_some());
    }

    #[test]
    fn exact_asset_link_is_required_for_selected_tag() {
        let release = json!({"assets":[{"name":"desktop-update.json","browser_download_url":"https://github.com/phillip9933/raiun/releases/download/desktop-v1.2.0/desktop-update.json"}]});
        let url = exact_asset_url(&release, "desktop-v1.2.0", "desktop-update.json").unwrap();
        assert_eq!(
            url.as_str(),
            "https://github.com/phillip9933/raiun/releases/download/desktop-v1.2.0/desktop-update.json"
        );
        assert!(exact_asset_url(&release, "desktop-v1.2.1", "desktop-update.json").is_err());
    }

    #[test]
    fn update_target_requires_exact_supported_bundle_kind() {
        assert_eq!(bundle_suffix("linux-x86_64-appimage").unwrap(), ".AppImage");
        assert_eq!(bundle_suffix("windows-x86_64-nsis").unwrap(), ".nsis.zip");
        assert!(bundle_suffix("linux-x86_64").is_err());
    }

    #[test]
    fn manifest_must_bind_exact_version_target_url_signature_and_release_asset() {
        let offer = ReleaseOffer {
            tag: "desktop-v1.2.0".into(),
            version: semver::Version::parse("1.2.0").unwrap(),
            release_url: "https://github.com/phillip9933/raiun/releases/tag/desktop-v1.2.0".into(),
            notes: "notes".into(),
        };
        let filename = "raiun-1.2.0-linux-x86_64.AppImage";
        let package_url = format!(
            "https://github.com/phillip9933/raiun/releases/download/{}/{}",
            offer.tag, filename
        );
        let release = json!({"assets":[{"name":filename,"browser_download_url":package_url}]});
        let manifest = json!({"version":"1.2.0","platforms":{"linux-x86_64-appimage":{"url":package_url,"signature":"signature"}}});
        let result = validate_manifest(
            &serde_json::to_vec(&manifest).unwrap(),
            &offer,
            "linux-x86_64-appimage",
            &release,
        )
        .unwrap();
        assert_eq!(
            result["platforms"]["linux-x86_64-appimage"]["url"],
            package_url
        );
        let wrong_version = manifest.to_string().replace("1.2.0", "1.2.1");
        assert!(
            validate_manifest(
                wrong_version.as_bytes(),
                &offer,
                "linux-x86_64-appimage",
                &release
            )
            .is_err()
        );
        assert!(
            validate_manifest(
                &serde_json::to_vec(&manifest).unwrap(),
                &offer,
                "linux-x86_64-deb",
                &release
            )
            .is_err()
        );
    }

    #[test]
    fn untrusted_urls_and_nonpackage_asset_shapes_fail_closed() {
        let offer = ReleaseOffer {
            tag: "desktop-v1.2.0".into(),
            version: semver::Version::parse("1.2.0").unwrap(),
            release_url: "https://github.com/phillip9933/raiun/releases/tag/desktop-v1.2.0".into(),
            notes: String::new(),
        };
        let bad = json!({"version":"1.2.0","platforms":{"windows-x86_64-nsis":{"url":"https://attacker.invalid/installer.nsis.zip","signature":"x"}}});
        let release = json!({"assets":[]});
        assert!(
            validate_manifest(
                &bad.to_string().into_bytes(),
                &offer,
                "windows-x86_64-nsis",
                &release
            )
            .is_err()
        );
    }

    #[test]
    fn github_transport_rejects_non_https_hosts_userinfo_and_nonstandard_ports() {
        for raw in [
            "http://github.com/releases",
            "https://github.com:444/releases",
            "https://user@github.com/releases",
            "https://github.com.attacker.invalid/releases",
        ] {
            assert!(!is_trusted_github_url(&Url::parse(raw).unwrap(), false));
        }
        assert!(is_trusted_github_url(
            &Url::parse("https://release-assets.githubusercontent.com/file").unwrap(),
            false
        ));
        assert!(is_trusted_github_url(
            &Url::parse("https://api.github.com/repos").unwrap(),
            true
        ));
        assert!(!is_trusted_github_url(
            &Url::parse("https://api.github.com/repos").unwrap(),
            false
        ));
    }
}
