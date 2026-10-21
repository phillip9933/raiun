use raiun_core::{CONFIG_SCHEMA_VERSION, Config, MediaImportJob, validate_media_import_jobs};
use raiun_opencloud::{ProxyConfig, transfer_budget::TransferLimits};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub const MAX_PAUSED_SPACE_IDS: usize = 256;
pub const MAX_SPACE_ID_BYTES: usize = 512;

#[derive(Clone, Serialize, Deserialize)]
pub struct Settings {
    pub config: Config,
    pub server: Option<String>,
    pub client_id: String,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub retired_pair_ids: Vec<String>,
    pub paused: bool,
    #[serde(default)]
    pub paused_space_ids: Vec<String>,
    #[serde(default)]
    pub mount_enabled: bool,
    /// Recurring upload-only media backup jobs. Missing in legacy settings.
    #[serde(default)]
    pub media_jobs: Vec<MediaImportJob>,
    /// Transport route for this profile's bound account.
    #[serde(default)]
    pub network_proxy: ProxyConfig,
    /// Account identity that owns the selected route. `None` is a pre-sign-in
    /// choice that is bound after the first successful authentication.
    #[serde(default)]
    pub network_proxy_account_id: Option<String>,
    #[serde(default = "default_proxy_revision")]
    pub network_proxy_revision: u64,
    /// Per-account content transfer ceilings. Missing in legacy settings means
    /// unlimited in each direction.
    #[serde(default)]
    pub bandwidth_limits: TransferLimits,
    #[serde(default)]
    pub bandwidth_account_id: Option<String>,
    #[serde(default = "default_bandwidth_revision")]
    pub bandwidth_revision: u64,
}

pub fn state_dir() -> Result<PathBuf, String> {
    let dir = if let Some(path) = std::env::var_os("RAIUN_STATE_DIR") {
        PathBuf::from(path)
    } else if let Some(path) = std::env::var_os("XDG_STATE_HOME") {
        PathBuf::from(path).join("raiun-desktop")
    } else {
        PathBuf::from(std::env::var_os("HOME").ok_or("HOME is unset")?)
            .join(".local/state/raiun-desktop")
    };
    if !dir.is_absolute() {
        return Err("State directory must be absolute".into());
    }
    if dir
        .symlink_metadata()
        .is_ok_and(|m| m.file_type().is_symlink())
    {
        return Err("State directory must not be a symbolic link".into());
    }
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = fs::metadata(&dir).map_err(|e| e.to_string())?;
        // Reject directories writable by another account before storing private state.
        if metadata.mode() & 0o022 != 0 {
            return Err("State directory must not be group/world writable".into());
        }
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    Ok(dir)
}

impl Settings {
    pub fn load(dir: &Path) -> Result<Self, String> {
        let path = dir.join("settings.json");
        if !path.exists() {
            let home = PathBuf::from(std::env::var_os("HOME").ok_or("HOME is unset")?);
            return Ok(Self {
                config: Config {
                    schema_version: CONFIG_SCHEMA_VERSION,
                    cloud_root: home.join("OpenCloud"),
                    pairs: vec![],
                },
                server: None,
                client_id: "OpenCloudDesktop".into(),
                account_id: None,
                retired_pair_ids: Vec::new(),
                paused: false,
                paused_space_ids: Vec::new(),
                mount_enabled: false,
                media_jobs: Vec::new(),
                network_proxy: ProxyConfig::System,
                network_proxy_account_id: None,
                network_proxy_revision: default_proxy_revision(),
                bandwidth_limits: TransferLimits::default(),
                bandwidth_account_id: None,
                bandwidth_revision: default_bandwidth_revision(),
            });
        }
        if path
            .symlink_metadata()
            .map_err(|e| e.to_string())?
            .file_type()
            .is_symlink()
        {
            return Err("Settings must not be a symbolic link".into());
        }
        let mut bytes = Vec::new();
        fs::File::open(path)
            .map_err(|e| e.to_string())?
            .take(1_048_577)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > 1_048_576 {
            return Err("Settings exceed size limit".into());
        }
        let settings: Self = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if settings.config.schema_version != CONFIG_SCHEMA_VERSION {
            return Err("Unsupported settings version".into());
        }
        validate_paused_space_ids(&settings.paused_space_ids)?;
        validate_media_import_jobs(&settings.media_jobs)?;
        settings
            .network_proxy
            .validate()
            .map_err(|_| "Saved proxy configuration is invalid".to_string())?;
        validate_proxy_account_binding(settings.network_proxy_account_id.as_deref())?;
        validate_proxy_account_owner(
            settings.network_proxy_account_id.as_deref(),
            settings.account_id.as_deref(),
        )?;
        if settings.network_proxy_revision == 0 {
            return Err("Proxy configuration revision is invalid".into());
        }
        validate_bandwidth_settings(&settings)?;
        Ok(settings)
    }
    pub fn save(&self, dir: &Path) -> Result<(), String> {
        validate_paused_space_ids(&self.paused_space_ids)?;
        validate_media_import_jobs(&self.media_jobs)?;
        self.network_proxy
            .validate()
            .map_err(|_| "Proxy configuration is invalid".to_string())?;
        validate_proxy_account_binding(self.network_proxy_account_id.as_deref())?;
        validate_proxy_account_owner(
            self.network_proxy_account_id.as_deref(),
            self.account_id.as_deref(),
        )?;
        if self.network_proxy_revision == 0 {
            return Err("Proxy configuration revision is invalid".into());
        }
        validate_bandwidth_settings(self)?;
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        if bytes.len() > 1_048_576 {
            return Err("Settings exceed size limit".into());
        }
        let mut file = tempfile::NamedTempFile::new_in(dir).map_err(|e| e.to_string())?;
        file.write_all(&bytes).map_err(|e| e.to_string())?;
        file.as_file().sync_all().map_err(|e| e.to_string())?;
        file.persist(dir.join("settings.json"))
            .map_err(|e| e.to_string())?;
        fs::File::open(dir)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())
    }
}

fn validate_proxy_account_binding(account_id: Option<&str>) -> Result<(), String> {
    if account_id
        .is_some_and(|id| id.is_empty() || id.len() > 512 || id.chars().any(char::is_control))
    {
        return Err("Proxy account binding is invalid".into());
    }
    Ok(())
}

fn validate_proxy_account_owner(
    proxy_account_id: Option<&str>,
    account_id: Option<&str>,
) -> Result<(), String> {
    if proxy_account_id.is_some() && proxy_account_id != account_id {
        return Err("Proxy configuration belongs to a different account".into());
    }
    Ok(())
}

fn default_proxy_revision() -> u64 {
    1
}

fn default_bandwidth_revision() -> u64 {
    1
}

fn validate_bandwidth_settings(settings: &Settings) -> Result<(), String> {
    settings
        .bandwidth_limits
        .validate()
        .map_err(|_| "Saved bandwidth limits are invalid".to_string())?;
    if settings.bandwidth_revision == 0 {
        return Err("Bandwidth settings revision is invalid".into());
    }
    validate_bandwidth_account_binding(settings.bandwidth_account_id.as_deref())?;
    validate_bandwidth_account_owner(
        settings.bandwidth_account_id.as_deref(),
        settings.account_id.as_deref(),
    )?;
    if settings.bandwidth_limits != TransferLimits::default()
        && settings.bandwidth_account_id.is_none()
    {
        return Err("Non-default bandwidth limits must be bound to an account".into());
    }
    Ok(())
}

fn validate_bandwidth_account_binding(account_id: Option<&str>) -> Result<(), String> {
    if account_id
        .is_some_and(|id| id.is_empty() || id.len() > 512 || id.chars().any(char::is_control))
    {
        return Err("Bandwidth account binding is invalid".into());
    }
    Ok(())
}

fn validate_bandwidth_account_owner(
    bandwidth_account_id: Option<&str>,
    account_id: Option<&str>,
) -> Result<(), String> {
    if bandwidth_account_id.is_some() && bandwidth_account_id != account_id {
        return Err("Bandwidth limits belong to a different account".into());
    }
    Ok(())
}

fn validate_paused_space_ids(ids: &[String]) -> Result<(), String> {
    if ids.len() > MAX_PAUSED_SPACE_IDS {
        return Err("Paused Space list exceeds its limit".into());
    }
    let mut unique = BTreeSet::new();
    for id in ids {
        if id.is_empty()
            || id.len() > MAX_SPACE_ID_BYTES
            || id.chars().any(char::is_control)
            || !unique.insert(id)
        {
            return Err("Paused Space IDs must be unique, nonempty, and bounded".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn legacy_settings_default_to_no_paused_spaces() {
        let dir = tempfile::tempdir().unwrap();
        let value = json!({
            "config": {
                "schema_version": CONFIG_SCHEMA_VERSION,
                "cloud_root": dir.path().join("cloud"),
                "pairs": []
            },
            "server": null,
            "client_id": "OpenCloudDesktop",
            "account_id": null,
            "retired_pair_ids": [],
            "paused": false,
            "mount_enabled": false
        });
        fs::write(
            dir.path().join("settings.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();

        let settings = Settings::load(dir.path()).unwrap();
        assert!(settings.paused_space_ids.is_empty());
        assert!(settings.media_jobs.is_empty());
        assert_eq!(settings.network_proxy, ProxyConfig::System);
        assert!(settings.network_proxy_account_id.is_none());
        assert_eq!(settings.network_proxy_revision, 1);
        assert_eq!(settings.bandwidth_limits, TransferLimits::default());
        assert!(settings.bandwidth_account_id.is_none());
        assert_eq!(settings.bandwidth_revision, 1);
    }

    #[test]
    fn media_jobs_persist_and_invalid_destination_identity_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut settings = Settings {
            config: Config {
                schema_version: CONFIG_SCHEMA_VERSION,
                cloud_root: dir.path().join("cloud"),
                pairs: vec![],
            },
            server: Some("https://cloud.example".into()),
            client_id: "OpenCloudDesktop".into(),
            account_id: Some("account-1".into()),
            retired_pair_ids: Vec::new(),
            paused: false,
            paused_space_ids: Vec::new(),
            mount_enabled: false,
            media_jobs: vec![MediaImportJob {
                id: "phone-import".into(),
                revision: 1,
                account_id: "account-1".into(),
                source_root: dir.path().join("Pictures"),
                space_id: "space-1".into(),
                destination_root: "/Photos".into(),
                destination_root_resource_id: "folder-id".into(),
                filter: raiun_core::MediaFilter::Photos,
                organization: raiun_core::MediaOrganization::PreserveRelativePath,
                filesystem_mtime_utc: false,
                interval_seconds: raiun_core::DEFAULT_MEDIA_SCAN_INTERVAL_SECONDS,
                enabled: true,
            }],
            network_proxy: ProxyConfig::System,
            network_proxy_account_id: Some("account-1".into()),
            network_proxy_revision: 1,
            bandwidth_limits: TransferLimits::default(),
            bandwidth_account_id: None,
            bandwidth_revision: 1,
        };
        settings.save(dir.path()).unwrap();
        assert_eq!(
            Settings::load(dir.path()).unwrap().media_jobs,
            settings.media_jobs
        );

        settings.media_jobs[0].destination_root_resource_id.clear();
        assert!(settings.save(dir.path()).is_err());
    }

    #[test]
    fn explicit_proxy_settings_round_trip_with_account_binding_and_revision() {
        let dir = tempfile::tempdir().unwrap();
        let proxy = ProxyConfig::Explicit {
            url: "https://proxy.example:8443".into(),
        };
        let mut settings = Settings {
            config: Config {
                schema_version: CONFIG_SCHEMA_VERSION,
                cloud_root: dir.path().join("cloud"),
                pairs: vec![],
            },
            server: Some("https://cloud.example".into()),
            client_id: "OpenCloudDesktop".into(),
            account_id: Some("account-1".into()),
            retired_pair_ids: Vec::new(),
            paused: false,
            paused_space_ids: Vec::new(),
            mount_enabled: false,
            media_jobs: Vec::new(),
            network_proxy: proxy.clone(),
            network_proxy_account_id: Some("account-1".into()),
            network_proxy_revision: 4,
            bandwidth_limits: TransferLimits::default(),
            bandwidth_account_id: None,
            bandwidth_revision: 1,
        };

        settings.save(dir.path()).unwrap();
        let loaded = Settings::load(dir.path()).unwrap();
        assert_eq!(loaded.network_proxy, proxy);
        assert_eq!(
            loaded.network_proxy_account_id.as_deref(),
            Some("account-1")
        );
        assert_eq!(loaded.network_proxy_revision, 4);

        settings.network_proxy_account_id = Some("other-account".into());
        assert!(settings.save(dir.path()).is_err());
    }

    #[test]
    fn bandwidth_limits_round_trip_with_account_binding_and_revision() {
        use std::num::NonZeroU64;

        let dir = tempfile::tempdir().unwrap();
        let mut settings = Settings {
            config: Config {
                schema_version: CONFIG_SCHEMA_VERSION,
                cloud_root: dir.path().join("cloud"),
                pairs: vec![],
            },
            server: Some("https://cloud.example".into()),
            client_id: "OpenCloudDesktop".into(),
            account_id: Some("account-1".into()),
            retired_pair_ids: Vec::new(),
            paused: false,
            paused_space_ids: Vec::new(),
            mount_enabled: false,
            media_jobs: Vec::new(),
            network_proxy: ProxyConfig::System,
            network_proxy_account_id: Some("account-1".into()),
            network_proxy_revision: 1,
            bandwidth_limits: TransferLimits {
                upload_bytes_per_second: Some(NonZeroU64::new(8192).unwrap()),
                download_bytes_per_second: None,
            },
            bandwidth_account_id: Some("account-1".into()),
            bandwidth_revision: 7,
        };
        settings.save(dir.path()).unwrap();
        let loaded = Settings::load(dir.path()).unwrap();
        assert_eq!(loaded.bandwidth_limits, settings.bandwidth_limits);
        assert_eq!(loaded.bandwidth_account_id.as_deref(), Some("account-1"));
        assert_eq!(loaded.bandwidth_revision, 7);

        settings.bandwidth_account_id = Some("account-2".into());
        assert!(settings.save(dir.path()).is_err());
        settings.bandwidth_account_id = Some("account-1".into());
        settings.bandwidth_limits.upload_bytes_per_second = Some(
            NonZeroU64::new(
                raiun_opencloud::transfer_budget::MAX_TRANSFER_RATE_BYTES_PER_SECOND + 1,
            )
            .unwrap(),
        );
        assert!(settings.save(dir.path()).is_err());
    }

    #[test]
    fn paused_space_ids_are_bounded_and_unique() {
        let duplicate = vec!["space-1".to_owned(), "space-1".to_owned()];
        assert!(validate_paused_space_ids(&duplicate).is_err());
        assert!(validate_paused_space_ids(&[String::new()]).is_err());
        assert!(validate_paused_space_ids(&["x".repeat(MAX_SPACE_ID_BYTES + 1)]).is_err());
        let too_many = (0..=MAX_PAUSED_SPACE_IDS)
            .map(|index| format!("space-{index}"))
            .collect::<Vec<_>>();
        assert!(validate_paused_space_ids(&too_many).is_err());
    }
}
