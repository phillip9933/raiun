//! Nonsecret headless configuration and platform-private session persistence.
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};
use url::{Host, Url};

pub const MAX_CONFIG_BYTES: u64 = 64 * 1024;
pub const MAX_SESSION_BYTES: u64 = 1024 * 1024;

/// Numeric effective OS account, independent of login-session or environment names.
#[cfg(unix)]
pub fn effective_user_id() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Browser,
    AppToken,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HeadlessConfig {
    pub schema_version: u32,
    pub server: String,
    pub auth: AuthMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    pub mount_path: PathBuf,
    #[serde(default = "yes")]
    pub auto_mount: bool,
    #[serde(default = "yes")]
    pub remember_login: bool,
    #[serde(default = "interval")]
    pub reconnect_interval_seconds: u64,
    #[serde(default = "default_profile")]
    pub profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_recovery: Option<raiun_core::WindowsRecoveryPolicy>,
}
fn yes() -> bool {
    true
}
fn interval() -> u64 {
    30
}
fn default_profile() -> String {
    "default".into()
}

#[derive(Debug)]
pub struct ConfigError(&'static str);
impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ConfigError {}

pub fn valid_profile(profile: &str) -> bool {
    profile == "default"
        || profile.strip_prefix("profile-").is_some_and(|tail| {
            tail.len() == 32
                && tail
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

/// Validate only; no network, discovery, credential lookup or filesystem writes.
pub fn validate_server(server: &str) -> Result<(), ConfigError> {
    let url =
        Url::parse(server).map_err(|_| ConfigError("server must be an absolute HTTPS URL"))?;
    let loopback = match url.host() {
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || server.chars().any(char::is_control)
    {
        return Err(ConfigError(
            "server requires HTTPS without credentials, query or fragment; HTTP is allowed only on loopback",
        ));
    }
    Ok(())
}

impl HeadlessConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != 1 {
            return Err(ConfigError(
                "unsupported headless configuration schema_version",
            ));
        }
        validate_server(&self.server)?;
        if !self.mount_path.is_absolute()
            || self.mount_path.parent().is_none()
            || self
                .mount_path
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(ConfigError(
                "mount_path must be an absolute directory path without parent traversal",
            ));
        }
        if !valid_profile(&self.profile) {
            return Err(ConfigError(
                "profile must be default or profile- followed by 32 lowercase hex digits",
            ));
        }
        for value in [&self.username, &self.client_id].into_iter().flatten() {
            if value.trim().is_empty() || value.len() > 4096 || value.chars().any(char::is_control)
            {
                return Err(ConfigError(
                    "username and client_id must be nonempty bounded text",
                ));
            }
        }
        if self.auth == AuthMethod::AppToken && self.username.is_none() {
            return Err(ConfigError("app_token authentication requires username"));
        }
        if self.auth == AuthMethod::AppToken
            && self
                .username
                .as_ref()
                .is_some_and(|name| name.len() > 512 || name.trim() != name || name.contains(':'))
        {
            return Err(ConfigError(
                "app_token username must be at most 512 bytes without colon or surrounding whitespace",
            ));
        }
        if !(1..=86_400).contains(&self.reconnect_interval_seconds) {
            return Err(ConfigError(
                "reconnect_interval_seconds must be between 1 and 86400",
            ));
        }
        if let Some(policy) = &self.windows_recovery {
            policy.validate().map_err(ConfigError)?;
            #[cfg(not(windows))]
            return Err(ConfigError(
                "windows_recovery is only supported by the Windows client",
            ));
        }
        Ok(())
    }
}

pub fn load(path: &Path) -> Result<HeadlessConfig, ConfigError> {
    load_optional(path)?.ok_or(ConfigError("headless configuration file does not exist"))
}

pub fn load_optional(path: &Path) -> Result<Option<HeadlessConfig>, ConfigError> {
    if !path.is_absolute() {
        return Err(ConfigError("headless configuration path must be absolute"));
    }
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ConfigError("cannot open headless configuration file")),
    };
    if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
        return Err(ConfigError("headless configuration must be a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ConfigError("cannot read headless configuration"))?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(ConfigError("headless configuration exceeds 64 KiB"));
    }
    let config: HeadlessConfig = serde_json::from_slice(&bytes).map_err(|_| ConfigError("invalid headless configuration JSON or unknown fields; secrets do not belong in this file"))?;
    config.validate()?;
    Ok(Some(config))
}

/// An explicitly exported path is always required to exist and be valid.
pub fn config_from_env() -> Result<Option<HeadlessConfig>, ConfigError> {
    std::env::var_os("RAIUN_HEADLESS_CONFIG")
        .map(|path| load(Path::new(&path)))
        .transpose()
}

#[cfg(unix)]
mod session;
#[cfg(unix)]
pub use session::{load_session, remove_session, save_session};

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> HeadlessConfig {
        serde_json::from_value(serde_json::json!({"schema_version":1,"server":"https://cloud.example.test","auth":"app_token","username":"synthetic","mount_path": std::env::temp_dir().join("synthetic-mount")})).unwrap()
    }
    #[test]
    fn strict_nonsecret_schema_and_defaults() {
        let config = config();
        config.validate().unwrap();
        assert!(config.auto_mount && config.remember_login);
        assert_eq!(config.reconnect_interval_seconds, 30);
        assert_eq!(config.profile, "default");
        let mut value = serde_json::to_value(config).unwrap();
        value["app_token"] = "never-store".into();
        assert!(serde_json::from_value::<HeadlessConfig>(value).is_err());
    }
    #[test]
    fn rejects_unsafe_or_malformed_configuration() {
        for server in [
            "http://cloud.example.test",
            "https://user:token@cloud.example.test",
            "https://cloud.example.test?token=x",
            "https://cloud.example.test#token",
        ] {
            assert!(validate_server(server).is_err());
        }
        for server in [
            "https://cloud.example.test",
            "http://127.0.0.1:1234",
            "http://[::1]:1234",
        ] {
            validate_server(server).unwrap();
        }
        let mut config = config();
        config.username = None;
        assert!(config.validate().is_err());
        config.auth = AuthMethod::Browser;
        config.profile = "../foreign".into();
        assert!(config.validate().is_err());
    }
    #[test]
    fn windows_recovery_is_strict_and_absent_settings_stay_compatible() {
        let original = config();
        let mut encoded = serde_json::to_value(&original).unwrap();
        assert!(encoded.get("windows_recovery").is_none());
        encoded["windows_recovery"] = serde_json::json!({"total_timeout_seconds":86400});
        let policy_config: HeadlessConfig = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(
            policy_config
                .windows_recovery
                .as_ref()
                .unwrap()
                .total_timeout_seconds,
            86_400
        );
        #[cfg(windows)]
        policy_config.validate().unwrap();
        #[cfg(not(windows))]
        assert_eq!(
            policy_config.validate().unwrap_err().to_string(),
            "windows_recovery is only supported by the Windows client"
        );
        encoded["windows_recovery"]["total_timeout_seconds"] = 0.into();
        let invalid: HeadlessConfig = serde_json::from_value(encoded.clone()).unwrap();
        assert!(invalid.validate().is_err());
        encoded["windows_recovery"]["token"] = "never-store".into();
        assert!(serde_json::from_value::<HeadlessConfig>(encoded).is_err());
    }
    #[test]
    fn missing_default_is_optional_but_explicit_load_fails() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("missing.json");
        assert!(load_optional(&path).unwrap().is_none());
        assert!(load(&path).is_err());
        assert!(load_optional(Path::new("relative")).is_err());
    }
}
