use raiun_core::{CONFIG_SCHEMA_VERSION, Config};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

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
    pub mount_enabled: bool,
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
                mount_enabled: false,
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
        Ok(settings)
    }
    pub fn save(&self, dir: &Path) -> Result<(), String> {
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
