//! Small private snapshot of the last authenticated account namespace.
//!
//! This contains only server Space metadata needed to mount the ordinary
//! Personal/Spaces shell while transport is unavailable. It is bound to the
//! exact configured server and derived account identity and is never used on
//! authorization or identity errors.

use raiun_core::backend::CloudSpace;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};
use tempfile::NamedTempFile;
use url::Url;

const FILE_NAME: &str = "namespace-v1.json";
const VERSION: u32 = 1;
const MAX_FILE_BYTES: usize = 1_048_576;
const MAX_SPACES: usize = 2048;
const MAX_FIELD_BYTES: usize = 16 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u32,
    account_id: String,
    server: String,
    origin: String,
    saved_at_unix: u64,
    spaces: Vec<CloudSpace>,
}

pub(super) fn save(
    engine_dir: &Path,
    account_id: &str,
    server: &str,
    spaces: &[CloudSpace],
) -> Result<(), String> {
    let snapshot = validate_snapshot(account_id, server, spaces)?;
    let directory = prepare_directory(engine_dir)?;
    let bytes = serde_json::to_vec(&snapshot).map_err(|_| "Could not encode account namespace")?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err("Account namespace exceeds its size limit".into());
    }
    let path = directory.join(FILE_NAME);
    reject_symlink_file(&path)?;
    let mut temporary =
        NamedTempFile::new_in(&directory).map_err(|_| "Account namespace is unavailable")?;
    temporary
        .write_all(&bytes)
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|_| "Could not save account namespace")?;
    temporary
        .persist(&path)
        .map_err(|_| "Could not publish account namespace")?;
    fs::File::open(&directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "Could not sync account namespace".to_owned())
}

pub(super) fn load(
    engine_dir: &Path,
    expected_account_id: &str,
    expected_server: &str,
) -> Result<Vec<CloudSpace>, String> {
    let directory = checked_directory(engine_dir)?;
    let path = directory.join(FILE_NAME);
    reject_symlink_file(&path)?;
    let metadata = fs::metadata(&path).map_err(|_| "No saved account namespace is available")?;
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES as u64 {
        return Err("Saved account namespace is invalid".into());
    }
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .open(&path)
        .and_then(|file| {
            file.take((MAX_FILE_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
        })
        .map_err(|_| "Saved account namespace is unavailable")?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err("Saved account namespace exceeds its size limit".into());
    }
    let snapshot: Snapshot =
        serde_json::from_slice(&bytes).map_err(|_| "Saved account namespace is invalid")?;
    validate_snapshot(expected_account_id, expected_server, &snapshot.spaces)?;
    let expected_origin = canonical_origin(expected_server)?;
    if snapshot.version != VERSION
        || snapshot.account_id != expected_account_id
        || snapshot.server != expected_server
        || snapshot.origin != expected_origin
    {
        return Err("Saved account namespace belongs to a different account or server".into());
    }
    Ok(snapshot.spaces)
}

pub(super) fn remove(engine_dir: &Path) -> Result<(), String> {
    let directory = match checked_directory(engine_dir) {
        Ok(directory) => directory,
        Err(error) if error == "Account namespace is not initialized" => return Ok(()),
        Err(error) => return Err(error),
    };
    let path = directory.join(FILE_NAME);
    reject_symlink_file(&path)?;
    match fs::remove_file(path) {
        Ok(()) => fs::File::open(&directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "Could not sync account namespace removal".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("Could not revoke the saved account namespace".into()),
    }
}

fn validate_snapshot(
    account_id: &str,
    server: &str,
    spaces: &[CloudSpace],
) -> Result<Snapshot, String> {
    if !valid_account_id(account_id) || spaces.is_empty() || spaces.len() > MAX_SPACES {
        return Err("Account namespace identity or Space count is invalid".into());
    }
    let origin = canonical_origin(server)?;
    let mut ids = BTreeSet::new();
    let mut personal = None;
    for space in spaces {
        if space.id.is_empty()
            || space.id.len() > MAX_FIELD_BYTES
            || space.name.is_empty()
            || space.name.len() > MAX_FIELD_BYTES
            || space.dav_url.len() > MAX_FIELD_BYTES
            || space.id.chars().any(char::is_control)
            || space.name.chars().any(char::is_control)
            || !ids.insert(space.id.as_str())
        {
            return Err("Account namespace contains invalid Space metadata".into());
        }
        let dav = Url::parse(&space.dav_url).map_err(|_| "Account namespace DAV URL is invalid")?;
        if canonical_origin(&space.dav_url)? != origin
            || !dav.username().is_empty()
            || dav.password().is_some()
            || dav.query().is_some()
            || dav.fragment().is_some()
        {
            return Err("Account namespace contains an out-of-origin DAV URL".into());
        }
        if space.personal {
            if personal.replace(space.id.as_str()).is_some() {
                return Err("Account namespace has multiple Personal drives".into());
            }
            if !space.writable || space.encrypted {
                return Err("Account namespace Personal drive is not usable".into());
            }
        }
    }
    let personal = personal.ok_or("Account namespace has no Personal drive")?;
    if account_identity(server, personal) != account_id {
        return Err("Account namespace identity does not match its Personal drive".into());
    }
    Ok(Snapshot {
        version: VERSION,
        account_id: account_id.to_owned(),
        server: server.to_owned(),
        origin,
        saved_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        spaces: spaces.to_vec(),
    })
}

fn canonical_origin(server: &str) -> Result<String, String> {
    let url = Url::parse(server).map_err(|_| "Account namespace server URL is invalid")?;
    if !(url.scheme() == "https"
        || (url.scheme() == "http"
            && url.host_str().is_some_and(|host| {
                host.eq_ignore_ascii_case("localhost")
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|address| address.is_loopback())
            })))
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("Account namespace server URL is invalid".into());
    }
    Ok(url.origin().ascii_serialization())
}

fn account_identity(server: &str, personal_drive_id: &str) -> String {
    let identity = format!("{server}\0{personal_drive_id}");
    let mut encoded = String::with_capacity(identity.len() * 2);
    for byte in identity.bytes() {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn valid_account_id(account_id: &str) -> bool {
    !account_id.is_empty()
        && account_id.len() % 2 == 0
        && account_id.len() <= 4096
        && account_id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn prepare_directory(engine_dir: &Path) -> Result<PathBuf, String> {
    if !engine_dir.is_absolute()
        || engine_dir
            .components()
            .any(|component| component == Component::ParentDir)
    {
        return Err("Account namespace path is invalid".into());
    }
    let mut current = PathBuf::new();
    for component in engine_dir.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err("Account namespace path contains a symbolic link".into());
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err("Account namespace path is not a directory".into());
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current)
                    .map_err(|_| "Account namespace directory is unavailable")?;
            }
            Err(_) => return Err("Account namespace directory is unavailable".into()),
        }
    }
    checked_directory(engine_dir)
}

fn checked_directory(engine_dir: &Path) -> Result<PathBuf, String> {
    let mut current = PathBuf::new();
    for component in engine_dir.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err("Account namespace path contains a symbolic link".into());
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err("Account namespace path is not a directory".into());
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err("Account namespace is not initialized".into());
            }
            Err(_) => return Err("Account namespace directory is unavailable".into()),
        }
    }
    let canonical =
        fs::canonicalize(engine_dir).map_err(|_| "Account namespace directory is unavailable")?;
    Ok(canonical)
}

fn reject_symlink_file(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err("Account namespace file is unsafe".into())
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("Account namespace file is unavailable".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn space(id: &str, name: &str, personal: bool) -> CloudSpace {
        CloudSpace {
            id: id.into(),
            name: name.into(),
            dav_url: format!("https://fixture.example.test/remote.php/dav/{id}"),
            personal,
            writable: true,
            encrypted: false,
        }
    }

    #[test]
    fn namespace_snapshot_is_private_account_and_origin_bound() {
        let temp = tempdir().unwrap();
        let engine_dir = temp.path().join("engine/accounts/account-a");
        let server = "https://fixture.example.test";
        let account_id = account_identity(server, "personal-drive");
        let spaces = vec![
            space("personal-drive", "Personal", true),
            space("project-drive", "Projects", false),
        ];
        save(&engine_dir, &account_id, server, &spaces).unwrap();

        assert_eq!(load(&engine_dir, &account_id, server).unwrap(), spaces);
        assert!(load(&engine_dir, &account_id, "https://other.example.test").is_err());
        assert!(
            load(
                &engine_dir,
                &account_identity(server, "other-drive"),
                server
            )
            .is_err()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(engine_dir.join(FILE_NAME)).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn namespace_snapshot_rejects_duplicate_and_foreign_spaces() {
        let temp = tempdir().unwrap();
        let engine_dir = temp.path().join("engine/account");
        let server = "https://fixture.example.test";
        let account_id = account_identity(server, "personal-drive");
        let mut spaces = vec![space("personal-drive", "Personal", true)];
        let mut foreign = space("foreign", "Foreign", false);
        foreign.dav_url = "https://other.example.test/dav/foreign".into();
        spaces.push(foreign);
        assert!(save(&engine_dir, &account_id, server, &spaces).is_err());

        let duplicate = vec![
            space("personal-drive", "Personal", true),
            space("personal-drive", "Duplicate", false),
        ];
        assert!(save(&engine_dir, &account_id, server, &duplicate).is_err());
    }
}
