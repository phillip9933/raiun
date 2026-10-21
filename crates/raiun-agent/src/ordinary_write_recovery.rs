//! Explicit, non-destructive export of conflicted ordinary offline edits.
//!
//! The journal remains the authority and is never resolved or deleted here.

use raiun_cache::{Cache, CacheScope, PendingWriteItem};
#[cfg(unix)]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io;
use std::path::{Component, Path, PathBuf};
use tempfile::NamedTempFile;

const MAX_DESTINATION_PATH: usize = 32 * 1024;

pub(super) fn export_conflict_copy(
    cache: &Cache,
    account_id: &str,
    space_id: &str,
    write_id: i64,
    destination: &Path,
    protected_directories: &[PathBuf],
    before_publish: impl FnOnce() -> Result<(), String>,
) -> Result<PendingWriteItem, String> {
    export_copy(
        destination,
        protected_directories,
        before_publish,
        |output| cache.copy_conflict_write_for_account(account_id, space_id, write_id, output),
    )
}

pub(super) fn export_saved_copy(
    cache: &Cache,
    scope: &CacheScope,
    write_id: i64,
    destination: &Path,
    protected_directories: &[PathBuf],
    before_publish: impl FnOnce() -> Result<(), String>,
) -> Result<PendingWriteItem, String> {
    export_copy(
        destination,
        protected_directories,
        before_publish,
        |output| cache.copy_saved_write(scope, write_id, output),
    )
}

fn export_copy(
    destination: &Path,
    protected_directories: &[PathBuf],
    before_publish: impl FnOnce() -> Result<(), String>,
    copy: impl FnOnce(&mut File) -> Result<PendingWriteItem, raiun_cache::CacheError>,
) -> Result<PendingWriteItem, String> {
    let (parent, final_path) = validate_destination(destination, protected_directories)?;
    match fs::symlink_metadata(&final_path) {
        Ok(_) => return Err("The selected file already exists".into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err("Could not inspect the selected destination".into()),
    }

    let mut staging = NamedTempFile::new_in(&parent)
        .map_err(|_| "Could not create a private staging file in the selected folder")?;
    set_private_file(staging.as_file())?;
    let item = copy(staging.as_file_mut()).map_err(|error| match error {
        raiun_cache::CacheError::Conflict => {
            "This saved edit changed and cannot be exported".to_owned()
        }
        raiun_cache::CacheError::NotFound => {
            "The selected saved edit is no longer available".to_owned()
        }
        raiun_cache::CacheError::Corrupt => {
            "The saved edit is damaged and was not exported".to_owned()
        }
        _ => "Could not read the saved edit".to_owned(),
    })?;
    staging
        .as_file()
        .sync_all()
        .map_err(|_| "Could not finish writing the selected copy")?;

    // Recheck the parent and final path immediately before the atomic no-clobber
    // publish. The staged file is in the canonical parent, so the selected
    // filename cannot redirect the write through a symlink.
    let original_parent = destination.parent().unwrap_or_else(|| Path::new("."));
    reject_symlink_ancestors(original_parent)?;
    if fs::canonicalize(original_parent)
        .map_err(|_| "The selected folder changed while saving the copy")?
        != parent
    {
        return Err("The selected folder changed while saving the copy".into());
    }
    match fs::symlink_metadata(&final_path) {
        Ok(_) => return Err("The selected file already exists".into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err("Could not inspect the selected destination".into()),
    }
    before_publish()?;
    staging
        .persist_noclobber(&final_path)
        .map_err(|_| "Could not save the copy without replacing an existing file")?;
    sync_directory(&parent)
        .map_err(|_| "The copy was created, but Raiun could not confirm it was durably saved")?;
    Ok(item)
}

fn validate_destination(
    destination: &Path,
    protected_directories: &[PathBuf],
) -> Result<(PathBuf, PathBuf), String> {
    if !destination.is_absolute() || destination.as_os_str().len() > MAX_DESTINATION_PATH {
        return Err("Choose a valid absolute file location".into());
    }
    let name = destination
        .file_name()
        .filter(|name| !name.is_empty() && *name != "." && *name != "..")
        .ok_or("Choose a file name for the copy")?;
    if destination
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err("The selected location contains an unsafe path component".into());
    }
    let original_parent = destination.parent().ok_or("Choose a folder for the copy")?;
    reject_symlink_ancestors(original_parent)?;
    let parent =
        fs::canonicalize(original_parent).map_err(|_| "The selected folder is unavailable")?;
    let metadata =
        fs::symlink_metadata(&parent).map_err(|_| "The selected folder is unavailable")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("Choose a real folder for the copy".into());
    }
    let final_path = parent.join(name);
    for protected in protected_directories {
        if protected.as_os_str().is_empty() {
            continue;
        }
        let normalized = canonical_or_lexical(protected)?;
        if final_path.starts_with(&normalized) {
            return Err("Choose a location outside Raiun’s private data and cloud folder".into());
        }
    }
    Ok((parent, final_path))
}

fn reject_symlink_ancestors(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err("The selected folder contains a symbolic link".into());
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err("The selected folder is unavailable".into());
            }
            Err(_) => return Err("Could not verify the selected folder".into()),
        }
    }
    Ok(())
}

fn canonical_or_lexical(path: &Path) -> Result<PathBuf, String> {
    if let Ok(canonical) = fs::canonicalize(path) {
        return Ok(canonical);
    }
    if !path.is_absolute() {
        return Err("Could not validate Raiun’s protected data location".into());
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err("Could not validate Raiun’s protected data location".into());
                }
            }
        }
    }
    Ok(normalized)
}

fn set_private_file(file: &File) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| "Could not protect the exported copy while saving")?;
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    OpenOptions::new().read(true).open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use raiun_cache::{CacheScope, ConditionalWriteRequest, ContentProtection, ScopeProtection};
    use raiun_core::backend::WriteCondition;
    use std::io::Cursor;

    fn conflict(cache_dir: &Path) -> (Cache, i64) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(cache_dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let cache = Cache::open(cache_dir, 1 << 20).unwrap();
        let scope = CacheScope::new(
            "https://cloud.example.test/",
            "account-a",
            "space-a",
            "root-a",
            ScopeProtection::PlaintextAllowed,
        )
        .unwrap();
        cache
            .publish_listing(
                &scope,
                "root-a",
                &[raiun_cache::CachedEntry {
                    parent_resource_id: "root-a".into(),
                    entry: raiun_core::backend::RemoteEntry {
                        id: "resource-a".into(),
                        path: "/notes.txt".into(),
                        etag: "old".into(),
                        size: 4,
                        directory: false,
                        modified_unix: 1,
                        writable: true,
                        encrypted: false,
                    },
                }],
                1,
            )
            .unwrap();
        let write = cache
            .queue_conditional_write(
                &scope,
                ConditionalWriteRequest {
                    parent_resource_id: "root-a".into(),
                    name: "notes.txt".into(),
                    logical_path: "/notes.txt".into(),
                    resource_id: Some("resource-a".into()),
                    base: WriteCondition::Match("old".into()),
                    expected_len: 11,
                    protection: ContentProtection::Plaintext,
                },
                &mut Cursor::new(b"local edit\n"),
            )
            .unwrap();
        cache.mark_write_conflict(&scope, write.id).unwrap();
        (cache, write.id)
    }

    #[test]
    fn exports_conflict_to_new_file_without_resolving_or_overwriting() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        fs::create_dir(&cache_dir).unwrap();
        let destination_dir = temp.path().join("chosen");
        fs::create_dir(&destination_dir).unwrap();
        let protected = temp.path().join("private");
        fs::create_dir(&protected).unwrap();
        let (cache, id) = conflict(&cache_dir);
        let destination = destination_dir.join("notes-copy.txt");
        let item = export_conflict_copy(
            &cache,
            "account-a",
            "space-a",
            id,
            &destination,
            std::slice::from_ref(&protected),
            || Ok(()),
        )
        .unwrap();
        assert_eq!(item.state, raiun_cache::WriteState::Conflict);
        assert_eq!(fs::read(&destination).unwrap(), b"local edit\n");
        assert_eq!(
            cache
                .pending_write_page_for_account("account-a", None, 10)
                .unwrap()
                .conflict_count,
            1
        );
        assert!(
            export_conflict_copy(
                &cache,
                "account-a",
                "space-a",
                id,
                &destination,
                std::slice::from_ref(&protected),
                || Ok(()),
            )
            .is_err()
        );
        assert_eq!(fs::read(&destination).unwrap(), b"local edit\n");
    }

    #[test]
    fn failed_generation_recheck_never_publishes_staged_copy() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        fs::create_dir(&cache_dir).unwrap();
        let destination_dir = temp.path().join("chosen");
        fs::create_dir(&destination_dir).unwrap();
        let (cache, id) = conflict(&cache_dir);
        let destination = destination_dir.join("copy.txt");
        assert!(
            export_conflict_copy(
                &cache,
                "account-a",
                "space-a",
                id,
                &destination,
                &[],
                || Err("account changed".into()),
            )
            .is_err()
        );
        assert!(!destination.exists());
        assert_eq!(
            cache
                .pending_write_page_for_account("account-a", None, 10)
                .unwrap()
                .conflict_count,
            1
        );
    }

    #[test]
    fn rejects_private_cloud_and_symlink_destinations() {
        let temp = tempfile::tempdir().unwrap();
        let cache_dir = temp.path().join("cache");
        let chosen = temp.path().join("chosen");
        let private = temp.path().join("private");
        let cloud = temp.path().join("cloud");
        for path in [&cache_dir, &chosen, &private, &cloud] {
            fs::create_dir(path).unwrap();
        }
        let (cache, id) = conflict(&cache_dir);
        let forbidden = [cache_dir.clone(), private.clone(), cloud.clone()];
        for destination in [
            cache_dir.join("bad.txt"),
            private.join("bad.txt"),
            cloud.join("bad.txt"),
        ] {
            assert!(
                export_conflict_copy(
                    &cache,
                    "account-a",
                    "space-a",
                    id,
                    &destination,
                    &forbidden,
                    || Ok(()),
                )
                .is_err()
            );
        }
        let link = chosen.join("linked.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink(chosen.join("missing.txt"), &link).unwrap();
        assert!(
            export_conflict_copy(
                &cache,
                "account-a",
                "space-a",
                id,
                &link,
                &forbidden,
                || Ok(()),
            )
            .is_err()
        );
        #[cfg(unix)]
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}
