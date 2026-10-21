//! Test-only generation locks on persistent, identity-pinned private files.

use super::{CacheError, CacheScope, io_error};
use raiun_control_windows::{PinnedPrivateFile, PinnedPrivateFileAccess, PrivateDirectory};
use std::ffi::OsStr;
use std::io;

pub(super) fn try_generation_lock<'a>(
    directory: &'a PrivateDirectory,
    scope: &CacheScope,
) -> Result<PinnedPrivateFile<'a>, CacheError> {
    // The digest includes origin, account, Space, root identity and protection.
    let name = format!("ciphertext-pin-generation-{}.lock", scope.key);
    try_private_lock(directory, OsStr::new(&name))
}

pub(super) fn try_private_lock<'a>(
    directory: &'a PrivateDirectory,
    name: &OsStr,
) -> Result<PinnedPrivateFile<'a>, CacheError> {
    let mut file = match directory.create_new_pinned_file(name) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => directory
            .open_pinned_file(name, PinnedPrivateFileAccess::ReadWrite)
            .map_err(io_error)?,
        Err(error) => return Err(io_error(error)),
    };
    file.try_lock_exclusive().map_err(|error| {
        if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() {
            CacheError::Conflict
        } else {
            io_error(error)
        }
    })?;
    // The returned pin owns the OS lock and prevents replacement/deletion.
    // Drop closes it and releases the lock; never unlink this persistent file.
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ScopeProtection;
    use raiun_control_windows::PinnedDirectory;
    use std::path::Path;
    use std::process::Command;

    fn scope(account: &str, root: &str) -> CacheScope {
        CacheScope::new(
            "https://synthetic.invalid/",
            account,
            "space-a",
            root,
            ScopeProtection::CiphertextOnly,
        )
        .unwrap()
    }
    fn directory(state: &Path) -> PrivateDirectory {
        let parent = PinnedDirectory::open(state).unwrap();
        PrivateDirectory::create_or_open_under(&parent, OsStr::new("locks")).unwrap()
    }
    fn child(state: &Path, expected: &str) {
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "windows_lock::tests::generation_lock_child",
                "--nocapture",
            ])
            .env("RAIUN_TEST_GENERATION_LOCK_DIR", state)
            .env("RAIUN_TEST_GENERATION_LOCK_EXPECT", expected)
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn generation_lock_child() {
        let Some(state) = std::env::var_os("RAIUN_TEST_GENERATION_LOCK_DIR") else {
            return;
        };
        let directory = directory(Path::new(&state));
        let result = try_generation_lock(&directory, &scope("account-a", "root-a"));
        match std::env::var("RAIUN_TEST_GENERATION_LOCK_EXPECT")
            .unwrap()
            .as_str()
        {
            "conflict" => assert!(matches!(result, Err(CacheError::Conflict))),
            "acquire" => {
                let file = result.unwrap();
                file.verify().unwrap();
            }
            _ => panic!("invalid synthetic expectation"),
        }
    }

    #[test]
    fn lock_excludes_other_process_and_reopens_same_identity_after_drop() {
        let state = tempfile::tempdir().unwrap();
        let directory = directory(state.path());
        let scope = scope("account-a", "root-a");
        let lock = try_generation_lock(&directory, &scope).unwrap();
        let identity = lock.identity();
        child(state.path(), "conflict");
        let path = directory
            .path()
            .join(format!("ciphertext-pin-generation-{}.lock", scope.key));
        assert!(std::fs::remove_file(&path).is_err());
        drop(lock);
        child(state.path(), "acquire");
        let lock = try_generation_lock(&directory, &scope).unwrap();
        assert_eq!(lock.identity(), identity);
        drop(lock);
        assert!(path.is_file(), "releasing a lock must not unlink its name");
    }

    #[test]
    fn account_and_root_scope_locks_do_not_alias() {
        let state = tempfile::tempdir().unwrap();
        let directory = directory(state.path());
        let a = try_generation_lock(&directory, &scope("account-a", "root-a")).unwrap();
        let b = try_generation_lock(&directory, &scope("account-b", "root-a")).unwrap();
        let c = try_generation_lock(&directory, &scope("account-a", "root-b")).unwrap();
        assert_ne!(a.identity(), b.identity());
        assert_ne!(a.identity(), c.identity());
        assert!(matches!(
            try_generation_lock(&directory, &scope("account-a", "root-a")),
            Err(CacheError::Conflict)
        ));
    }

    #[test]
    fn hardlinked_lock_is_rejected_without_repair() {
        let state = tempfile::tempdir().unwrap();
        let directory = directory(state.path());
        let scope = scope("account-a", "root-a");
        let lock = try_generation_lock(&directory, &scope).unwrap();
        drop(lock);
        let path = directory
            .path()
            .join(format!("ciphertext-pin-generation-{}.lock", scope.key));
        let alias = directory.path().join("alias");
        std::fs::hard_link(&path, &alias).unwrap();
        assert!(try_generation_lock(&directory, &scope).is_err());
        assert!(path.is_file() && alias.is_file());
        std::fs::remove_file(alias).unwrap();
        assert!(try_generation_lock(&directory, &scope).is_ok());
    }
}
