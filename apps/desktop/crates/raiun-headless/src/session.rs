//! Linux/Unix MVP custody: private filesystem permissions, never a keyring.
use crate::{MAX_SESSION_BYTES, valid_profile};
use rustix::{
    fd::{AsFd, OwnedFd},
    fs::{self, Mode, OFlags},
    process::geteuid,
};
use std::{
    fs::File,
    io::{self, Read, Write},
    path::{Component, Path},
    sync::atomic::{AtomicU64, Ordering},
};
use zeroize::Zeroizing;

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "headless session storage is not a private owned directory or regular file",
    )
}
fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}
fn check_directory(fd: impl AsFd) -> io::Result<()> {
    let stat = fs::fstat(fd)?;
    if stat.st_uid != geteuid().as_raw() || stat.st_mode & 0o7777 != 0o700 {
        return Err(denied());
    }
    Ok(())
}
fn check_file(file: &File) -> io::Result<()> {
    let stat = fs::fstat(file)?;
    if stat.st_uid != geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
        || fs::FileType::from_raw_mode(stat.st_mode) != fs::FileType::RegularFile
        || stat.st_size < 0
        || stat.st_size as u64 > MAX_SESSION_BYTES
    {
        return Err(denied());
    }
    Ok(())
}
fn child(parent: impl AsFd, name: &std::ffi::OsStr, create: bool) -> io::Result<OwnedFd> {
    if create {
        match fs::mkdirat(parent.as_fd(), name, Mode::from_raw_mode(0o700)) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(error.into()),
        }
    }
    let fd = fs::openat(parent, name, directory_flags(), Mode::empty())?;
    check_directory(&fd)?;
    Ok(fd)
}
fn sessions(root: &Path, create: bool) -> io::Result<OwnedFd> {
    if !root.is_absolute() || root.parent().is_none() {
        return Err(denied());
    }
    let mut directory = fs::open("/", directory_flags(), Mode::empty())?;
    let mut parts = root.components().peekable();
    while let Some(part) = parts.next() {
        match part {
            Component::RootDir => {}
            Component::Normal(name) if parts.peek().is_none() => {
                directory = child(&directory, name, create)?;
            }
            Component::Normal(name) => {
                directory = fs::openat(&directory, name, directory_flags(), Mode::empty())?;
            }
            _ => return Err(denied()),
        }
    }
    check_directory(&directory)?;
    child(&directory, std::ffi::OsStr::new("sessions"), create)
}
fn name(profile: &str) -> io::Result<String> {
    if !valid_profile(profile) {
        return Err(denied());
    }
    Ok(format!("{profile}.json"))
}
fn existing(directory: &OwnedFd, name: &str) -> io::Result<Option<File>> {
    let fd = match fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let file = File::from(fd);
    check_file(&file)?;
    Ok(Some(file))
}

/// Save opaque bounded session bytes atomically under `root/sessions/profile.json`.
/// Existing directories/files must already be private; no permission repair.
pub fn save_session(root: &Path, profile: &str, bytes: &[u8]) -> io::Result<()> {
    let name = name(profile)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_SESSION_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "session bytes exceed the storage bound",
        ));
    }
    let directory = sessions(root, true)?;
    drop(existing(&directory, &name)?);
    let temporary = format!(
        ".session-{}-{}.tmp",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let fd = fs::openat(
        &directory,
        temporary.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?;
    let mut file = File::from(fd);
    let result = (|| {
        check_file(&file)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::renameat(&directory, temporary.as_str(), &directory, name.as_str())?;
        fs::fsync(&directory)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::unlinkat(&directory, temporary.as_str(), fs::AtFlags::empty());
    }
    result
}

pub fn load_session(root: &Path, profile: &str) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let name = name(profile)?;
    let directory = match sessions(root, false) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let Some(file) = existing(&directory, &name)? else {
        return Ok(None);
    };
    let mut bytes = Zeroizing::new(Vec::new());
    (&file)
        .take(MAX_SESSION_BYTES + 1)
        .read_to_end(&mut bytes)?;
    check_file(&file)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_SESSION_BYTES {
        return Err(denied());
    }
    Ok(Some(bytes))
}

pub fn remove_session(root: &Path, profile: &str) -> io::Result<()> {
    let name = name(profile)?;
    let directory = match sessions(root, false) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if existing(&directory, &name)?.is_some() {
        fs::unlinkat(&directory, name.as_str(), fs::AtFlags::empty())?;
        fs::fsync(&directory)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[test]
    fn private_atomic_session_roundtrip_and_profile_isolation() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("state");
        assert!(load_session(&root, "default").unwrap().is_none());
        save_session(&root, "default", b"synthetic-first").unwrap();
        save_session(&root, "default", b"synthetic-replacement").unwrap();
        assert_eq!(
            load_session(&root, "default").unwrap().unwrap().as_slice(),
            b"synthetic-replacement"
        );
        assert!(
            load_session(&root, "profile-00000000000000000000000000000001")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(root.join("sessions/default.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        remove_session(&root, "default").unwrap();
        assert!(load_session(&root, "default").unwrap().is_none());
    }
    #[test]
    fn refuses_symlinks_hardlinks_and_unsafe_permissions_without_repair() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("state");
        save_session(&root, "default", b"synthetic").unwrap();
        let alias = temp.path().join("alias");
        symlink(&root, &alias).unwrap();
        assert!(load_session(&alias, "default").is_err());
        let file = root.join("sessions/default.json");
        std::fs::hard_link(&file, temp.path().join("link")).unwrap();
        assert!(load_session(&root, "default").is_err());
        assert!(remove_session(&root, "default").is_err());
        std::fs::remove_file(temp.path().join("link")).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_session(&root, "default").is_err());
        assert!(save_session(&root, "default", b"new").is_err());
        assert_eq!(
            std::fs::metadata(file).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }
}
