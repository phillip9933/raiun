//! Explicit immutable process routing for isolated headless Windows clients.

use std::{
    ffi::OsStr,
    io,
    path::{Path, PathBuf},
    sync::OnceLock,
};

/// An admitted private state root and its opaque IPC scope. The native pins
/// remain alive for the process, including while cloned contexts are in use.
#[derive(Clone)]
pub struct HeadlessContext {
    state_root: PathBuf,
    scope_id: String,
    #[cfg(windows)]
    directory: std::sync::Arc<crate::PrivateDirectory>,
}

impl HeadlessContext {
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }
    pub fn scope_id(&self) -> &str {
        &self.scope_id
    }

    #[cfg(windows)]
    pub(crate) fn session_directory(&self) -> io::Result<std::sync::Arc<crate::PrivateDirectory>> {
        self.directory.verify_path()?;
        let parent = crate::PinnedDirectory::open(self.state_root())?;
        let child = crate::PrivateDirectory::create_or_open_under(&parent, OsStr::new("sessions"))?;
        Ok(std::sync::Arc::new(child))
    }
}

type CachedContext = Result<Option<HeadlessContext>, (io::ErrorKind, String)>;
static CONTEXT: OnceLock<CachedContext> = OnceLock::new();

/// Interpret the opt-in environment once. An invalid first interpretation
/// remains an error; changing environment variables cannot reroute a running
/// agent's pipe, credentials, cache or recovery state.
pub fn headless_context() -> io::Result<Option<HeadlessContext>> {
    cached_context(&CONTEXT, read_context)
}

fn cached_context(
    cache: &OnceLock<CachedContext>,
    initialize: impl FnOnce() -> io::Result<Option<HeadlessContext>>,
) -> io::Result<Option<HeadlessContext>> {
    match cache.get_or_init(|| initialize().map_err(|error| (error.kind(), error.to_string()))) {
        Ok(context) => Ok(context.clone()),
        Err((kind, message)) => Err(io::Error::new(*kind, message.clone())),
    }
}

fn opt_in(value: Option<&OsStr>) -> io::Result<bool> {
    match value {
        None => Ok(false),
        Some(value) if value == "1" => Ok(true),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "RAIUN_HEADLESS_CONTEXT must be absent or exactly 1",
        )),
    }
}

fn read_context() -> io::Result<Option<HeadlessContext>> {
    if !opt_in(std::env::var_os("RAIUN_HEADLESS_CONTEXT").as_deref())? {
        return Ok(None);
    }
    #[cfg(windows)]
    {
        let state = std::env::var_os("RAIUN_STATE_DIR")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "RAIUN_STATE_DIR is required for headless Windows processes",
                )
            })?;
        admit(Path::new(&state)).map(Some)
    }
    #[cfg(not(windows))]
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows headless process context requires Windows",
    ))
}

#[cfg(any(windows, test))]
fn scope_for_root(canonical: &str, volume: u32, file: u64) -> String {
    use sha2::{Digest, Sha256};
    let canonical = canonical
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase();
    let mut hash = Sha256::new();
    hash.update(b"RAIUN-HEADLESS-WINDOWS-ROOT\0\x01");
    hash.update((canonical.len() as u64).to_le_bytes());
    hash.update(canonical.as_bytes());
    // Identity also distinguishes Windows case-sensitive sibling directories
    // and prevents a replaced directory from reusing a still-live endpoint.
    hash.update(volume.to_le_bytes());
    hash.update(file.to_le_bytes());
    hash.finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(windows)]
fn admit(state: &Path) -> io::Result<HeadlessContext> {
    let local = std::env::var_os("LOCALAPPDATA")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| io::Error::other("Current user's local application data is unavailable"))?;
    let (directory, canonical) =
        crate::private_directory::admit_headless_root(state, Path::new(&local))?;
    let identity = directory.identity();
    let scope_id = scope_for_root(&canonical, identity.volume_serial, identity.file_index);
    Ok(HeadlessContext {
        state_root: directory.path().to_path_buf(),
        scope_id,
        directory: std::sync::Arc::new(directory),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_opt_in_is_exact_and_default_is_unmodified() {
        assert!(!opt_in(None).unwrap());
        assert!(opt_in(Some(OsStr::new("1"))).unwrap());
        for value in ["", "0", "true", " 1", "1 "] {
            assert!(opt_in(Some(OsStr::new(value))).is_err());
        }
    }

    #[test]
    fn first_interpretation_and_first_error_remain_immutable() {
        let absent = OnceLock::new();
        assert!(cached_context(&absent, || Ok(None)).unwrap().is_none());
        assert!(
            cached_context(&absent, || panic!("must not reinterpret environment"))
                .unwrap()
                .is_none()
        );
        let rejected = OnceLock::new();
        let error = cached_context(&rejected, || {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "synthetic invalid context",
            ))
        });
        assert_eq!(error.err().unwrap().kind(), io::ErrorKind::InvalidInput);
        let error = cached_context(&rejected, || panic!("must not permit later rerouting"));
        assert_eq!(
            error.err().unwrap().to_string(),
            "synthetic invalid context"
        );
    }

    #[test]
    fn scope_normalizes_windows_case_and_separators_but_binds_root_identity() {
        let first = scope_for_root(r"\\?\Volume{ABC}\Users\Test\State", 1, 2);
        assert_eq!(
            first,
            scope_for_root("//?/volume{abc}/users/test/state/", 1, 2)
        );
        assert_eq!(first.len(), 64);
        assert_ne!(
            first,
            scope_for_root(r"\\?\Volume{ABC}\Users\Test\Other", 1, 2)
        );
        assert_ne!(
            first,
            scope_for_root(r"\\?\Volume{ABC}\Users\Test\State", 1, 3)
        );
        assert_ne!(
            first,
            scope_for_root(r"\\?\Volume{ABC}\Users\Test\State", 2, 2)
        );
    }

    #[test]
    fn headless_pipe_names_separate_users_roots_and_desktop_with_a_fixed_bound() {
        let sid = "S-1-5-21-123-456-789-1001";
        let scope = scope_for_root("canonical", 1, 2);
        let pipe = crate::headless_pipe_path_for_sid(sid, &scope).unwrap();
        assert_ne!(Some(pipe.clone()), crate::pipe_path_for_sid(sid));
        assert_ne!(
            Some(pipe.clone()),
            crate::headless_pipe_path_for_sid("S-1-5-18", &scope)
        );
        assert_ne!(
            Some(pipe.clone()),
            crate::headless_pipe_path_for_sid(sid, &"a".repeat(64))
        );
        assert!(pipe.len() < 256);
        for bad in ["", "a", &"A".repeat(64), &"z".repeat(64)] {
            assert!(crate::headless_pipe_path_for_sid(sid, bad).is_none());
        }
        assert!(crate::headless_pipe_path_for_sid("untrusted/path", &scope).is_none());
    }
}
