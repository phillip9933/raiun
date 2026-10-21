//! Explicitly remembered vault passwords backed by the user's Secret Service.
//!
//! This adapter never writes credentials to Raiun settings or local files. A
//! saved secret is keyed by local profile, canonical server origin, Space ID,
//! and root DAV resource ID. Tests use an in-memory mock and never invoke a
//! real keyring.

use std::{
    collections::{BTreeMap, HashMap},
    fs,
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Mutex, OnceLock},
    thread,
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use raiun_vault::session::VaultSessionScope;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const SERVICE: &str = "app.raiun.desktop.vault-password.v1";
const MAX_PASSWORD_BYTES: usize = 4096;
const MAX_ENCODED_SECRET_BYTES: usize = 8192;
const MAX_DIAGNOSTIC_BYTES: usize = 8192;
const MAX_STATUS_SCOPES: usize = 1024;
const MAX_AUTHORITY_SCOPES: usize = 1024;
const MAX_AUTHORITY_BYTES: u64 = 262_144;
const AUTHORITY_FILE: &str = "vault-credential-authority.json";
const AUTHORITY_LOCK_FILE: &str = "vault-credential-authority.lock";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
static STATUS: OnceLock<Mutex<HashMap<VaultSessionScope, RememberedStatus>>> = OnceLock::new();

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RememberedStatus {
    KnownSaved,
    NotSaved,
    Unknown,
    Unavailable,
}

impl RememberedStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::KnownSaved => "known_saved",
            Self::NotSaved => "not_saved",
            Self::Unknown => "unknown",
            Self::Unavailable => "unavailable",
        }
    }
}

pub(crate) trait VaultCredentialStore: Send + Sync {
    fn store(&self, scope: &VaultSessionScope, password: &[u8]) -> Result<(), String>;
    fn load(&self, scope: &VaultSessionScope) -> Result<Option<Zeroizing<Vec<u8>>>, String>;
    fn remove(&self, scope: &VaultSessionScope) -> Result<CredentialCleanup, String>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CredentialCleanup {
    Uncertain,
}

pub(crate) struct CredentialOperationGuard {
    _file: fs::File,
}

impl CredentialCleanup {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Uncertain => "uncertain",
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityState {
    version: u8,
    profile_id: String,
    profile_generation: String,
    vault_generations: BTreeMap<String, String>,
}

struct AuthorityTuple {
    profile_generation: String,
    vault_generation: String,
}

pub(crate) struct SecretServiceVaultCredentialStore {
    executable: PathBuf,
    state_dir: PathBuf,
}

impl SecretServiceVaultCredentialStore {
    pub(crate) fn for_state_dir(state_dir: &Path) -> Self {
        Self {
            executable: PathBuf::from("secret-tool"),
            state_dir: state_dir.to_owned(),
        }
    }
}

impl VaultCredentialStore for SecretServiceVaultCredentialStore {
    fn store(&self, scope: &VaultSessionScope, password: &[u8]) -> Result<(), String> {
        validate_password(password)?;
        let authority = self.authority_for_scope(scope, true)?;
        // Secret Service replaces an item with the same exact attributes.
        let mut encoded = Zeroizing::new(STANDARD_NO_PAD.encode(password).into_bytes());
        let mut child = self.command("store", scope, &authority, true)?;
        let mut input = child
            .stdin
            .take()
            .ok_or("Could not open Secret Service input")?;
        let write_result = input.write_all(&encoded);
        drop(input);
        encoded.zeroize();
        if write_result.is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Secret Service could not save the remembered vault password".into());
        }
        let (status, output, diagnostics) = wait_bounded(child, COMMAND_TIMEOUT)?;
        drop(output);
        drop(diagnostics);
        if status.success() {
            record_status(scope, RememberedStatus::KnownSaved);
            Ok(())
        } else {
            Err("Secret Service could not save the remembered vault password".into())
        }
    }

    fn load(&self, scope: &VaultSessionScope) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        let authority = self.authority_for_scope(scope, true)?;
        let child = self.command("lookup", scope, &authority, false)?;
        let (status, mut output, diagnostics) = wait_bounded(child, COMMAND_TIMEOUT)?;
        if !status.success() {
            let not_found = status.code() == Some(1) && diagnostics.is_empty();
            output.zeroize();
            record_status(
                scope,
                if not_found {
                    RememberedStatus::NotSaved
                } else {
                    RememberedStatus::Unavailable
                },
            );
            return if not_found {
                Ok(None)
            } else {
                Err("Secret Service could not read the remembered vault password".into())
            };
        }
        if output.ends_with(b"\r\n") {
            let new_len = output.len() - 2;
            output.truncate(new_len);
        } else if output.ends_with(b"\n") {
            output.pop();
        }
        if output.is_empty() || output.len() > MAX_ENCODED_SECRET_BYTES {
            output.zeroize();
            record_status(scope, RememberedStatus::Unavailable);
            return Err("Stored vault password is invalid".into());
        }
        let decoded = STANDARD_NO_PAD
            .decode(&output)
            .map_err(|_| "Stored vault password is invalid".to_string());
        output.zeroize();
        let mut decoded = Zeroizing::new(match decoded {
            Ok(value) => value,
            Err(error) => {
                record_status(scope, RememberedStatus::Unavailable);
                return Err(error);
            }
        });
        if let Err(error) = validate_password(&decoded) {
            record_status(scope, RememberedStatus::Unavailable);
            return Err(error);
        }
        // Passwords originate from JSON strings, so reject malformed UTF-8 in
        // the store instead of passing arbitrary bytes to the KDF.
        if std::str::from_utf8(&decoded).is_err() {
            decoded.zeroize();
            record_status(scope, RememberedStatus::Unavailable);
            return Err("Stored vault password is invalid".into());
        }
        record_status(scope, RememberedStatus::KnownSaved);
        Ok(Some(decoded))
    }

    fn remove(&self, scope: &VaultSessionScope) -> Result<CredentialCleanup, String> {
        let previous = self.authority_for_scope(scope, true)?;
        self.rotate_scope_generation(scope)?;
        if let Ok(child) = self.command("clear", scope, &previous, false) {
            let _ = wait_bounded(child, COMMAND_TIMEOUT);
        }
        record_status(scope, RememberedStatus::NotSaved);
        Ok(CredentialCleanup::Uncertain)
    }
}

impl SecretServiceVaultCredentialStore {
    fn command(
        &self,
        action: &str,
        scope: &VaultSessionScope,
        authority: &AuthorityTuple,
        input: bool,
    ) -> Result<Child, String> {
        validate_profile_id(scope.account_id())?;
        let mut command = Command::new(&self.executable);
        command.args([action]);
        if action == "store" {
            command.arg("--label=Raiun Desktop remembered vault password");
        }
        command
            .args([
                "service",
                SERVICE,
                "profile",
                scope.account_id(),
                "profile_generation",
                &authority.profile_generation,
                "origin",
                scope.server_origin(),
                "space_id",
                scope.space_id(),
                "root_resource_id",
                scope.resource_id(),
                "vault_generation",
                &authority.vault_generation,
            ])
            .stdin(if input { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command.spawn().map_err(|_| secret_service_unavailable())
    }

    fn authority_for_scope(
        &self,
        scope: &VaultSessionScope,
        create_missing: bool,
    ) -> Result<AuthorityTuple, String> {
        let profile_id = scope.account_id();
        validate_profile_id(profile_id)?;
        let key = scope_key(scope);
        let mut state = read_authority(&self.state_dir, profile_id)?;
        if !state.vault_generations.contains_key(&key) {
            if !create_missing {
                return Err("Remembered vault credential authority is missing".into());
            }
            if state.vault_generations.len() >= MAX_AUTHORITY_SCOPES {
                return Err("Too many remembered vault credentials for this profile".into());
            }
            state
                .vault_generations
                .insert(key.clone(), random_generation()?);
            write_authority(&self.state_dir, &state)?;
        }
        let vault_generation = state
            .vault_generations
            .get(&key)
            .cloned()
            .ok_or("Remembered vault credential authority is missing")?;
        Ok(AuthorityTuple {
            profile_generation: state.profile_generation,
            vault_generation,
        })
    }

    fn rotate_scope_generation(&self, scope: &VaultSessionScope) -> Result<(), String> {
        let profile_id = scope.account_id();
        let key = scope_key(scope);
        let mut state = read_authority(&self.state_dir, profile_id)?;
        if !state.vault_generations.contains_key(&key)
            && state.vault_generations.len() >= MAX_AUTHORITY_SCOPES
        {
            return Err("Too many remembered vault credentials for this profile".into());
        }
        state.vault_generations.insert(key, random_generation()?);
        write_authority(&self.state_dir, &state)
    }
}

#[cfg(not(test))]
pub(crate) fn revoke_profile(
    state_dir: &Path,
    profile_id: &str,
) -> Result<CredentialCleanup, String> {
    revoke_profile_with_executable(state_dir, profile_id, Path::new("secret-tool"))
}

fn revoke_profile_with_executable(
    state_dir: &Path,
    profile_id: &str,
    executable: &Path,
) -> Result<CredentialCleanup, String> {
    let _operation = credential_operation_lock(state_dir, profile_id)?;
    validate_profile_id(profile_id)?;
    let mut state = read_authority(state_dir, profile_id)?;
    state.profile_generation = random_generation()?;
    state.vault_generations.clear();
    write_authority(state_dir, &state)?;
    clear_profile_status(profile_id);

    let child = Command::new(executable)
        .args(["clear", "service", SERVICE, "profile", profile_id])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    if let Ok(child) = child {
        let _ = wait_bounded(child, COMMAND_TIMEOUT);
    }
    // The Secret Service may leave locked items behind even after clear exits
    // successfully. The new epoch makes any such item unreachable to Raiun.
    Ok(CredentialCleanup::Uncertain)
}

/// Return only process-local knowledge. Inspecting a vault must never launch a
/// keyring lookup (which may unlock a collection or present a prompt). A fresh
/// process therefore reports `unknown` until the user explicitly remembers,
/// tries, or forgets a saved password.
pub(crate) fn remembered_status(scope: &VaultSessionScope) -> &'static str {
    let Some(status) = STATUS.get() else {
        return RememberedStatus::Unknown.as_str();
    };
    status
        .lock()
        .ok()
        .and_then(|status| status.get(scope).copied())
        .unwrap_or(RememberedStatus::Unknown)
        .as_str()
}

pub(crate) fn record_status(scope: &VaultSessionScope, status: RememberedStatus) {
    let state = STATUS.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut state) = state.lock() {
        if state.contains_key(scope) || state.len() < MAX_STATUS_SCOPES {
            state.insert(scope.clone(), status);
        }
    }
}

fn clear_profile_status(profile_id: &str) {
    let Some(status) = STATUS.get() else {
        return;
    };
    if let Ok(mut status) = status.lock() {
        status.retain(|scope, _| scope.account_id() != profile_id);
    }
}

fn validate_password(password: &[u8]) -> Result<(), String> {
    if password.is_empty() || password.len() > MAX_PASSWORD_BYTES {
        Err("Password must contain 1–4096 UTF-8 bytes".into())
    } else {
        Ok(())
    }
}

fn validate_profile_id(profile_id: &str) -> Result<(), String> {
    if profile_id.is_empty()
        || profile_id.len() > 256
        || !profile_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        Err("Local profile identifier is invalid".into())
    } else {
        Ok(())
    }
}

fn secret_service_unavailable() -> String {
    "Secret Service is unavailable; unlock a compatible system keyring and retry".into()
}

fn credential_operation_lock(
    state_dir: &Path,
    profile_id: &str,
) -> Result<CredentialOperationGuard, String> {
    validate_profile_id(profile_id)?;
    validate_private_state_dir(state_dir)?;
    let path = state_dir.join(AUTHORITY_LOCK_FILE);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err("Remembered credential lock is unsafe".into());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("Remembered credential lock is unavailable".into()),
        _ => {}
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&path)
        .map_err(|_| "Remembered credential lock is unavailable".to_string())?;
    validate_private_file(&path)?;
    fs2::FileExt::lock_exclusive(&file)
        .map_err(|_| "Remembered credential state is unavailable".to_string())?;
    Ok(CredentialOperationGuard { _file: file })
}

pub(crate) fn begin_credential_operation(
    state_dir: &Path,
    profile_id: &str,
) -> Result<CredentialOperationGuard, String> {
    credential_operation_lock(state_dir, profile_id)
}

fn read_authority(state_dir: &Path, profile_id: &str) -> Result<AuthorityState, String> {
    validate_profile_id(profile_id)?;
    validate_private_state_dir(state_dir)?;
    let path = state_dir.join(AUTHORITY_FILE);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err("Remembered credential authority is unsafe".into());
        }
        Ok(metadata) if metadata.len() > MAX_AUTHORITY_BYTES => {
            return Err("Remembered credential authority is invalid".into());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let state = AuthorityState {
                version: 1,
                profile_id: profile_id.to_owned(),
                profile_generation: random_generation()?,
                vault_generations: BTreeMap::new(),
            };
            write_authority(state_dir, &state)?;
            return Ok(state);
        }
        Err(_) => return Err("Remembered credential authority could not be read".into()),
    }
    validate_private_file(&path)?;
    let file = fs::File::open(path)
        .map_err(|_| "Remembered credential authority could not be read".to_string())?;
    let mut bytes = Vec::new();
    file.take(MAX_AUTHORITY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Remembered credential authority could not be read".to_string())?;
    if bytes.len() as u64 > MAX_AUTHORITY_BYTES {
        return Err("Remembered credential authority is invalid".into());
    }
    let state: AuthorityState = serde_json::from_slice(&bytes)
        .map_err(|_| "Remembered credential authority is invalid".to_string())?;
    validate_authority(&state, profile_id)?;
    Ok(state)
}

fn write_authority(state_dir: &Path, state: &AuthorityState) -> Result<(), String> {
    validate_private_state_dir(state_dir)?;
    validate_authority(state, &state.profile_id)?;
    let bytes = serde_json::to_vec(state)
        .map_err(|_| "Remembered credential authority could not be encoded".to_string())?;
    if bytes.len() as u64 > MAX_AUTHORITY_BYTES {
        return Err("Remembered credential authority exceeds its size limit".into());
    }
    let mut file = tempfile::NamedTempFile::new_in(state_dir)
        .map_err(|_| "Remembered credential authority could not be saved".to_string())?;
    set_private_file_mode(file.path())?;
    file.write_all(&bytes)
        .map_err(|_| "Remembered credential authority could not be saved".to_string())?;
    file.as_file()
        .sync_all()
        .map_err(|_| "Remembered credential authority could not be saved".to_string())?;
    file.persist(state_dir.join(AUTHORITY_FILE))
        .map_err(|_| "Remembered credential authority could not be saved".to_string())?;
    fs::File::open(state_dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "Remembered credential authority could not be saved".to_string())
}

fn validate_authority(state: &AuthorityState, profile_id: &str) -> Result<(), String> {
    if state.version != 1
        || state.profile_id != profile_id
        || !valid_generation(&state.profile_generation)
        || state.vault_generations.len() > MAX_AUTHORITY_SCOPES
        || state
            .vault_generations
            .iter()
            .any(|(key, generation)| !valid_scope_key(key) || !valid_generation(generation))
    {
        return Err("Remembered credential authority is invalid".into());
    }
    Ok(())
}

fn valid_scope_key(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_generation(value: &str) -> bool {
    valid_scope_key(value)
}

fn random_generation() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|_| "Could not create remembered credential authority".to_string())?;
    let mut value = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}")
            .map_err(|_| "Could not create remembered credential authority".to_string())?;
    }
    bytes.zeroize();
    Ok(value)
}

fn scope_key(scope: &VaultSessionScope) -> String {
    let mut digest = Sha256::new();
    for value in [
        scope.account_id(),
        scope.server_origin(),
        scope.space_id(),
        scope.resource_id(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    let digest = digest.finalize();
    let mut value = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut value, "{byte:02x}");
    }
    value
}

fn validate_private_state_dir(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| "Private profile state directory is unavailable".to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("Private profile state directory is unsafe".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("Private profile state directory permissions are unsafe".into());
        }
    }
    Ok(())
}

fn validate_private_file(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| "Remembered credential authority could not be read".to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("Remembered credential authority is unsafe".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("Remembered credential authority permissions are unsafe".into());
        }
    }
    Ok(())
}

fn set_private_file_mode(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| "Remembered credential authority could not be saved".to_string())?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Bounded helper process runner. Diagnostic text is drained and discarded.
type BoundedCommandOutput = (std::process::ExitStatus, Zeroizing<Vec<u8>>, Vec<u8>);

fn wait_bounded(mut child: Child, timeout: Duration) -> Result<BoundedCommandOutput, String> {
    let stdout = child
        .stdout
        .take()
        .ok_or("Could not read Secret Service output")?;
    let stderr = child
        .stderr
        .take()
        .ok_or("Could not read Secret Service diagnostics")?;
    let out_reader = thread::spawn(move || {
        let mut bytes = Zeroizing::new(Vec::new());
        let _ = stdout
            .take((MAX_ENCODED_SECRET_BYTES + 1) as u64)
            .read_to_end(&mut bytes);
        bytes
    });
    let err_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stderr
            .take((MAX_DIAGNOSTIC_BYTES + 1) as u64)
            .read_to_end(&mut bytes);
        bytes
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = out_reader.join();
                let _ = err_reader.join();
                return Err("Secret Service timed out; unlock the keyring and retry".into());
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = out_reader.join();
                let _ = err_reader.join();
                return Err("Secret Service operation failed".into());
            }
        }
    };
    let output = out_reader
        .join()
        .map_err(|_| "Could not read Secret Service output")?;
    let diagnostics = err_reader
        .join()
        .map_err(|_| "Could not read Secret Service diagnostics")?;
    if output.len() > MAX_ENCODED_SECRET_BYTES || diagnostics.len() > MAX_DIAGNOSTIC_BYTES {
        return Err("Secret Service response exceeds its size limit".into());
    }
    Ok((status, output, diagnostics))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashMap,
        process::Command,
        sync::{
            Mutex, MutexGuard,
            atomic::{AtomicUsize, Ordering},
        },
    };

    // Several tests exercise the real process boundary using isolated helper
    // executables. Keep those subprocess-heavy tests from exhausting the
    // host's per-user process limit when the full suite runs in parallel.
    // This is test-local synchronization; it does not mutate process-global
    // environment or use the user's Secret Service.
    #[cfg(unix)]
    static SUBPROCESS_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[cfg(unix)]
    fn subprocess_test_guard() -> MutexGuard<'static, ()> {
        SUBPROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[derive(Default)]
    struct MockStore {
        secrets: Mutex<HashMap<VaultSessionScope, Zeroizing<Vec<u8>>>>,
        unavailable: Mutex<bool>,
        loads: AtomicUsize,
    }

    impl VaultCredentialStore for MockStore {
        fn store(&self, scope: &VaultSessionScope, password: &[u8]) -> Result<(), String> {
            validate_password(password)?;
            if *self.unavailable.lock().unwrap() {
                return Err("mock unavailable".into());
            }
            self.secrets
                .lock()
                .unwrap()
                .insert(scope.clone(), Zeroizing::new(password.to_vec()));
            Ok(())
        }

        fn load(&self, scope: &VaultSessionScope) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
            self.loads.fetch_add(1, Ordering::Relaxed);
            if *self.unavailable.lock().unwrap() {
                return Err("mock unavailable".into());
            }
            Ok(self
                .secrets
                .lock()
                .unwrap()
                .get(scope)
                .map(|password| Zeroizing::new(password.to_vec())))
        }

        fn remove(&self, scope: &VaultSessionScope) -> Result<CredentialCleanup, String> {
            self.secrets.lock().unwrap().remove(scope);
            Ok(CredentialCleanup::Uncertain)
        }
    }

    fn scope(profile: &str, origin: &str, space: &str, root: &str) -> VaultSessionScope {
        VaultSessionScope::new(profile, origin, space, root).unwrap()
    }

    #[test]
    fn remembered_credentials_are_isolated_by_exact_vault_scope() {
        let store = MockStore::default();
        let original = scope("profile-iso", "https://cloud.example/", "space-a", "root-a");
        store.store(&original, "correct horse".as_bytes()).unwrap();
        record_status(&original, RememberedStatus::KnownSaved);
        assert_eq!(
            store.load(&original).unwrap().unwrap().as_slice(),
            b"correct horse"
        );
        assert_eq!(remembered_status(&original), "known_saved");
        for other in [
            scope(
                "profile-iso-other",
                "https://cloud.example",
                "space-a",
                "root-a",
            ),
            scope("profile-iso", "https://other.example", "space-a", "root-a"),
            scope("profile-iso", "https://cloud.example", "space-b", "root-a"),
            scope("profile-iso", "https://cloud.example", "space-a", "root-b"),
        ] {
            assert_eq!(remembered_status(&other), "unknown");
        }
        let before_inspection = store.loads.load(Ordering::Relaxed);
        for _ in 0..20 {
            let _ = remembered_status(&original);
        }
        assert_eq!(store.loads.load(Ordering::Relaxed), before_inspection);
    }

    #[test]
    fn explicit_remove_and_profile_logout_cleanup_are_scoped() {
        let store = MockStore::default();
        let a = scope(
            "profile-cleanup",
            "https://cloud.example",
            "space-a",
            "root-a",
        );
        let b = scope(
            "profile-cleanup",
            "https://cloud.example",
            "space-b",
            "root-b",
        );
        let other_profile = scope(
            "profile-cleanup-other",
            "https://cloud.example",
            "space-a",
            "root-a",
        );
        for item in [&a, &b, &other_profile] {
            store.store(item, b"test password").unwrap();
            record_status(item, RememberedStatus::KnownSaved);
        }
        store.remove(&a).unwrap();
        record_status(&a, RememberedStatus::NotSaved);
        assert_eq!(remembered_status(&a), "not_saved");
        assert_eq!(remembered_status(&b), "known_saved");
        assert_eq!(remembered_status(&b), "known_saved");
        assert_eq!(remembered_status(&other_profile), "known_saved");
    }

    #[test]
    fn unavailable_keyring_is_not_reported_as_missing_or_fallen_back() {
        let store = MockStore::default();
        *store.unavailable.lock().unwrap() = true;
        let item = scope(
            "profile-unavailable",
            "https://cloud.example",
            "space-a",
            "root-a",
        );
        record_status(&item, RememberedStatus::Unavailable);
        assert_eq!(remembered_status(&item), "unavailable");
        assert!(store.load(&item).is_err());
        assert!(store.store(&item, b"plaintext fallback forbidden").is_err());
    }

    #[test]
    fn secret_validation_bounds_passwords_and_profile_attributes() {
        assert!(validate_password(b"a").is_ok());
        assert!(validate_password(&vec![b'x'; MAX_PASSWORD_BYTES]).is_ok());
        assert!(validate_password(&vec![b'x'; MAX_PASSWORD_BYTES + 1]).is_err());
        assert!(validate_password(b"").is_err());
        assert!(validate_profile_id("default").is_ok());
        assert!(validate_profile_id("profile_123-a").is_ok());
        assert!(validate_profile_id("../profile").is_err());
        assert!(validate_profile_id("profile name").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn helper_deadline_kills_a_stuck_process() {
        let _guard = subprocess_test_guard();
        let child = Command::new("sh")
            .args(["-c", "exec sleep 10"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let started = Instant::now();
        let result = wait_bounded(child, Duration::from_millis(40));
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn helper_rejects_oversized_stdout_and_stderr() {
        let _guard = subprocess_test_guard();
        let stdout_child = Command::new("sh")
            .args(["-c", "head -c 8193 /dev/zero"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        assert!(wait_bounded(stdout_child, Duration::from_secs(2)).is_err());

        let stderr_child = Command::new("sh")
            .args(["-c", "head -c 8193 /dev/zero >&2"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        assert!(wait_bounded(stderr_child, Duration::from_secs(2)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn helper_receives_secret_payload_over_stdin_not_arguments() {
        let _guard = subprocess_test_guard();
        let password = "synthetic-password-only";
        let encoded = STANDARD_NO_PAD.encode(password.as_bytes());
        let mut command = Command::new("sh");
        command
            .args(["-c", "IFS= read -r value; printf '%s' \"$value\""])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child_args = command
            .get_args()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(!child_args.iter().any(|value| value.contains(password)));
        assert!(!child_args.iter().any(|value| value.contains(&encoded)));
        let mut child = command.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(encoded.as_bytes())
            .unwrap();
        let (status, output, diagnostics) = wait_bounded(child, Duration::from_secs(2)).unwrap();
        assert!(status.success());
        assert_eq!(output.as_slice(), encoded.as_bytes());
        assert!(diagnostics.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn credential_adapter_uses_synthetic_helper_without_real_keyring() {
        let _guard = subprocess_test_guard();
        use std::{fs, os::unix::fs::PermissionsExt};

        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let args_file = temp.path().join("args");
        let stdin_file = temp.path().join("stdin");
        let password = b"synthetic-password-only";
        let encoded = STANDARD_NO_PAD.encode(password);
        let program = temp.path().join("fake-secret-tool");
        fs::write(
            &program,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\ncase \"$1\" in\n  store) cat > '{}' ;;\n  lookup) cat '{}' ;;\n  clear) : ;;\n  *) exit 2 ;;\nesac\n",
                args_file.display(),
                stdin_file.display(),
                stdin_file.display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();

        let store = SecretServiceVaultCredentialStore {
            executable: program,
            state_dir: temp.path().to_owned(),
        };
        let item = scope(
            "profile-subprocess",
            "https://cloud.example",
            "space-a",
            "root-a",
        );
        store.store(&item, password).unwrap();
        let args = fs::read_to_string(args_file).unwrap();
        assert!(args.contains(SERVICE));
        assert!(args.contains("https://cloud.example"));
        assert!(!args.contains(std::str::from_utf8(password).unwrap()));
        assert!(!args.contains(&encoded));
        assert_eq!(fs::read(stdin_file).unwrap(), encoded.as_bytes());
        assert_eq!(store.load(&item).unwrap().unwrap().as_slice(), password);
    }

    #[cfg(unix)]
    #[test]
    fn forget_and_logout_epochs_revoke_stale_keyring_items_across_restart() {
        let _guard = subprocess_test_guard();
        use std::{fs, os::unix::fs::PermissionsExt};

        let temp = tempfile::tempdir().unwrap();
        let profile_dir = temp.path().join("profile");
        fs::create_dir(&profile_dir).unwrap();
        fs::set_permissions(&profile_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let saved_attrs = temp.path().join("saved-attrs");
        let saved_secret = temp.path().join("saved-secret");
        let program = temp.path().join("fake-secret-tool");
        fs::write(
            &program,
            format!(
                "#!/bin/sh\naction=$1\nshift\nprev=\nprofile_generation=\nvault_generation=\nfor value in \"$@\"; do\n  case \"$prev\" in profile_generation) profile_generation=$value;; vault_generation) vault_generation=$value;; esac\n  prev=$value\ndone\ncase \"$action\" in\n  store) printf '%s\\n%s\\n' \"$profile_generation\" \"$vault_generation\" > '{}'; cat > '{}' ;;\n  lookup) if [ -f '{}' ] && [ \"$(sed -n '1p' '{}')\" = \"$profile_generation\" ] && [ \"$(sed -n '2p' '{}')\" = \"$vault_generation\" ]; then cat '{}'; else exit 1; fi ;;\n  clear) exit 0 ;;\n  *) exit 2 ;;\nesac\n",
                saved_attrs.display(),
                saved_secret.display(),
                saved_attrs.display(),
                saved_attrs.display(),
                saved_attrs.display(),
                saved_secret.display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
        let store = SecretServiceVaultCredentialStore {
            executable: program.clone(),
            state_dir: profile_dir.clone(),
        };
        let first = scope(
            "profile-locked-clear",
            "https://cloud.example",
            "space-a",
            "root-a",
        );
        store.store(&first, b"saved password").unwrap();
        let old_attrs = fs::read_to_string(&saved_attrs).unwrap();
        let authority_path = profile_dir.join(AUTHORITY_FILE);
        let before_forget = fs::read(&authority_path).unwrap();
        assert_eq!(store.remove(&first).unwrap(), CredentialCleanup::Uncertain);
        assert_ne!(fs::read(&authority_path).unwrap(), before_forget);
        assert!(
            saved_secret.exists(),
            "fake keyring leaves locked item behind"
        );
        drop(store);
        clear_profile_status("profile-locked-clear");

        let restarted = SecretServiceVaultCredentialStore {
            executable: program.clone(),
            state_dir: profile_dir.clone(),
        };
        assert!(restarted.load(&first).unwrap().is_none());
        assert_eq!(fs::read_to_string(&saved_attrs).unwrap(), old_attrs);
        assert!(
            saved_secret.exists(),
            "old keyring item remains physically present"
        );

        restarted.store(&first, b"new password").unwrap();
        let before_logout = fs::read(&authority_path).unwrap();
        assert_eq!(
            revoke_profile_with_executable(&profile_dir, "profile-locked-clear", &program,)
                .unwrap(),
            CredentialCleanup::Uncertain
        );
        assert!(saved_secret.exists(), "fake broad clear leaves item behind");
        drop(restarted);

        let after_logout = SecretServiceVaultCredentialStore {
            executable: program,
            state_dir: profile_dir,
        };
        assert!(after_logout.load(&first).unwrap().is_none());
        assert_ne!(fs::read(&authority_path).unwrap(), before_logout);
    }

    #[cfg(unix)]
    #[test]
    fn authority_metadata_is_private_and_corruption_fails_before_keyring_access() {
        let _guard = subprocess_test_guard();
        use std::{fs, os::unix::fs::PermissionsExt};

        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let marker = temp.path().join("invoked");
        let program = temp.path().join("fake-secret-tool");
        fs::write(
            &program,
            format!("#!/bin/sh\ntouch '{}'\nexit 1\n", marker.display()),
        )
        .unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
        let store = SecretServiceVaultCredentialStore {
            executable: program,
            state_dir: temp.path().to_owned(),
        };
        let item = scope(
            "profile-authority",
            "https://private.example",
            "private-space",
            "private-root",
        );

        let tuple = store.authority_for_scope(&item, true).unwrap();
        assert!(valid_generation(&tuple.profile_generation));
        assert!(valid_generation(&tuple.vault_generation));
        let authority_path = temp.path().join(AUTHORITY_FILE);
        let metadata = fs::symlink_metadata(&authority_path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        let bytes = fs::read(&authority_path).unwrap();
        let contents = String::from_utf8(bytes).unwrap();
        assert!(!contents.contains("private.example"));
        assert!(!contents.contains("private-space"));
        assert!(!contents.contains("private-root"));

        fs::write(&authority_path, b"not valid metadata").unwrap();
        assert!(store.load(&item).is_err());
        assert!(
            !marker.exists(),
            "damaged authority must not reach keyring lookup"
        );
    }

    #[cfg(unix)]
    #[test]
    fn credential_operation_guard_serializes_revoke_after_saved_unlock_work() {
        let _guard = subprocess_test_guard();
        use std::{fs, os::unix::fs::PermissionsExt, sync::mpsc};

        let temp = tempfile::tempdir().unwrap();
        let profile_dir = temp.path().join("profile");
        fs::create_dir(&profile_dir).unwrap();
        fs::set_permissions(&profile_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let authority = read_authority(&profile_dir, "profile-serialized").unwrap();
        write_authority(&profile_dir, &authority).unwrap();
        let authority_path = profile_dir.join(AUTHORITY_FILE);
        let before = fs::read(&authority_path).unwrap();
        let program = temp.path().join("fake-secret-tool");
        fs::write(&program, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();

        let other_profile_dir = temp.path().join("other-profile");
        fs::create_dir(&other_profile_dir).unwrap();
        fs::set_permissions(&other_profile_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let guard = begin_credential_operation(&profile_dir, "profile-serialized").unwrap();
        let other_profile_guard =
            begin_credential_operation(&other_profile_dir, "profile-serialized-other").unwrap();
        drop(other_profile_guard);
        let (attempted_tx, attempted_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let worker_dir = profile_dir.clone();
        let worker_program = program.clone();
        let worker = std::thread::spawn(move || {
            attempted_tx.send(()).unwrap();
            let result =
                revoke_profile_with_executable(&worker_dir, "profile-serialized", &worker_program);
            finished_tx.send(result).unwrap();
        });
        attempted_rx.recv().unwrap();
        assert!(finished_rx.try_recv().is_err());
        // The first holder represents a use_saved lookup plus KDF/session
        // publication. Forget/logout cannot rotate authority until it ends.
        assert_eq!(fs::read(&authority_path).unwrap(), before);
        drop(guard);
        assert_eq!(
            finished_rx
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap(),
            CredentialCleanup::Uncertain
        );
        assert_ne!(fs::read(&authority_path).unwrap(), before);
        worker.join().unwrap();
    }
}
