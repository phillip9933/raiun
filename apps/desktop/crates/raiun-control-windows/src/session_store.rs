//! Current-user DPAPI session persistence for Windows.
//!
//! The payload stays opaque to this crate. Callers must serialize and validate
//! sessions with their existing format and enforce the same 65,536-byte bound.

use std::{
    env,
    ffi::c_void,
    fs::File,
    io::{self, Read, Write},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle},
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use sha2::{Digest, Sha256};
use windows_sys::Win32::{
    Foundation::{
        ERROR_ALREADY_EXISTS, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
    },
    Security::{
        Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SE_FILE_OBJECT, SetSecurityInfo,
        },
        Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
        },
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
        SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW, DeleteFileW,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, GetFileInformationByHandle, MOVEFILE_REPLACE_EXISTING,
        MOVEFILE_WRITE_THROUGH, MoveFileExW, OPEN_EXISTING,
    },
};

use zeroize::Zeroizing;

const MAX_SESSION_BYTES: usize = 65_536;
const MAX_CIPHERTEXT_BYTES: usize = 256 * 1024;
const ENVELOPE_MAGIC: &[u8] = b"RAIUN-DPAPI-SESSION\0\x01";
const ACTIVE_POINTER_MAGIC: &[u8] = b"RAIUN-DPAPI-ACTIVE\0\x01";
const MAX_ACTIVE_POINTER_BYTES: usize = 16 * 1024;
const MAX_ROOT_CONFIG_BYTES: usize = 16 * 1024;
const MAX_PROFILE_REGISTRY_BYTES: usize = 1024 * 1024;
const MAX_EDIT_RECORD_PLAINTEXT_BYTES: usize = 17 * 1024 * 1024;
const MAX_EDIT_RECORD_CIPHERTEXT_BYTES: usize = 18 * 1024 * 1024;
const SDDL_REVISION_1: u32 = 1;
const WRITE_DAC_ACCESS: u32 = 0x0004_0000;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Stores opaque serialized sessions encrypted by Windows DPAPI for the
/// current user. It never uses machine-wide DPAPI protection.
#[derive(Clone)]
pub struct DpapiSessionStore {
    root: PathBuf,
    // Derived profile stores retain exact private directory/ancestor pins.
    // Their OI/CI policy is verified, never rewritten by legacy root repair.
    profile_directory: Option<Arc<crate::PrivateDirectory>>,
}

impl DpapiSessionStore {
    /// Locate the current user's `%LOCALAPPDATA%` and prepare Raiun's private
    /// session directory. The path is obtained from the environment, never IPC.
    pub fn current_user() -> io::Result<Self> {
        let local = env::var_os("LOCALAPPDATA")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                io::Error::other("Current user's local application data is unavailable")
            })?;
        let local = PathBuf::from(local);
        if !local.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Current user's local application data must be absolute",
            ));
        }
        // Normalize only the existing trusted base. Keep a local disk path in
        // the public representation: private cache APIs deliberately reject
        // device/verbatim prefixes. Native calls encode extended paths below,
        // without changing this policy or canonicalizing untrusted children.
        let local = std::fs::canonicalize(local)?;
        let local = match local.components().next() {
            Some(std::path::Component::Prefix(prefix))
                if matches!(prefix.kind(), std::path::Prefix::VerbatimDisk(_)) =>
            {
                let units = local.as_os_str().encode_wide().collect::<Vec<_>>();
                PathBuf::from(std::ffi::OsString::from_wide(&units[4..]))
            }
            _ => local,
        };
        if !local.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Current user's local application data must be a directory",
            ));
        }
        let root = local.join("Raiun").join("sessions");
        let store = Self {
            root,
            profile_directory: None,
        };
        store.ensure_private_root()?;
        Ok(store)
    }

    /// Derive independent private storage for a trusted registry profile.
    /// Default retains the existing location for upgrade compatibility. This
    /// only creates/validates storage; it does not select, restore or sign in.
    /// Callers must still pass the same trusted profile to identity-scoped
    /// session/root APIs and validate restored account identity; directory
    /// separation does not replace those checks.
    pub fn for_profile(&self, profile: &str) -> io::Result<Self> {
        if self.profile_directory.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Derive profiles from the base store",
            ));
        }
        if profile == "default" {
            return Ok(self.clone());
        }
        if !profile.strip_prefix("profile-").is_some_and(|suffix| {
            suffix.len() == 32
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid profile identity",
            ));
        }
        // Reuse pinned private-directory admission. Existing children must
        // already have the exact private policy; never repair them here.
        let parent = crate::PinnedDirectory::open(&self.root)?;
        let child =
            crate::PrivateDirectory::create_or_open_under(&parent, std::ffi::OsStr::new(profile))?;
        child.verify_path()?;
        Ok(Self {
            root: child.path().to_path_buf(),
            profile_directory: Some(Arc::new(child)),
        })
    }

    /// Inventory only bounded, protected root-configuration metadata for a trusted
    /// profile. This preserves reservations after logout removes the active
    /// session pointer. It never reads/decrypts session files or grants account
    /// authority; the broker must fully decode ownership before using a record.
    /// The broker must serialize inventory with root-config mutations (normally
    /// before starting runtimes). Any malformed, foreign, unreadable or excessive
    /// inventory fails closed.
    pub fn load_root_config_inventory(&self, expected_profile: &str) -> io::Result<Vec<Vec<u8>>> {
        validate_identity(Some(expected_profile), "inventory", "inventory")?;
        if !self.ensure_existing_private_root()? {
            return Ok(Vec::new());
        }
        let parent = crate::PinnedDirectory::open(&self.root)?;
        let mut records = Vec::new();
        for (index, entry) in std::fs::read_dir(&self.root)?.enumerate() {
            if index >= 4096 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Root metadata inventory exceeds its entry limit",
                ));
            }
            let entry = entry?;
            let name = entry.file_name();
            let Some(name_text) = name.to_str() else {
                continue;
            };
            if !name_text.to_ascii_lowercase().ends_with(".root-config") {
                continue;
            }
            let digest = name_text.strip_suffix(".root-config").ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Root metadata filename is not canonical",
                )
            })?;
            if records.len() >= 64
                || digest.len() != 64
                || !digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Root metadata inventory is invalid",
                ));
            }
            let (mut file, _) = parent.open_immutable_regular_file(&name)?;
            crate::private_directory::verify_private_metadata_file(&file)?;
            if file.metadata()?.len() > MAX_ROOT_CONFIG_BYTES as u64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Stored root configuration exceeds the storage limit",
                ));
            }
            let mut bytes = Vec::new();
            Read::by_ref(&mut file)
                .take((MAX_ROOT_CONFIG_BYTES + 1) as u64)
                .read_to_end(&mut bytes)?;
            if bytes.is_empty() || bytes.len() > MAX_ROOT_CONFIG_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Stored root configuration has an invalid size",
                ));
            }
            let metadata: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Stored root configuration is invalid",
                )
            })?;
            let scope = metadata
                .get("profile_scope")
                .and_then(serde_json::Value::as_str);
            let server = metadata.get("server").and_then(serde_json::Value::as_str);
            let client = metadata
                .get("client_id")
                .and_then(serde_json::Value::as_str);
            let (Some(scope), Some(server), Some(client)) = (scope, server, client) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Root metadata identity is invalid",
                ));
            };
            validate_identity(Some(scope), server, client)?;
            if scope != expected_profile
                || hex(&identity_digest(Some(scope), server, client)) != digest
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Root metadata identity does not match",
                ));
            }
            crate::private_directory::verify_private_metadata_file(&file)?;
            parent.verify_path()?;
            records.push(bytes);
        }
        parent.verify_path()?;
        Ok(records)
    }

    /// Read the fixed non-secret account registry without scanning credentials.
    /// Only verified absence returns None; malformed content remains the caller's
    /// responsibility and must never be interpreted as a default migration.
    pub fn load_profile_registry(&self) -> io::Result<Option<Vec<u8>>> {
        let directory = self.profile_registry_directory()?;
        let mut reader =
            match directory.open_owned_immutable_file(std::ffi::OsStr::new("registry.json")) {
                Ok(reader) => reader,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error),
            };
        if reader.metadata()?.len() > MAX_PROFILE_REGISTRY_BYTES as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Account registry exceeds the storage limit",
            ));
        }
        let mut bytes = Vec::new();
        reader
            .by_ref()
            .take((MAX_PROFILE_REGISTRY_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        reader.verify()?;
        if bytes.is_empty() || bytes.len() > MAX_PROFILE_REGISTRY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Account registry has an invalid size",
            ));
        }
        Ok(Some(bytes))
    }

    /// Atomically replace only the fixed non-secret account registry. The broker
    /// must validate the document and serialize mutations before this call, and
    /// publish its in-memory selection only after success. No session is moved.
    pub fn save_profile_registry(&self, bytes: &[u8]) -> io::Result<()> {
        if bytes.is_empty() || bytes.len() > MAX_PROFILE_REGISTRY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Account registry has an invalid size",
            ));
        }
        let directory = self.profile_registry_directory()?;
        // Validate any existing destination without repairing its ACL. Release
        // the immutable pin before atomic replacement, retaining directory pins.
        match directory.open_owned_immutable_file(std::ffi::OsStr::new("registry.json")) {
            Ok(reader) => reader.verify()?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error),
        }
        let destination = directory.path().join("registry.json");
        let temporary = self.write_temp(&destination, bytes)?;
        let result = (|| {
            directory.verify_path()?;
            let from = wide_path(&temporary)?;
            let to = wide_path(&destination)?;
            // SAFETY: both fixed sibling paths are within the retained private
            // directory. Same atomic write-through replacement as session data;
            // this renames the entry rather than following a destination link.
            let moved = unsafe {
                MoveFileExW(
                    from.as_ptr(),
                    to.as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            };
            if moved == 0 {
                return Err(io::Error::last_os_error());
            }
            directory.verify_path()
        })();
        if result.is_err() {
            let _ = remove_exact_file(&temporary);
        }
        result
    }

    fn profile_registry_directory(&self) -> io::Result<Arc<crate::PrivateDirectory>> {
        if self.profile_directory.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Account registry belongs to the base store",
            ));
        }
        self.ensure_private_root()?;
        let parent = crate::PinnedDirectory::open(&self.root)?;
        let directory = crate::PrivateDirectory::create_or_open_under(
            &parent,
            std::ffi::OsStr::new("profiles"),
        )?;
        directory.verify_path()?;
        Ok(Arc::new(directory))
    }

    /// Private per-user application state directory used for protected local
    /// recovery records. The returned path is trusted local state, never IPC.
    pub fn local_edit_state_directory(&self) -> &Path {
        &self.root
    }

    /// Apply the current user's protected DACL to a directory below the
    /// private local edit root. Journal callers first pin the complete path
    /// chain without delete sharing, so this path-based handle open cannot be
    /// redirected to a replacement while the ACL is applied.
    pub fn protect_local_edit_directory(&self, path: &Path) -> io::Result<()> {
        if !path.starts_with(&self.root) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Local edit directory is outside the private state root",
            ));
        }
        let sid = super::win32::current_user_sid_for_storage()?;
        let descriptor = security_descriptor(&wide(&format!("D:P(A;;FA;;;{sid})")))?;
        let handle = open_directory(path)?;
        secure_handle_dacl(handle.as_raw_handle() as HANDLE, descriptor.dacl)
    }

    /// Protect one bounded local recovery record for the current Windows
    /// user. The caller-supplied associated data is hashed and supplied to
    /// DPAPI as optional entropy so ciphertext cannot be moved between edit
    /// scopes or record IDs. This does not persist or expose a session token.
    pub fn protect_local_edit_record(
        &self,
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> io::Result<Vec<u8>> {
        if associated_data.is_empty()
            || associated_data.len() > 64 * 1024
            || plaintext.is_empty()
            || plaintext.len() > MAX_EDIT_RECORD_PLAINTEXT_BYTES
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Local edit record exceeds the secure storage limit",
            ));
        }
        let entropy: [u8; 32] = Sha256::digest(associated_data).into();
        protect_bounded(plaintext, &entropy, MAX_EDIT_RECORD_CIPHERTEXT_BYTES)
    }

    /// Unprotect a local edit record for the current Windows user and exact
    /// associated-data binding. Returned plaintext is zeroized on drop.
    pub fn unprotect_local_edit_record(
        &self,
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> io::Result<Zeroizing<Vec<u8>>> {
        if associated_data.is_empty() || associated_data.len() > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Local edit record binding is invalid",
            ));
        }
        let entropy: [u8; 32] = Sha256::digest(associated_data).into();
        unprotect_bounded(
            ciphertext,
            &entropy,
            MAX_EDIT_RECORD_CIPHERTEXT_BYTES,
            MAX_EDIT_RECORD_PLAINTEXT_BYTES,
        )
    }

    /// Encrypt and atomically replace a session scoped to one profile, server,
    /// and OAuth client identity.
    pub fn save(
        &self,
        profile_scope: Option<&str>,
        server: &str,
        client_id: &str,
        plaintext: &[u8],
    ) -> io::Result<()> {
        validate_identity(profile_scope, server, client_id)?;
        validate_session_size(plaintext.len())?;
        self.ensure_private_root()?;
        let identity = identity_digest(profile_scope, server, client_id);
        let entropy = identity;
        let encrypted = protect(plaintext, &entropy)?;
        if encrypted.len() > MAX_CIPHERTEXT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Encrypted session exceeds the storage limit",
            ));
        }
        let mut envelope = Vec::with_capacity(ENVELOPE_MAGIC.len() + encrypted.len());
        envelope.extend_from_slice(ENVELOPE_MAGIC);
        envelope.extend_from_slice(&encrypted);
        let destination = self.session_path(&identity);
        secure_existing_file(&destination)?;
        let temporary = self.write_temp(&destination, &envelope)?;
        if destination.exists() {
            reject_reparse_file(&destination)?;
        }
        let from = wide_path(&temporary)?;
        let to = wide_path(&destination)?;
        let moved = unsafe {
            MoveFileExW(
                from.as_ptr(),
                to.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if moved == 0 {
            let error = io::Error::last_os_error();
            let _ = remove_exact_file(&temporary);
            return Err(error);
        }
        Ok(())
    }

    /// Load and decrypt one exact identity. The returned plaintext is
    /// zeroized when dropped. Missing files return `Ok(None)`.
    pub fn load(
        &self,
        profile_scope: Option<&str>,
        server: &str,
        client_id: &str,
    ) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
        validate_identity(profile_scope, server, client_id)?;
        if !self.ensure_existing_private_root()? {
            return Ok(None);
        }
        let identity = identity_digest(profile_scope, server, client_id);
        let path = self.session_path(&identity);
        let Some(file) = open_regular_file(&path, GENERIC_READ)? else {
            return Ok(None);
        };
        secure_file_handle(file.as_raw_handle() as HANDLE)?;
        let metadata = file.metadata()?;
        if metadata.len() > (ENVELOPE_MAGIC.len() + MAX_CIPHERTEXT_BYTES) as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Stored session exceeds the secure storage limit",
            ));
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
        file.take((ENVELOPE_MAGIC.len() + MAX_CIPHERTEXT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > ENVELOPE_MAGIC.len() + MAX_CIPHERTEXT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Stored session exceeds the secure storage limit",
            ));
        }
        if bytes.len() < ENVELOPE_MAGIC.len() || !bytes.starts_with(ENVELOPE_MAGIC) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Stored session format is invalid",
            ));
        }
        let ciphertext = &bytes[ENVELOPE_MAGIC.len()..];
        let plaintext = unprotect(ciphertext, &identity)?;
        if plaintext.is_empty() || plaintext.len() > MAX_SESSION_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Stored session exceeds the secure storage limit",
            ));
        }
        Ok(Some(plaintext))
    }

    /// Remove one exact identity's session. It does not create the store when
    /// no store exists and never follows a reparse point.
    pub fn remove(
        &self,
        profile_scope: Option<&str>,
        server: &str,
        client_id: &str,
    ) -> io::Result<()> {
        validate_identity(profile_scope, server, client_id)?;
        if !self.ensure_existing_private_root()? {
            return Ok(());
        }
        remove_exact_file(&self.session_path(&identity_digest(profile_scope, server, client_id)))
    }

    /// Persist bounded non-secret root configuration beneath the same
    /// current-user-only private directory as protected sessions. The file is
    /// scoped to one exact profile/server/client identity and atomically
    /// replaced; callers remain responsible for validating its contents.
    pub fn save_root_config(
        &self,
        profile_scope: &str,
        server: &str,
        client_id: &str,
        bytes: &[u8],
    ) -> io::Result<()> {
        validate_identity(Some(profile_scope), server, client_id)?;
        if bytes.is_empty() || bytes.len() > MAX_ROOT_CONFIG_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Root configuration exceeds the storage limit",
            ));
        }
        self.ensure_private_root()?;
        let destination =
            self.root_config_path(&identity_digest(Some(profile_scope), server, client_id));
        secure_existing_file(&destination)?;
        let temporary = self.write_temp(&destination, bytes)?;
        if destination.exists() {
            reject_reparse_file(&destination)?;
        }
        let from = wide_path(&temporary)?;
        let to = wide_path(&destination)?;
        let moved = unsafe {
            MoveFileExW(
                from.as_ptr(),
                to.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if moved == 0 {
            let error = io::Error::last_os_error();
            let _ = remove_exact_file(&temporary);
            return Err(error);
        }
        Ok(())
    }

    /// Load bounded non-secret root configuration for one exact identity.
    /// Missing configuration returns `Ok(None)` and no directory scan occurs.
    pub fn load_root_config(
        &self,
        profile_scope: &str,
        server: &str,
        client_id: &str,
    ) -> io::Result<Option<Vec<u8>>> {
        validate_identity(Some(profile_scope), server, client_id)?;
        if !self.ensure_existing_private_root()? {
            return Ok(None);
        }
        let path = self.root_config_path(&identity_digest(Some(profile_scope), server, client_id));
        let Some(file) = open_regular_file(&path, GENERIC_READ)? else {
            return Ok(None);
        };
        secure_file_handle(file.as_raw_handle() as HANDLE)?;
        let metadata = file.metadata()?;
        if metadata.len() > MAX_ROOT_CONFIG_BYTES as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Stored root configuration exceeds the storage limit",
            ));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take((MAX_ROOT_CONFIG_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_ROOT_CONFIG_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Stored root configuration exceeds the storage limit",
            ));
        }
        Ok(Some(bytes))
    }

    /// Remove root configuration for one exact identity. Logout calls this
    /// only after revoking session-restore authority.
    pub fn remove_root_config(
        &self,
        profile_scope: &str,
        server: &str,
        client_id: &str,
    ) -> io::Result<()> {
        validate_identity(Some(profile_scope), server, client_id)?;
        if !self.ensure_existing_private_root()? {
            return Ok(());
        }
        remove_exact_file(&self.root_config_path(&identity_digest(
            Some(profile_scope),
            server,
            client_id,
        )))
    }

    /// Atomically select one exact saved identity for startup restoration.
    /// Only bounded identity metadata is stored in the pointer; session tokens
    /// remain in the separate DPAPI-protected session blob.
    pub fn set_active_identity(
        &self,
        profile_scope: &str,
        server: &str,
        client_id: &str,
    ) -> io::Result<()> {
        validate_identity(Some(profile_scope), server, client_id)?;
        self.ensure_private_root()?;
        let entropy = active_identity_digest(profile_scope, server, client_id);
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "profile_scope": profile_scope,
                "server": server,
                "client_id": client_id,
            }))
            .map_err(|_| io::Error::other("Could not encode the active session pointer"))?,
        );
        if plaintext.is_empty() || plaintext.len() > MAX_ACTIVE_POINTER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Active session pointer exceeds the storage limit",
            ));
        }
        let encrypted = protect(&plaintext, &entropy)?;
        if encrypted.len() > MAX_CIPHERTEXT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Active session pointer exceeds the storage limit",
            ));
        }
        let mut envelope =
            Vec::with_capacity(ACTIVE_POINTER_MAGIC.len() + entropy.len() + encrypted.len());
        envelope.extend_from_slice(ACTIVE_POINTER_MAGIC);
        envelope.extend_from_slice(&entropy);
        envelope.extend_from_slice(&encrypted);
        let destination = self.active_pointer_path();
        secure_existing_file(&destination)?;
        let temporary = self.write_temp(&destination, &envelope)?;
        if destination.exists() {
            reject_reparse_file(&destination)?;
        }
        let from = wide_path(&temporary)?;
        let to = wide_path(&destination)?;
        let moved = unsafe {
            MoveFileExW(
                from.as_ptr(),
                to.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if moved == 0 {
            let error = io::Error::last_os_error();
            let _ = remove_exact_file(&temporary);
            return Err(error);
        }
        Ok(())
    }

    /// Read the one active pointer without scanning the session directory.
    /// A caller must load the exact session blob and validate its identity.
    pub fn active_identity(&self) -> io::Result<Option<(String, String, String)>> {
        if !self.ensure_existing_private_root()? {
            return Ok(None);
        }
        let path = self.active_pointer_path();
        let Some(file) = open_regular_file(&path, GENERIC_READ)? else {
            return Ok(None);
        };
        secure_file_handle(file.as_raw_handle() as HANDLE)?;
        let max_file_len = ACTIVE_POINTER_MAGIC.len() + 32 + MAX_CIPHERTEXT_BYTES;
        let metadata = file.metadata()?;
        if metadata.len() > max_file_len as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Active session pointer exceeds the storage limit",
            ));
        }
        let mut envelope = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
        file.take(max_file_len as u64 + 1)
            .read_to_end(&mut envelope)?;
        if envelope.len() > max_file_len
            || envelope.len() < ACTIVE_POINTER_MAGIC.len() + 32
            || !envelope.starts_with(ACTIVE_POINTER_MAGIC)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Active session pointer format is invalid",
            ));
        }
        let digest_start = ACTIVE_POINTER_MAGIC.len();
        let ciphertext_start = digest_start + 32;
        let digest: [u8; 32] = envelope[digest_start..ciphertext_start]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid pointer digest"))?;
        let plaintext = unprotect(&envelope[ciphertext_start..], &digest)?;
        if plaintext.len() > MAX_ACTIVE_POINTER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Active session pointer exceeds the storage limit",
            ));
        }
        let value: serde_json::Value = serde_json::from_slice(&plaintext).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Active session pointer is invalid",
            )
        })?;
        let Some(object) = value.as_object() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Active session pointer is invalid",
            ));
        };
        if object.len() != 4 || value["version"].as_u64() != Some(1) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Active session pointer version is unsupported",
            ));
        }
        let profile_scope = value["profile_scope"].as_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Active session pointer is invalid",
            )
        })?;
        let server = value["server"].as_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Active session pointer is invalid",
            )
        })?;
        let client_id = value["client_id"].as_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Active session pointer is invalid",
            )
        })?;
        validate_identity(Some(profile_scope), server, client_id)?;
        if active_identity_digest(profile_scope, server, client_id) != digest {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Active session pointer identity does not match",
            ));
        }
        Ok(Some((
            profile_scope.to_owned(),
            server.to_owned(),
            client_id.to_owned(),
        )))
    }

    /// Revoke startup restoration authority. Idempotent when no pointer exists.
    pub fn clear_active_identity(&self) -> io::Result<()> {
        if !self.ensure_existing_private_root()? {
            return Ok(());
        }
        remove_exact_file(&self.active_pointer_path())
    }

    fn ensure_private_root(&self) -> io::Result<()> {
        if let Some(directory) = &self.profile_directory {
            return directory.verify_path();
        }
        let sid = super::win32::current_user_sid_for_storage()?;
        let sddl = wide(&format!("D:P(A;;FA;;;{sid})"));
        let descriptor = security_descriptor(&sddl)?;
        for directory in [&self.root.parent().unwrap().to_path_buf(), &self.root] {
            let path = wide_path(directory)?;
            let created = unsafe { CreateDirectoryW(path.as_ptr(), &descriptor.attributes()) };
            if created == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
                    return Err(error);
                }
            }
            let handle = open_directory(directory)?;
            secure_handle_dacl(handle.as_raw_handle() as HANDLE, descriptor.dacl)?;
        }
        Ok(())
    }

    fn ensure_existing_private_root(&self) -> io::Result<bool> {
        if let Some(directory) = &self.profile_directory {
            directory.verify_path()?;
            return Ok(true);
        }
        let sid = super::win32::current_user_sid_for_storage()?;
        let sddl = wide(&format!("D:P(A;;FA;;;{sid})"));
        let descriptor = security_descriptor(&sddl)?;
        for directory in [&self.root.parent().unwrap().to_path_buf(), &self.root] {
            let handle = match open_directory(directory) {
                Ok(handle) => handle,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
                Err(error) => return Err(error),
            };
            secure_handle_dacl(handle.as_raw_handle() as HANDLE, descriptor.dacl)?;
        }
        Ok(true)
    }

    fn session_path(&self, identity: &[u8; 32]) -> PathBuf {
        self.root.join(format!("{}.session", hex(identity)))
    }

    fn root_config_path(&self, identity: &[u8; 32]) -> PathBuf {
        self.root.join(format!("{}.root-config", hex(identity)))
    }

    fn active_pointer_path(&self) -> PathBuf {
        self.root.join("active-session.pointer")
    }

    fn write_temp(&self, destination: &Path, data: &[u8]) -> io::Result<PathBuf> {
        let sid = super::win32::current_user_sid_for_storage()?;
        let sddl = wide(&format!("D:P(A;;FA;;;{sid})"));
        let descriptor = security_descriptor(&sddl)?;
        for _ in 0..16 {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let name = format!(".session-{}-{sequence}.tmp", std::process::id());
            let path = destination.with_file_name(name);
            let path_wide = wide_path(&path)?;
            let raw = unsafe {
                CreateFileW(
                    path_wide.as_ptr(),
                    GENERIC_WRITE,
                    0,
                    &descriptor.attributes(),
                    CREATE_NEW,
                    FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OPEN_REPARSE_POINT,
                    std::ptr::null_mut(),
                )
            };
            if raw == INVALID_HANDLE_VALUE {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::AlreadyExists {
                    continue;
                }
                return Err(error);
            }
            let mut file = unsafe { File::from_raw_handle(raw as RawHandle) };
            if let Err(error) = file.write_all(data).and_then(|()| file.sync_all()) {
                drop(file);
                let _ = remove_exact_file(&path);
                return Err(error);
            }
            return Ok(path);
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Could not allocate a private temporary session file",
        ))
    }
}

struct SecurityDescriptor {
    raw: *mut c_void,
    dacl: *mut windows_sys::Win32::Security::ACL,
}

impl SecurityDescriptor {
    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.raw,
            bInheritHandle: 0,
        }
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe { LocalFree(self.raw) };
    }
}

fn security_descriptor(sddl: &[u16]) -> io::Result<SecurityDescriptor> {
    let mut raw = std::ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut raw,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 || raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = std::ptr::null_mut();
    let ok = unsafe { GetSecurityDescriptorDacl(raw, &mut present, &mut dacl, &mut defaulted) };
    if ok == 0 || present == 0 || dacl.is_null() {
        unsafe { LocalFree(raw) };
        return Err(io::Error::other(
            "Could not create the private session-store access list",
        ));
    }
    Ok(SecurityDescriptor { raw, dacl })
}

fn secure_handle_dacl(
    handle: HANDLE,
    dacl: *mut windows_sys::Win32::Security::ACL,
) -> io::Result<()> {
    let result = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null_mut(),
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    Ok(())
}

fn secure_file_handle(handle: HANDLE) -> io::Result<()> {
    let sid = super::win32::current_user_sid_for_storage()?;
    let descriptor = security_descriptor(&wide(&format!("D:P(A;;FA;;;{sid})")))?;
    secure_handle_dacl(handle, descriptor.dacl)
}

fn secure_existing_file(path: &Path) -> io::Result<()> {
    if let Some(file) = open_regular_file(path, GENERIC_READ)? {
        secure_file_handle(file.as_raw_handle() as HANDLE)?;
    }
    Ok(())
}

fn open_directory(path: &Path) -> io::Result<OwnedHandle> {
    let path_wide = wide_path(path)?;
    let raw = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | WRITE_DAC_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
    let info = file_info(handle.as_raw_handle() as HANDLE)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Session-store directory is not a private regular directory",
        ));
    }
    Ok(handle)
}

fn open_regular_file(path: &Path, access: u32) -> io::Result<Option<File>> {
    let path_wide = wide_path(path)?;
    let raw = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            access | WRITE_DAC_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error);
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
    let info = file_info(handle.as_raw_handle() as HANDLE)?;
    if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Session entry is not a regular file",
        ));
    }
    let raw = std::os::windows::io::IntoRawHandle::into_raw_handle(handle);
    Ok(Some(unsafe { File::from_raw_handle(raw) }))
}

fn file_info(handle: HANDLE) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info)
}

fn reject_reparse_file(path: &Path) -> io::Result<()> {
    if let Some(file) = open_regular_file(path, GENERIC_READ)? {
        drop(file);
        Ok(())
    } else {
        Ok(())
    }
}

fn remove_exact_file(path: &Path) -> io::Result<()> {
    let Some(file) = open_regular_file(path, GENERIC_READ)? else {
        return Ok(());
    };
    secure_file_handle(file.as_raw_handle() as HANDLE)?;
    drop(file);
    let path_wide = wide_path(path)?;
    let deleted = unsafe { DeleteFileW(path_wide.as_ptr()) };
    if deleted == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn protect(plaintext: &[u8], entropy: &[u8; 32]) -> io::Result<Vec<u8>> {
    protect_bounded(plaintext, entropy, MAX_CIPHERTEXT_BYTES)
}

fn protect_bounded(
    plaintext: &[u8],
    entropy: &[u8; 32],
    max_ciphertext_bytes: usize,
) -> io::Result<Vec<u8>> {
    if plaintext.is_empty() || plaintext.len() > u32::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Protected data exceeds the secure storage limit",
        ));
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let optional_entropy = CRYPT_INTEGER_BLOB {
        cbData: entropy.len() as u32,
        pbData: entropy.as_ptr() as *mut u8,
    };
    let mut output = unsafe { std::mem::zeroed::<CRYPT_INTEGER_BLOB>() };
    let ok = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            &optional_entropy,
            std::ptr::null_mut(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0
        || output.pbData.is_null()
        || output.cbData == 0
        || output.cbData as usize > max_ciphertext_bytes
    {
        if !output.pbData.is_null() {
            unsafe {
                if ok != 0 && output.cbData > 0 {
                    zeroize::Zeroize::zeroize(std::slice::from_raw_parts_mut(
                        output.pbData,
                        output.cbData as usize,
                    ));
                }
                LocalFree(output.pbData.cast());
            }
        }
        return Err(io::Error::last_os_error());
    }
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe {
        LocalFree(output.pbData.cast());
    }
    Ok(result)
}

fn unprotect(ciphertext: &[u8], entropy: &[u8; 32]) -> io::Result<Zeroizing<Vec<u8>>> {
    validate_ciphertext_size(ciphertext.len())?;
    unprotect_bounded(ciphertext, entropy, MAX_CIPHERTEXT_BYTES, MAX_SESSION_BYTES)
}

fn unprotect_bounded(
    ciphertext: &[u8],
    entropy: &[u8; 32],
    max_ciphertext_bytes: usize,
    max_plaintext_bytes: usize,
) -> io::Result<Zeroizing<Vec<u8>>> {
    if ciphertext.is_empty()
        || ciphertext.len() > max_ciphertext_bytes
        || ciphertext.len() > u32::MAX as usize
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Protected data exceeds the secure storage limit",
        ));
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: ciphertext.len() as u32,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let optional_entropy = CRYPT_INTEGER_BLOB {
        cbData: entropy.len() as u32,
        pbData: entropy.as_ptr() as *mut u8,
    };
    let mut output = unsafe { std::mem::zeroed::<CRYPT_INTEGER_BLOB>() };
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            &optional_entropy,
            std::ptr::null_mut(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0
        || output.pbData.is_null()
        || output.cbData == 0
        || output.cbData as usize > max_plaintext_bytes
    {
        if !output.pbData.is_null() {
            unsafe {
                if ok != 0 && output.cbData > 0 {
                    zeroize::Zeroize::zeroize(std::slice::from_raw_parts_mut(
                        output.pbData,
                        output.cbData as usize,
                    ));
                }
                LocalFree(output.pbData.cast());
            }
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Stored session could not be decrypted for this user",
        ));
    }
    let plaintext = Zeroizing::new(
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec(),
    );
    unsafe {
        zeroize::Zeroize::zeroize(std::slice::from_raw_parts_mut(
            output.pbData,
            output.cbData as usize,
        ));
        LocalFree(output.pbData.cast());
    }
    Ok(plaintext)
}

fn validate_session_size(size: usize) -> io::Result<()> {
    if size == 0 || size > MAX_SESSION_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Session exceeds the secure storage limit",
        ));
    }
    Ok(())
}

fn validate_ciphertext_size(size: usize) -> io::Result<()> {
    if size == 0 || size > MAX_CIPHERTEXT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Stored session exceeds the secure storage limit",
        ));
    }
    Ok(())
}

fn validate_identity(profile_scope: Option<&str>, server: &str, client_id: &str) -> io::Result<()> {
    let parts = [profile_scope.unwrap_or(""), server, client_id];
    if profile_scope == Some("")
        || server.is_empty()
        || client_id.is_empty()
        || parts
            .iter()
            .any(|part| part.len() > 4096 || part.chars().any(char::is_control))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Session identity is invalid",
        ));
    }
    Ok(())
}

fn identity_digest(profile_scope: Option<&str>, server: &str, client_id: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"raiun-session-store-v1");
    for part in [profile_scope.unwrap_or(""), server, client_id] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    digest.finalize().into()
}

fn active_identity_digest(profile_scope: &str, server: &str, client_id: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"raiun-active-session-pointer-v1");
    for part in [profile_scope, server, client_id] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    digest.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    super::private_directory::wide_extended_path(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires isolated ordinary Windows user and native private-storage ACL support"]
    fn root_inventory_survives_logout_pointer_removal() {
        let root = std::env::temp_dir().join(format!(
            "raiun-root-inventory-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        eprintln!("synthetic_root_inventory_fixture={}", root.display());
        let store = DpapiSessionStore {
            root: root.join("sessions"),
            profile_directory: None,
        };
        store.ensure_private_root().unwrap();
        let server = "https://synthetic.invalid";
        let client = "synthetic-client";
        let metadata = serde_json::to_vec(&serde_json::json!({"version":2,"profile_scope":"default","server":server,"client_id":client,"path":"C:\\Synthetic"})).unwrap();
        store
            .save_root_config("default", server, client, &metadata)
            .unwrap();
        // If inventory tried to read credentials instead of metadata, these
        // deliberately invalid opaque session bytes could not be decrypted.
        let session_path = store.session_path(&identity_digest(Some("default"), server, client));
        let sentinel = b"synthetic non-session sentinel";
        let temporary = store.write_temp(&session_path, sentinel).unwrap();
        std::fs::rename(temporary, &session_path).unwrap();
        store
            .set_active_identity("default", server, client)
            .unwrap();
        store.clear_active_identity().unwrap();
        assert!(store.active_identity().unwrap().is_none());
        assert_eq!(
            store.load_root_config_inventory("default").unwrap(),
            vec![metadata.clone()]
        );
        assert!(
            store
                .load_root_config_inventory("profile-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .is_err()
        );
        assert_eq!(std::fs::read(&session_path).unwrap(), sentinel);
        assert_eq!(
            store.load_root_config("default", server, client).unwrap(),
            Some(metadata)
        );
        let canonical = store.root_config_path(&identity_digest(Some("default"), server, client));
        let intermediate = canonical.with_extension("case-probe");
        let alternate = canonical.with_extension("ROOT-CONFIG");
        std::fs::rename(&canonical, &intermediate).unwrap();
        std::fs::rename(&intermediate, &alternate).unwrap();
        assert!(store.load_root_config_inventory("default").is_err());
        drop(store);
        // Success-only cleanup of the exact newly-created fixture.
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "requires isolated ordinary Windows user and native private-storage ACL support"]
    fn profile_registry_replaces_reopens_and_preserves_other_storage() {
        let root = std::env::temp_dir().join(format!(
            "raiun-profile-registry-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        eprintln!("synthetic_profile_registry_root={}", root.display());
        // Direct fixture construction, never current_user() or real LOCALAPPDATA.
        let base = DpapiSessionStore {
            root: root.join("sessions"),
            profile_directory: None,
        };
        base.ensure_private_root().unwrap();
        let server = "https://synthetic.invalid";
        let client = "synthetic-client";
        let identity = identity_digest(Some("default"), server, client);
        let session_path = base.session_path(&identity);
        assert!(!session_path.exists());
        // Opaque sibling bytes only: exercise preservation without invoking DPAPI
        // or pretending these bytes constitute a decryptable session envelope.
        let temporary = base
            .write_temp(&session_path, b"synthetic opaque session sentinel")
            .unwrap();
        std::fs::rename(temporary, &session_path).unwrap();
        base.set_active_identity("default", server, client).unwrap();
        base.save_root_config("default", server, client, b"synthetic root metadata")
            .unwrap();
        let siblings = [
            session_path,
            base.active_pointer_path(),
            base.root_config_path(&identity),
        ];
        let before = siblings
            .iter()
            .map(|path| std::fs::read(path).unwrap())
            .collect::<Vec<_>>();
        assert!(base.load_profile_registry().unwrap().is_none());
        let first =
            br#"{"version":1,"selected":"default","profiles":{"default":{"label":"Default"}}}"#;
        let second = br#"{"version":1,"selected":"profile-11111111111111111111111111111111","profiles":{"default":{"label":"Default"},"profile-11111111111111111111111111111111":{"label":"Work"}}}"#;
        base.save_profile_registry(first).unwrap();
        assert_eq!(
            base.load_profile_registry().unwrap().as_deref(),
            Some(first.as_slice())
        );
        base.save_profile_registry(second).unwrap();
        assert_eq!(
            base.load_profile_registry().unwrap().as_deref(),
            Some(second.as_slice())
        );
        assert!(base.save_profile_registry(b"").is_err());
        assert!(base.save_profile_registry(&vec![b'x'; 1_048_577]).is_err());
        assert_eq!(
            base.load_profile_registry().unwrap().as_deref(),
            Some(second.as_slice())
        );
        let derived = base
            .for_profile("profile-11111111111111111111111111111111")
            .unwrap();
        assert!(derived.load_profile_registry().is_err());
        assert!(derived.save_profile_registry(first).is_err());
        assert_eq!(
            base.load_profile_registry().unwrap().as_deref(),
            Some(second.as_slice())
        );
        drop(derived);
        let store_root = base.root.clone();
        drop(base);
        let reopened = DpapiSessionStore {
            root: store_root,
            profile_directory: None,
        };
        assert_eq!(
            reopened.load_profile_registry().unwrap().as_deref(),
            Some(second.as_slice())
        );
        assert_eq!(
            reopened.active_identity().unwrap(),
            Some(("default".into(), server.into(), client.into()))
        );
        assert_eq!(
            reopened
                .load_root_config("default", server, client)
                .unwrap()
                .as_deref(),
            Some(b"synthetic root metadata".as_slice())
        );
        let after = siblings
            .iter()
            .map(|path| std::fs::read(path).unwrap())
            .collect::<Vec<_>>();
        assert!(
            before == after,
            "registry operations must preserve exact sibling bytes"
        );
        drop(reopened);
        // Only this CREATE_NEW fixture root is removed, after every assertion and
        // after dropping all private pins. Panic leaves the whole fixture intact.
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn profile_stores_preserve_default_and_separate_restore_pointers_and_bytes() {
        let root = std::env::temp_dir().join(format!(
            "raiun-profile-store-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        eprintln!("synthetic_profile_store_root={}", root.display());
        let base = DpapiSessionStore {
            root: root.join("sessions"),
            profile_directory: None,
        };
        base.ensure_private_root().unwrap();
        let a = "profile-00000000000000000000000000000000";
        let b = "profile-11111111111111111111111111111111";
        assert_eq!(base.for_profile("default").unwrap().root, base.root);
        for invalid in [
            "",
            "../other",
            "profile-other",
            "profile-0000000000000000000000000000000A",
        ] {
            assert!(base.for_profile(invalid).is_err());
        }
        let first = base.for_profile(a).unwrap();
        let second = base.for_profile(b).unwrap();
        assert!(first.for_profile("default").is_err());
        assert!(first.for_profile(b).is_err());
        first
            .save(
                Some(a),
                "https://synthetic.invalid",
                "client",
                b"first synthetic",
            )
            .unwrap();
        first
            .set_active_identity(a, "https://synthetic.invalid", "client")
            .unwrap();
        first
            .save_root_config(a, "https://synthetic.invalid", "client", b"{}")
            .unwrap();
        assert!(base.active_identity().unwrap().is_none());
        assert!(second.active_identity().unwrap().is_none());
        assert!(
            second
                .load(Some(a), "https://synthetic.invalid", "client")
                .unwrap()
                .is_none()
        );
        assert!(
            second
                .load_root_config(a, "https://synthetic.invalid", "client")
                .unwrap()
                .is_none()
        );
        second
            .save(
                Some(b),
                "https://synthetic.invalid",
                "client",
                b"second synthetic",
            )
            .unwrap();
        second
            .set_active_identity(b, "https://synthetic.invalid", "client")
            .unwrap();
        first.clear_active_identity().unwrap();
        assert_eq!(second.active_identity().unwrap().unwrap().0, b);
        assert!(first.active_identity().unwrap().is_none());
        assert_eq!(
            &*base
                .for_profile(a)
                .unwrap()
                .load(Some(a), "https://synthetic.invalid", "client")
                .unwrap()
                .unwrap(),
            b"first synthetic"
        );
        assert_eq!(
            &*second
                .load(Some(b), "https://synthetic.invalid", "client")
                .unwrap()
                .unwrap(),
            b"second synthetic"
        );
        drop((first, second, base));
        // Only the exact fresh synthetic scope is removed after full success.
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn identity_digest_does_not_disclose_server_or_client_labels() {
        let digest = hex(&identity_digest(
            Some("profile-7"),
            "https://cloud.example.test",
            "client-id",
        ));
        assert_eq!(digest.len(), 64);
        assert!(!digest.contains("cloud"));
        assert!(!digest.contains("client"));
    }

    #[test]
    fn session_identity_is_bounded_and_rejects_controls() {
        assert!(validate_identity(Some("profile"), "https://cloud.test", "client").is_ok());
        assert!(validate_identity(Some(""), "https://cloud.test", "client").is_err());
        assert!(validate_identity(None, "", "client").is_err());
        assert!(validate_identity(None, "https://cloud.test", &"x".repeat(4097)).is_err());
        assert!(validate_identity(None, &"x".repeat(4096), "client").is_ok());
    }

    #[test]
    fn session_bytes_are_bounded_to_agent_contract() {
        assert!(validate_session_size(65_536).is_ok());
        assert!(validate_session_size(MAX_SESSION_BYTES + 1).is_err());
        assert!(validate_ciphertext_size(MAX_CIPHERTEXT_BYTES).is_ok());
        assert!(validate_ciphertext_size(MAX_CIPHERTEXT_BYTES + 1).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_round_trips_a_full_sized_session_for_this_user() {
        let session = Zeroizing::new(vec![b's'; MAX_SESSION_BYTES]);
        let entropy = identity_digest(Some("test-profile"), "synthetic-server", "synthetic-client");
        let cipher = protect(&session, &entropy).expect("protect synthetic session");
        let restored = unprotect(&cipher, &entropy).expect("unprotect as same user");
        assert_eq!(&*restored, &*session);
        assert!(
            unprotect(
                &cipher,
                &identity_digest(Some("test-profile"), "other-server", "other-client")
            )
            .is_err()
        );
    }

    #[cfg(windows)]
    #[test]
    fn current_user_store_protects_nested_state_beyond_dos_path_limit() {
        let store = DpapiSessionStore::current_user().expect("private current-user store");
        let public_units = store.root.as_os_str().encode_wide().collect::<Vec<_>>();
        assert!(
            !public_units.starts_with(&[92, 92, 63, 92]),
            "public local disk root retains cache path policy"
        );
        let native_units = wide_path(&store.root).expect("encode private native path");
        assert!(
            native_units.starts_with(&[92, 92, 63, 92]),
            "native calls use extended-length syntax"
        );
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let mut path = store
            .root
            .join(format!("long-state-test-{}-{sequence}", std::process::id()));
        std::fs::create_dir(&path).expect("create unique synthetic state directory");
        store
            .protect_local_edit_directory(&path)
            .expect("protect test root");
        let mut depth = 0;
        while path.as_os_str().encode_wide().count() <= 320 {
            depth += 1;
            assert!(depth < 8, "bounded test depth");
            path = path.join("a".repeat(64));
            std::fs::create_dir(&path).expect("create long synthetic child");
            store
                .protect_local_edit_directory(&path)
                .expect("protect long state with exact current-user ACL");
            assert!(open_directory(&path).is_ok());
        }
        let associated = b"synthetic-long-path-record";
        let encrypted = store
            .protect_local_edit_record(associated, b"retained synthetic bytes")
            .unwrap();
        let file = path.join("record");
        std::fs::write(&file, &encrypted).unwrap();
        secure_existing_file(&file).expect("protect long-path record");
        let stored = std::fs::read(&file).unwrap();
        assert_eq!(
            &*store
                .unprotect_local_edit_record(associated, &stored)
                .unwrap(),
            b"retained synthetic bytes"
        );
        assert!(
            store
                .unprotect_local_edit_record(b"different-binding", &stored)
                .is_err()
        );
        // Keep this isolated synthetic state for native failure inspection.
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_round_trips_bounded_edit_record_with_exact_associated_data() {
        let store = DpapiSessionStore::current_user().expect("current-user DPAPI store");
        let associated_data = b"synthetic profile + origin + root + file + revision";
        let plaintext = Zeroizing::new(vec![0x5a; 1024 * 1024]);
        let encrypted = store
            .protect_local_edit_record(associated_data, &plaintext)
            .expect("protect one-megabyte local edit");
        let restored = store
            .unprotect_local_edit_record(associated_data, &encrypted)
            .expect("unprotect with exact binding");
        assert_eq!(&*restored, &*plaintext);
        assert!(
            store
                .unprotect_local_edit_record(b"different file identity", &encrypted)
                .is_err()
        );
    }

    #[cfg(windows)]
    #[test]
    fn private_store_round_trips_replaces_and_removes_session() {
        let store = DpapiSessionStore::current_user().expect("private current-user store");
        let profile = format!("synthetic-test-{}", std::process::id());
        let first = Zeroizing::new(vec![b'a'; MAX_SESSION_BYTES]);
        store
            .save(Some(&profile), "https://synthetic.test", "client", &first)
            .expect("save full-size session");
        assert!(
            store
                .load(
                    Some("different-profile"),
                    "https://synthetic.test",
                    "client"
                )
                .expect("profile-isolated lookup")
                .is_none()
        );
        assert_eq!(
            &*store
                .load(Some(&profile), "https://synthetic.test", "client")
                .expect("load")
                .expect("entry"),
            &*first
        );
        let replacement = Zeroizing::new(b"replacement session".to_vec());
        store
            .save(
                Some(&profile),
                "https://synthetic.test",
                "client",
                &replacement,
            )
            .expect("atomic replace");
        assert_eq!(
            &*store
                .load(Some(&profile), "https://synthetic.test", "client")
                .expect("reload")
                .expect("entry"),
            &*replacement
        );
        store
            .remove(Some(&profile), "https://synthetic.test", "client")
            .expect("remove exact entry");
        assert!(
            store
                .load(Some(&profile), "https://synthetic.test", "client")
                .expect("missing load")
                .is_none()
        );
    }

    #[cfg(windows)]
    #[test]
    fn private_store_round_trips_root_config_for_exact_session_identity() {
        let local = env::var_os("LOCALAPPDATA").expect("current-user local app data");
        let _base_store = DpapiSessionStore::current_user()
            .expect("initialize current-user private app directory");
        let isolated_root = PathBuf::from(local)
            .join("Raiun")
            .join(format!("root-config-test-{}", std::process::id()));
        let store = DpapiSessionStore {
            root: isolated_root.join("sessions"),
            profile_directory: None,
        };
        let config = br#"{"version":1,"root":"C:\\synthetic"}"#;
        store
            .save_root_config(
                "synthetic-profile",
                "https://synthetic.test",
                "client",
                config,
            )
            .expect("save bounded private configuration");
        assert_eq!(
            store
                .load_root_config("synthetic-profile", "https://synthetic.test", "client")
                .expect("load exact private configuration")
                .as_deref(),
            Some(config.as_slice())
        );
        assert!(
            store
                .load_root_config("other-profile", "https://synthetic.test", "client")
                .expect("profile isolation")
                .is_none()
        );
        assert!(
            store
                .load_root_config("synthetic-profile", "https://other.test", "client")
                .expect("server isolation")
                .is_none()
        );
        store
            .remove_root_config("synthetic-profile", "https://synthetic.test", "client")
            .expect("remove exact root configuration");
        assert!(
            store
                .load_root_config("synthetic-profile", "https://synthetic.test", "client")
                .expect("missing configuration")
                .is_none()
        );
        std::fs::remove_dir_all(isolated_root).expect("remove isolated private test store");
    }

    #[cfg(windows)]
    #[test]
    fn active_pointer_round_trips_exact_profile_server_and_client_then_revokes() {
        let local = env::var_os("LOCALAPPDATA").expect("current-user local app data");
        let isolated_root = PathBuf::from(local)
            .join("Raiun")
            .join(format!("pointer-test-{}", std::process::id()));
        let store = DpapiSessionStore {
            root: isolated_root.join("sessions"),
            profile_directory: None,
        };
        let profile = format!("synthetic-pointer-{}", std::process::id());
        store
            .set_active_identity(&profile, "https://synthetic.test", "synthetic-client")
            .expect("write the protected active pointer");
        let active = store
            .active_identity()
            .expect("read the protected pointer")
            .expect("active identity");
        assert_eq!(active.0, profile);
        assert_eq!(active.1, "https://synthetic.test");
        assert_eq!(active.2, "synthetic-client");
        store
            .clear_active_identity()
            .expect("revoke startup restoration");
        assert!(
            store
                .active_identity()
                .expect("read cleared pointer")
                .is_none()
        );
        store
            .remove(Some(&profile), "https://synthetic.test", "synthetic-client")
            .expect("remove exact synthetic session if present");
        std::fs::remove_dir_all(isolated_root).expect("remove isolated pointer test store");
    }
}
