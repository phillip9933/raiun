//! Current-user protected recovery provider for production Cloud Files roots.
//!
//! The scope catalog is immutable and append-only. It records every exact
//! account/Space/remote-root journal before that journal can be created, so a
//! restart can enumerate all prior scopes and reject orphaned or corrupt
//! state instead of silently presenting an empty recovery view.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[cfg(windows)]
use crate::DpapiEditRecordProtector;
use crate::{
    BackendError, ConfiguredRootIdentity, EditJournal, EditJournalScope, EditRecordProtector,
    EditRecoveryProvider, LocalEditMetadata, LocalEditRecord, PlaceholderEditBinding,
    PreparedEditRecovery, ProviderScope,
};
use crate::{ExplicitRecoveryApproval, ReconciliationOutcome, RecoveryRemote};

const CATALOG_DIRECTORY: &str = "cloud-files-edit-scopes-v1";
const CATALOG_SUFFIX: &str = ".scope";
const CATALOG_AAD_PREFIX: &[u8] = b"raiun/windows-edit-scope-catalog/v1\0";
const MAX_CATALOG_SCOPES: usize = 10_000;
const MAX_DISCOVERY_CATALOG_SCOPES: usize = 256;
const MAX_CATALOG_RECORD_BYTES: usize = 64 * 1024;
const IDENTITY_CATALOG_DIRECTORY: &str = "cloud-files-provider-identities-v1";
const IDENTITY_RECORD_SUFFIX: &str = ".binding";
const IDENTITY_CATALOG_AAD_PREFIX: &[u8] = b"raiun/windows-provider-identity-catalog/v1\0";
const MAX_IDENTITY_SCOPES: usize = 10_000;
const MAX_IDENTITY_FIELD_BYTES: usize = 4096;
const MAX_IDENTITY_PATH_BYTES: usize = 32 * 1024;
const MAX_IDENTITY_BINDINGS_PER_SCOPE: usize = 100_000;
const MAX_IDENTITY_RECORD_VERSIONS: usize = 1_024;
const MAX_IDENTITY_RECORD_BYTES: usize = 64 * 1024;
const MAX_IDENTITY_CATALOG_BYTES: u64 = 256 * 1024 * 1024;

static IDENTITY_CATALOG_LOCK: Mutex<()> = Mutex::new(());

/// Durable provider that binds recovered edits to one authenticated account
/// generation and one stable local Cloud Files root identity.
pub struct DurableEditRecoveryProvider {
    state_directory: PathBuf,
    scope: ProviderScope,
    root_identity: ConfiguredRootIdentity,
    protector: Arc<dyn EditRecordProtector>,
    catalog_lock: Arc<Mutex<()>>,
}

impl DurableEditRecoveryProvider {
    /// Create the production provider from a trusted per-user state directory
    /// and the exact scope/root captured by the agent before Cloud Files
    /// registration. On Windows prefer [`Self::current_user`].
    pub fn new(
        state_directory: PathBuf,
        scope: ProviderScope,
        root_identity: ConfiguredRootIdentity,
        protector: impl EditRecordProtector + 'static,
    ) -> Self {
        Self {
            state_directory,
            scope,
            root_identity,
            protector: Arc::new(protector),
            catalog_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Build the production provider using current-user DPAPI and Raiun's
    /// protected `%LOCALAPPDATA%` state directory.
    #[cfg(windows)]
    pub fn current_user(
        scope: ProviderScope,
        root_identity: ConfiguredRootIdentity,
    ) -> Result<Self, crate::JournalError> {
        let protector = DpapiEditRecordProtector::current_user()?;
        let state_directory = protector.local_state_directory().to_path_buf();
        Ok(Self::new(state_directory, scope, root_identity, protector))
    }

    fn catalog(&self) -> ScopeCatalog {
        ScopeCatalog {
            state_directory: self.state_directory.clone(),
            protector: Arc::clone(&self.protector),
            lock: Arc::clone(&self.catalog_lock),
        }
    }

    /// Enumerate retained edit metadata for this authenticated account and
    /// configured local root. Previous token generations remain visible as
    /// recovery evidence; callers must revalidate the remote baseline before
    /// offering any recovery action. Content bytes are never returned here.
    pub fn unresolved_edits(&self) -> Result<Vec<LocalEditMetadata>, BackendError> {
        if !valid_scope_binding(&self.scope, self.root_identity) {
            return Err(BackendError::Unavailable);
        }
        let catalog = self.catalog();
        catalog
            .preflight(&self.scope, self.root_identity)
            .and_then(|()| catalog.unresolved_edits(&self.scope, self.root_identity))
            .map_err(|_| BackendError::Unavailable)
    }

    /// Read-only discovery with an aggregate scan allowance. This authenticates
    /// catalog bindings and only this account/root's record bodies. Global
    /// startup preflight remains separate; no partial results escape on limits.
    pub fn unresolved_metadata_bounded(
        &self,
    ) -> Result<Vec<LocalEditMetadata>, crate::JournalError> {
        if !valid_scope_binding(&self.scope, self.root_identity) {
            return Err(crate::JournalError::InvalidScope);
        }
        self.catalog()
            .unresolved_metadata_bounded(&self.scope, self.root_identity)
    }

    /// Fail closed if a protected journal or incomplete staging record remains
    /// for this exact account/root, including state left by an earlier run.
    pub fn has_unresolved_edits(&self) -> Result<bool, BackendError> {
        if !valid_scope_binding(&self.scope, self.root_identity) {
            return Err(BackendError::Unavailable);
        }
        let catalog = self.catalog();
        catalog
            .preflight(&self.scope, self.root_identity)
            .and_then(|()| catalog.has_unresolved(&self.scope, self.root_identity))
            .map_err(|_| BackendError::Unavailable)
    }

    /// Return the current-user protected catalog used to resolve stable
    /// Cloud Files descendant IDs after restart. Its DPAPI purpose is separate
    /// from the edit-recovery journal; each entry remains bound to one exact
    /// account, Personal Space/root, and local root identity.
    pub fn identity_catalog(&self) -> Arc<dyn crate::opencloud::ProviderIdentityCatalog> {
        Arc::new(DurableProviderIdentityCatalog {
            state_directory: self.state_directory.clone(),
            protector: Arc::clone(&self.protector),
            owner_profile_id: self.scope.profile_id().to_owned(),
            owner_account_id: self.scope.account_id().to_owned(),
            owner_server_origin: self.scope.server_origin().to_owned(),
            owner_root_identity: self.root_identity,
        })
    }
}

impl crate::opencloud::ProviderIdentityCatalog for DurableProviderIdentityCatalog {
    fn load(
        &self,
        scope: &crate::opencloud::ProviderIdentityCatalogScope,
    ) -> Result<Vec<crate::opencloud::ProviderIdentityBinding>, BackendError> {
        let _guard = IDENTITY_CATALOG_LOCK
            .lock()
            .map_err(|_| BackendError::Unavailable)?;
        self.validate_owner_scope(scope)?;
        validate_identity_scope(scope).map_err(|_| BackendError::Unavailable)?;
        let scope_key = identity_scope_key(scope).map_err(|_| BackendError::Unavailable)?;
        let entries = self.load_all().map_err(|_| BackendError::Unavailable)?;
        let mut output = Vec::new();
        for entry in entries {
            if entry.scope == *scope
                && entry.scope_key == scope_key
                && let Some(binding) = entry.binding
            {
                output.push(binding);
            }
        }
        output.sort_by_key(|binding| *binding.identity().as_bytes());
        Ok(output)
    }

    fn upsert(
        &self,
        scope: &crate::opencloud::ProviderIdentityCatalogScope,
        binding: &crate::opencloud::ProviderIdentityBinding,
    ) -> Result<(), BackendError> {
        self.validate_owner_scope(scope)?;
        validate_identity_scope(scope).map_err(|_| BackendError::Unavailable)?;
        validate_identity_binding(scope, binding).map_err(|_| BackendError::Unavailable)?;
        let identity = *binding.identity().as_bytes();

        for _ in 0..MAX_IDENTITY_WRITE_RETRIES {
            let _guard = IDENTITY_CATALOG_LOCK
                .lock()
                .map_err(|_| BackendError::Unavailable)?;
            let entries = self.load_all().map_err(|_| BackendError::Unavailable)?;
            let existing_bytes = identity_catalog_bytes(&entries)?;
            let scope_key = identity_scope_key(scope).map_err(|_| BackendError::Unavailable)?;
            let existing = entries
                .iter()
                .find(|entry| entry.scope_key == scope_key && entry.identity == identity);
            let generation = if let Some(existing) = existing {
                if existing.scope != *scope {
                    return Err(BackendError::Unavailable);
                }
                let Some(current) = existing.binding.as_ref() else {
                    // Removed identities are tombstoned and may never be
                    // rebound to a different remote object.
                    return Err(BackendError::Unavailable);
                };
                if !same_identity_target(current, binding) {
                    return Err(BackendError::Unavailable);
                }
                if current == binding {
                    return Ok(());
                }
                existing
                    .generation
                    .checked_add(1)
                    .ok_or(BackendError::Unavailable)?
            } else {
                1
            };
            let record = ProtectedIdentityRecord {
                schema_version: 1,
                scope: scope.clone(),
                identity,
                generation,
                binding: Some(binding.clone()),
            };
            match self.append_record(&record, &scope_key, existing_bytes) {
                Ok(()) => return Ok(()),
                Err(IdentityAppendError::AlreadyExists) => continue,
                Err(IdentityAppendError::Failed) => return Err(BackendError::Unavailable),
            }
        }
        Err(BackendError::Unavailable)
    }

    fn remove(
        &self,
        scope: &crate::opencloud::ProviderIdentityCatalogScope,
        identity: crate::opencloud::OpaqueIdentity,
    ) -> Result<(), BackendError> {
        self.validate_owner_scope(scope)?;
        validate_identity_scope(scope).map_err(|_| BackendError::Unavailable)?;
        for _ in 0..MAX_IDENTITY_WRITE_RETRIES {
            let _guard = IDENTITY_CATALOG_LOCK
                .lock()
                .map_err(|_| BackendError::Unavailable)?;
            let entries = self.load_all().map_err(|_| BackendError::Unavailable)?;
            let existing_bytes = identity_catalog_bytes(&entries)?;
            let scope_key = identity_scope_key(scope).map_err(|_| BackendError::Unavailable)?;
            let Some(existing) = entries.iter().find(|entry| {
                entry.scope_key == scope_key && entry.identity == *identity.as_bytes()
            }) else {
                return Ok(());
            };
            if existing.scope != *scope {
                return Err(BackendError::Unavailable);
            }
            if existing.binding.is_none() {
                return Ok(());
            }
            let generation = existing
                .generation
                .checked_add(1)
                .ok_or(BackendError::Unavailable)?;
            let record = ProtectedIdentityRecord {
                schema_version: 1,
                scope: scope.clone(),
                identity: *identity.as_bytes(),
                generation,
                binding: None,
            };
            match self.append_record(&record, &scope_key, existing_bytes) {
                Ok(()) => return Ok(()),
                Err(IdentityAppendError::AlreadyExists) => continue,
                Err(IdentityAppendError::Failed) => return Err(BackendError::Unavailable),
            }
        }
        Err(BackendError::Unavailable)
    }
}

struct DurableProviderIdentityCatalog {
    state_directory: PathBuf,
    protector: Arc<dyn EditRecordProtector>,
    owner_profile_id: String,
    owner_account_id: String,
    owner_server_origin: String,
    owner_root_identity: ConfiguredRootIdentity,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedIdentityRecord {
    schema_version: u32,
    scope: crate::opencloud::ProviderIdentityCatalogScope,
    identity: [u8; 16],
    generation: u64,
    binding: Option<crate::opencloud::ProviderIdentityBinding>,
}

struct LoadedIdentityRecord {
    scope_key: String,
    scope: crate::opencloud::ProviderIdentityCatalogScope,
    identity: [u8; 16],
    generation: u64,
    binding: Option<crate::opencloud::ProviderIdentityBinding>,
    history_bytes: u64,
}

enum IdentityAppendError {
    AlreadyExists,
    Failed,
}

impl DurableProviderIdentityCatalog {
    fn validate_owner_scope(
        &self,
        scope: &crate::opencloud::ProviderIdentityCatalogScope,
    ) -> Result<(), BackendError> {
        if scope.profile_id() != self.owner_profile_id
            || scope.account_id() != self.owner_account_id
            || scope.server_origin() != self.owner_server_origin
            || scope.local_root() != self.owner_root_identity
        {
            return Err(BackendError::Unavailable);
        }
        Ok(())
    }

    fn directory(&self) -> PathBuf {
        self.state_directory.join(IDENTITY_CATALOG_DIRECTORY)
    }

    fn load_all(&self) -> Result<Vec<LoadedIdentityRecord>, crate::JournalError> {
        verify_identity_directory(&self.state_directory)?;
        let directory = self.directory();
        match fs::symlink_metadata(&directory) {
            Ok(_) => verify_identity_directory(&directory)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(crate::JournalError::Io),
        }
        let mut output = Vec::new();
        let mut scope_count = 0usize;
        let mut record_count = 0usize;
        let mut total_bytes = 0u64;
        for entry in fs::read_dir(&directory).map_err(|_| crate::JournalError::Io)? {
            scope_count = scope_count
                .checked_add(1)
                .ok_or(crate::JournalError::ScanLimit)?;
            if scope_count > MAX_IDENTITY_SCOPES {
                return Err(crate::JournalError::ScanLimit);
            }
            let entry = entry.map_err(|_| crate::JournalError::Io)?;
            let scope_key = entry
                .file_name()
                .into_string()
                .map_err(|_| crate::JournalError::CorruptRecord)?;
            if !valid_digest(&scope_key) {
                return Err(crate::JournalError::CorruptRecord);
            }
            let scope_directory = entry.path();
            verify_identity_directory(&scope_directory)?;
            let mut bindings_in_scope = 0usize;
            for identity_entry in
                fs::read_dir(&scope_directory).map_err(|_| crate::JournalError::Io)?
            {
                bindings_in_scope = bindings_in_scope
                    .checked_add(1)
                    .ok_or(crate::JournalError::ScanLimit)?;
                if bindings_in_scope > MAX_IDENTITY_BINDINGS_PER_SCOPE {
                    return Err(crate::JournalError::ScanLimit);
                }
                record_count = record_count
                    .checked_add(1)
                    .ok_or(crate::JournalError::ScanLimit)?;
                if record_count > MAX_IDENTITY_CATALOG_RECORDS {
                    return Err(crate::JournalError::ScanLimit);
                }
                let identity_entry = identity_entry.map_err(|_| crate::JournalError::Io)?;
                let identity_name = identity_entry
                    .file_name()
                    .into_string()
                    .map_err(|_| crate::JournalError::CorruptRecord)?;
                let identity = parse_identity_hex(&identity_name)?;
                let identity_directory = identity_entry.path();
                verify_identity_directory(&identity_directory)?;
                let loaded = self.read_identity_history(
                    &scope_key,
                    identity,
                    &identity_directory,
                    &mut record_count,
                    &mut total_bytes,
                )?;
                output.push(loaded);
            }
        }
        Ok(output)
    }

    fn read_identity_history(
        &self,
        expected_scope_key: &str,
        identity: [u8; 16],
        directory: &Path,
        total_records: &mut usize,
        total_bytes: &mut u64,
    ) -> Result<LoadedIdentityRecord, crate::JournalError> {
        let mut paths = Vec::new();
        for entry in fs::read_dir(directory).map_err(|_| crate::JournalError::Io)? {
            if paths.len() >= MAX_IDENTITY_RECORD_VERSIONS {
                return Err(crate::JournalError::ScanLimit);
            }
            let entry = entry.map_err(|_| crate::JournalError::Io)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| crate::JournalError::CorruptRecord)?;
            let generation = parse_identity_generation(&name)?;
            let metadata =
                fs::symlink_metadata(entry.path()).map_err(|_| crate::JournalError::Io)?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || has_reparse_attribute(&metadata)
            {
                return Err(crate::JournalError::CorruptRecord);
            }
            paths.push((generation, entry.path()));
        }
        if paths.is_empty() {
            return Err(crate::JournalError::CorruptRecord);
        }
        paths.sort_by_key(|(generation, _)| *generation);
        let mut expected_generation = 1u64;
        let mut scope: Option<crate::opencloud::ProviderIdentityCatalogScope> = None;
        let mut previous_binding: Option<crate::opencloud::ProviderIdentityBinding> = None;
        let mut removed = false;
        let mut history_bytes = 0u64;
        for (generation, path) in paths {
            *total_records = total_records
                .checked_add(1)
                .ok_or(crate::JournalError::ScanLimit)?;
            if *total_records > MAX_IDENTITY_CATALOG_RECORDS || generation != expected_generation {
                return Err(crate::JournalError::ScanLimit);
            }
            let sealed = read_private_catalog_file_bounded(&path, MAX_IDENTITY_RECORD_BYTES)?;
            let sealed_len =
                u64::try_from(sealed.len()).map_err(|_| crate::JournalError::ScanLimit)?;
            *total_bytes = total_bytes
                .checked_add(sealed_len)
                .ok_or(crate::JournalError::ScanLimit)?;
            history_bytes = history_bytes
                .checked_add(sealed_len)
                .ok_or(crate::JournalError::ScanLimit)?;
            if *total_bytes > MAX_IDENTITY_CATALOG_BYTES {
                return Err(crate::JournalError::ScanLimit);
            }
            let aad = identity_record_aad(expected_scope_key, identity, generation);
            let plain = Zeroizing::new(self.protector.open(&aad, &sealed)?);
            let record: ProtectedIdentityRecord =
                serde_json::from_slice(&plain).map_err(|_| crate::JournalError::CorruptRecord)?;
            if record.schema_version != 1
                || record.identity != identity
                || record.generation != generation
                || identity_scope_key(&record.scope)? != expected_scope_key
                || identity_is_zero(&record.identity)
            {
                return Err(crate::JournalError::ScopeMismatch);
            }
            validate_identity_scope(&record.scope)?;
            if scope
                .as_ref()
                .is_some_and(|existing| existing != &record.scope)
            {
                return Err(crate::JournalError::ScopeMismatch);
            }
            scope = Some(record.scope.clone());
            match &record.binding {
                Some(binding) => {
                    if removed || binding.identity().as_bytes() != &identity {
                        return Err(crate::JournalError::CorruptRecord);
                    }
                    validate_identity_binding(&record.scope, binding)?;
                    if previous_binding
                        .as_ref()
                        .is_some_and(|previous| !same_identity_target(previous, binding))
                    {
                        return Err(crate::JournalError::ScopeMismatch);
                    }
                    previous_binding = Some(binding.clone());
                }
                None => {
                    if previous_binding.is_none() || removed {
                        return Err(crate::JournalError::CorruptRecord);
                    }
                    removed = true;
                }
            }
            expected_generation = generation
                .checked_add(1)
                .ok_or(crate::JournalError::ScanLimit)?;
        }
        Ok(LoadedIdentityRecord {
            scope_key: expected_scope_key.to_owned(),
            scope: scope.ok_or(crate::JournalError::CorruptRecord)?,
            identity,
            generation: expected_generation - 1,
            binding: if removed { None } else { previous_binding },
            history_bytes,
        })
    }

    fn append_record(
        &self,
        record: &ProtectedIdentityRecord,
        scope_key: &str,
        existing_bytes: u64,
    ) -> Result<(), IdentityAppendError> {
        let body = serde_json::to_vec(record).map_err(|_| IdentityAppendError::Failed)?;
        if body.len() > MAX_IDENTITY_RECORD_BYTES {
            return Err(IdentityAppendError::Failed);
        }
        let aad = identity_record_aad(scope_key, record.identity, record.generation);
        let sealed = self
            .protector
            .seal(&aad, &body)
            .map_err(|_| IdentityAppendError::Failed)?;
        if sealed.is_empty() || sealed.len() > MAX_IDENTITY_RECORD_BYTES {
            return Err(IdentityAppendError::Failed);
        }
        let sealed_len = u64::try_from(sealed.len()).map_err(|_| IdentityAppendError::Failed)?;
        if existing_bytes > MAX_IDENTITY_CATALOG_BYTES.saturating_sub(sealed_len) {
            return Err(IdentityAppendError::Failed);
        }
        let root = self.directory();
        ensure_identity_directory(&self.state_directory, &root, self.protector.as_ref())?;
        let scope_directory = root.join(scope_key);
        ensure_identity_directory(&root, &scope_directory, self.protector.as_ref())?;
        let identity_name = identity_hex(&record.identity);
        let identity_directory = scope_directory.join(identity_name);
        ensure_identity_directory(
            &scope_directory,
            &identity_directory,
            self.protector.as_ref(),
        )?;
        let filename = format!("{:020}{IDENTITY_RECORD_SUFFIX}", record.generation);
        let path = identity_directory.join(filename);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    IdentityAppendError::AlreadyExists
                } else {
                    IdentityAppendError::Failed
                }
            })?;
        set_private_file(&file).map_err(|_| IdentityAppendError::Failed)?;
        file.write_all(&sealed)
            .map_err(|_| IdentityAppendError::Failed)?;
        file.sync_all().map_err(|_| IdentityAppendError::Failed)?;
        drop(file);
        sync_directory(&identity_directory).map_err(|_| IdentityAppendError::Failed)?;
        Ok(())
    }
}

const MAX_IDENTITY_WRITE_RETRIES: usize = 8;
const MAX_IDENTITY_CATALOG_RECORDS: usize = 200_000;

fn identity_catalog_bytes(entries: &[LoadedIdentityRecord]) -> Result<u64, BackendError> {
    entries
        .iter()
        .try_fold(0u64, |total, entry| total.checked_add(entry.history_bytes))
        .filter(|total| *total <= MAX_IDENTITY_CATALOG_BYTES)
        .ok_or(BackendError::Unavailable)
}

fn validate_identity_scope(
    scope: &crate::opencloud::ProviderIdentityCatalogScope,
) -> Result<(), crate::JournalError> {
    for value in [
        scope.profile_id(),
        scope.account_id(),
        scope.server_origin(),
        scope.personal_space_id(),
        scope.personal_root_resource_id(),
    ] {
        if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
            return Err(crate::JournalError::InvalidScope);
        }
    }
    if scope.local_root().file_index == 0 {
        return Err(crate::JournalError::InvalidScope);
    }
    Ok(())
}

fn validate_identity_binding(
    scope: &crate::opencloud::ProviderIdentityCatalogScope,
    binding: &crate::opencloud::ProviderIdentityBinding,
) -> Result<(), crate::JournalError> {
    if identity_is_zero(binding.identity().as_bytes()) {
        return Err(crate::JournalError::InvalidEdit);
    }
    let valid_text = |value: &str, max: usize| {
        !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
    };
    let valid_path = |path: &str, allow_root: bool| {
        path.len() <= MAX_IDENTITY_PATH_BYTES
            && path.starts_with('/')
            && (path == "/" && allow_root || path != "/" && !path.ends_with('/'))
            && !path.contains("//")
            && !path.contains('\\')
            && !path.chars().any(char::is_control)
            && !path
                .split('/')
                .any(|component| matches!(component, "." | ".."))
    };
    match binding {
        crate::opencloud::ProviderIdentityBinding::Directory {
            space_id,
            root_resource_id,
            path,
            remote_id,
            ..
        } => {
            if !valid_text(space_id, 512)
                || !valid_text(root_resource_id, MAX_IDENTITY_FIELD_BYTES)
                || !valid_path(path, true)
                || !valid_text(remote_id, MAX_IDENTITY_FIELD_BYTES)
            {
                return Err(crate::JournalError::InvalidEdit);
            }
        }
        crate::opencloud::ProviderIdentityBinding::File {
            space_id,
            root_resource_id,
            path,
            remote_id,
            etag,
            ..
        } => {
            if !valid_text(space_id, 512)
                || !valid_text(root_resource_id, MAX_IDENTITY_FIELD_BYTES)
                || !valid_path(path, false)
                || !valid_text(remote_id, MAX_IDENTITY_FIELD_BYTES)
                || !valid_text(etag, MAX_IDENTITY_FIELD_BYTES)
            {
                return Err(crate::JournalError::InvalidEdit);
            }
        }
        crate::opencloud::ProviderIdentityBinding::SpacesNamespace {
            personal_space_id,
            personal_root_resource_id,
            ..
        } => {
            if personal_space_id != scope.personal_space_id()
                || personal_root_resource_id != scope.personal_root_resource_id()
            {
                return Err(crate::JournalError::ScopeMismatch);
            }
        }
    }
    Ok(())
}

fn same_identity_target(
    left: &crate::opencloud::ProviderIdentityBinding,
    right: &crate::opencloud::ProviderIdentityBinding,
) -> bool {
    use crate::opencloud::ProviderIdentityBinding as Binding;
    match (left, right) {
        (
            Binding::Directory {
                identity: left_identity,
                space_id: left_space,
                root_resource_id: left_root,
                path: left_path,
                remote_id: left_remote,
            },
            Binding::Directory {
                identity: right_identity,
                space_id: right_space,
                root_resource_id: right_root,
                path: right_path,
                remote_id: right_remote,
            },
        ) => {
            left_identity == right_identity
                && left_space == right_space
                && left_root == right_root
                && left_path == right_path
                && left_remote == right_remote
        }
        (
            Binding::File {
                identity: left_identity,
                space_id: left_space,
                root_resource_id: left_root,
                path: left_path,
                remote_id: left_remote,
                ..
            },
            Binding::File {
                identity: right_identity,
                space_id: right_space,
                root_resource_id: right_root,
                path: right_path,
                remote_id: right_remote,
                ..
            },
        ) => {
            left_identity == right_identity
                && left_space == right_space
                && left_root == right_root
                && left_path == right_path
                && left_remote == right_remote
        }
        (
            Binding::SpacesNamespace {
                identity: left_identity,
                personal_space_id: left_space,
                personal_root_resource_id: left_root,
            },
            Binding::SpacesNamespace {
                identity: right_identity,
                personal_space_id: right_space,
                personal_root_resource_id: right_root,
            },
        ) => {
            left_identity == right_identity && left_space == right_space && left_root == right_root
        }
        _ => false,
    }
}

fn identity_scope_key(
    scope: &crate::opencloud::ProviderIdentityCatalogScope,
) -> Result<String, crate::JournalError> {
    let canonical = serde_json::to_vec(scope).map_err(|_| crate::JournalError::InvalidScope)?;
    if canonical.len() > MAX_CATALOG_RECORD_BYTES {
        return Err(crate::JournalError::LimitExceeded);
    }
    Ok(digest_hex(&canonical))
}

fn identity_record_aad(scope_key: &str, identity: [u8; 16], generation: u64) -> Vec<u8> {
    let mut output = IDENTITY_CATALOG_AAD_PREFIX.to_vec();
    output.extend_from_slice(scope_key.as_bytes());
    output.push(0);
    output.extend_from_slice(identity_hex(&identity).as_bytes());
    output.push(0);
    output.extend_from_slice(&generation.to_le_bytes());
    output
}

fn identity_hex(identity: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(32);
    for byte in identity {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn parse_identity_hex(value: &str) -> Result<[u8; 16], crate::JournalError> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(crate::JournalError::CorruptRecord);
    }
    let mut identity = [0u8; 16];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(chunk).map_err(|_| crate::JournalError::CorruptRecord)?;
        identity[index] =
            u8::from_str_radix(pair, 16).map_err(|_| crate::JournalError::CorruptRecord)?;
    }
    if identity_is_zero(&identity) {
        return Err(crate::JournalError::CorruptRecord);
    }
    Ok(identity)
}

fn parse_identity_generation(value: &str) -> Result<u64, crate::JournalError> {
    let digits = value
        .strip_suffix(IDENTITY_RECORD_SUFFIX)
        .ok_or(crate::JournalError::CorruptRecord)?;
    if digits.len() != 20 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(crate::JournalError::CorruptRecord);
    }
    let generation = digits
        .parse::<u64>()
        .map_err(|_| crate::JournalError::CorruptRecord)?;
    if generation == 0 || format!("{generation:020}{IDENTITY_RECORD_SUFFIX}") != value {
        return Err(crate::JournalError::CorruptRecord);
    }
    Ok(generation)
}

fn identity_is_zero(identity: &[u8; 16]) -> bool {
    identity.iter().all(|byte| *byte == 0)
}

fn ensure_identity_directory(
    parent: &Path,
    path: &Path,
    protector: &dyn EditRecordProtector,
) -> Result<(), IdentityAppendError> {
    verify_identity_directory(parent).map_err(|_| IdentityAppendError::Failed)?;
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(IdentityAppendError::Failed),
    }
    verify_identity_directory(path).map_err(|_| IdentityAppendError::Failed)?;
    protector
        .protect_directory(path)
        .map_err(|_| IdentityAppendError::Failed)?;
    verify_identity_directory(path).map_err(|_| IdentityAppendError::Failed)
}

fn verify_identity_directory(path: &Path) -> Result<(), crate::JournalError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| crate::JournalError::Io)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || has_reparse_attribute(&metadata) {
        return Err(crate::JournalError::CorruptRecord);
    }
    Ok(())
}

fn read_private_catalog_file_bounded(
    path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, crate::JournalError> {
    let bytes = read_private_catalog_file(path)?;
    if bytes.len() > max_bytes {
        return Err(crate::JournalError::LimitExceeded);
    }
    Ok(bytes)
}

impl EditRecoveryProvider for DurableEditRecoveryProvider {
    fn prepare(
        &self,
        provider_scope: &ProviderScope,
        root_identity: ConfiguredRootIdentity,
    ) -> Result<Arc<dyn PreparedEditRecovery>, BackendError> {
        if provider_scope != &self.scope || root_identity != self.root_identity {
            return Err(BackendError::Unavailable);
        }
        let catalog = self.catalog();
        catalog
            .preflight(&self.scope, self.root_identity)
            .map_err(|_| BackendError::Unavailable)?;
        Ok(Arc::new(DurablePreparedEditRecovery {
            scope: self.scope.clone(),
            root_identity: self.root_identity,
            catalog,
            receipt_owner: Arc::new(()),
        }))
    }

    fn identity_catalog(&self) -> Option<Arc<dyn crate::opencloud::ProviderIdentityCatalog>> {
        Some(DurableEditRecoveryProvider::identity_catalog(self))
    }
}

/// Single-use, in-memory authority for the exact snapshot just published by
/// one prepared recovery instance. It cannot be cloned, constructed externally,
/// serialized, or recovered by scanning a journal. Dropping it loses only the
/// initial-dispatch opportunity; the protected edit remains available.
pub struct InitialEditReceipt {
    owner: Arc<()>,
    metadata: LocalEditMetadata,
}

impl InitialEditReceipt {
    #[cfg(any(windows, test))]
    pub(crate) fn record_key(&self) -> (&str, u64) {
        (&self.metadata.record_id, self.metadata.generation)
    }

    #[cfg(any(windows, test))]
    pub(crate) fn local_file(&self) -> crate::LocalFileIdentity {
        self.metadata.local_file
    }

    #[cfg(any(windows, test))]
    pub(crate) fn owner(&self) -> &Arc<()> {
        &self.owner
    }

    /// Trusted routing context for constructing the current generation-checked
    /// remote adapter. This is account metadata and must not be logged.
    pub fn scope(&self) -> &EditJournalScope {
        &self.metadata.scope
    }
}

/// Opaque evidence minted only by the guarded native completion path after
/// the OS accepts its nonzero-USN comparison. Not a remote-only receipt.
pub struct CompletedLocalEdit {
    metadata: LocalEditMetadata,
}

impl CompletedLocalEdit {
    #[cfg(any(windows, test))]
    pub(crate) fn from_native_completion(metadata: &LocalEditMetadata) -> Self {
        Self {
            metadata: metadata.clone(),
        }
    }
}

struct DurablePreparedEditRecovery {
    scope: ProviderScope,
    root_identity: ConfiguredRootIdentity,
    catalog: ScopeCatalog,
    receipt_owner: Arc<()>,
}

impl PreparedEditRecovery for DurablePreparedEditRecovery {
    fn provider_scope(&self) -> &ProviderScope {
        &self.scope
    }

    fn root_identity(&self) -> ConfiguredRootIdentity {
        self.root_identity
    }

    fn append_edit(
        &self,
        binding: &PlaceholderEditBinding,
        root_identity: ConfiguredRootIdentity,
        local_file: crate::LocalFileIdentity,
        relative_path: &str,
        content: &[u8],
    ) -> Result<(), BackendError> {
        self.append_edit_for_initial_dispatch(
            binding,
            root_identity,
            local_file,
            relative_path,
            content,
        )?;
        Ok(())
    }

    fn append_edit_for_initial_dispatch(
        &self,
        binding: &PlaceholderEditBinding,
        root_identity: ConfiguredRootIdentity,
        local_file: crate::LocalFileIdentity,
        relative_path: &str,
        content: &[u8],
    ) -> Result<Option<InitialEditReceipt>, BackendError> {
        if root_identity != self.root_identity
            || binding.profile_id != self.scope.profile_id()
            || binding.server_origin != self.scope.server_origin()
            || binding.account_subject != self.scope.account_id()
            || binding.account_generation != self.scope.token_generation()
        {
            return Err(BackendError::Unavailable);
        }
        let journal_scope = EditJournalScope {
            profile_id: binding.profile_id.clone(),
            server_origin: binding.server_origin.clone(),
            account_subject: binding.account_subject.clone(),
            space_id: binding.space_id.clone(),
            root_resource_id: binding.root_resource_id.clone(),
            root_volume_serial: root_identity.volume_serial,
            root_file_index: root_identity.file_index,
        };
        self.catalog
            .register_scope(&journal_scope)
            .map_err(|_| BackendError::Unavailable)?;
        let journal = self
            .catalog
            .open_journal(&journal_scope)
            .map_err(|_| BackendError::Unavailable)?;
        let metadata = journal
            .append_edit(
                binding.account_generation,
                local_file,
                relative_path,
                Some(crate::RemoteEditBaseline {
                    resource_id: binding.remote_resource_id.clone(),
                    etag: binding.base_etag.clone(),
                    byte_len: binding.base_size,
                }),
                content,
            )
            .map_err(|_| BackendError::Unavailable)?;
        Ok(Some(InitialEditReceipt {
            owner: Arc::clone(&self.receipt_owner),
            metadata,
        }))
    }

    fn dispatch_initial_receipt(
        &self,
        receipt: InitialEditReceipt,
        remote: &dyn RecoveryRemote,
    ) -> Result<ReconciliationOutcome, crate::JournalError> {
        if !Arc::ptr_eq(&receipt.owner, &self.receipt_owner)
            || receipt.metadata.generation != self.scope.token_generation()
            || !scope_matches_provider(&receipt.metadata.scope, &self.scope, self.root_identity)
        {
            return Err(crate::JournalError::ScopeMismatch);
        }
        let metadata = receipt.metadata;
        let journal = self.catalog.journal_for_record(
            &self.scope,
            self.root_identity,
            &metadata.record_id,
            metadata.generation,
        )?;
        let snapshot = journal.recover_all()?;
        if journal.scope() != &metadata.scope
            || !snapshot
                .records
                .iter()
                .any(|record| record.metadata == metadata)
        {
            return Err(crate::JournalError::ScopeMismatch);
        }
        drop(snapshot);
        crate::recovery_reconcile::dispatch_initial_edit(
            &journal,
            &metadata.record_id,
            metadata.generation,
            &metadata.scope,
            remote,
        )
    }

    fn dispatch_initial_receipt_verified(
        &self,
        receipt: InitialEditReceipt,
        remote: &dyn RecoveryRemote,
    ) -> Result<(ReconciliationOutcome, Option<crate::VerifiedEditReadback>), crate::JournalError>
    {
        // The ordinary dispatch consumes and validates this instance's fresh
        // capability before any upload. Keep only its immutable metadata for
        // joining a new readback to that same protected record afterward.
        let metadata = receipt.metadata.clone();
        let outcome = self.dispatch_initial_receipt(receipt, remote)?;
        if !matches!(outcome, ReconciliationOutcome::VerifiedApplied { .. }) {
            return Ok((outcome, None));
        }
        let journal = self.catalog.journal_for_record(
            &self.scope,
            self.root_identity,
            &metadata.record_id,
            metadata.generation,
        )?;
        if journal.scope() != &metadata.scope {
            return Err(crate::JournalError::ScopeMismatch);
        }
        let record = journal
            .recover_all()?
            .records
            .into_iter()
            .find(|record| record.metadata == metadata)
            .ok_or(crate::JournalError::ScopeMismatch)?;
        match crate::verify_edit_readback(&record, &metadata.scope, remote) {
            Ok(proof) => Ok((outcome, Some(proof))),
            // No proof means no acknowledgement authority. Preserve the
            // original encrypted body and report the fresh verification result.
            Err(outcome) => Ok((outcome, None)),
        }
    }

    fn record_local_completion(
        &self,
        completion: CompletedLocalEdit,
    ) -> Result<(), crate::JournalError> {
        let metadata = completion.metadata;
        if metadata.generation != self.scope.token_generation()
            || !scope_matches_provider(&metadata.scope, &self.scope, self.root_identity)
        {
            return Err(crate::JournalError::ScopeMismatch);
        }
        let journal = self.catalog.journal_for_record(
            &self.scope,
            self.root_identity,
            &metadata.record_id,
            metadata.generation,
        )?;
        let lease = journal.acquire_dispatch_lease(&metadata.record_id)?;
        journal.acknowledge_local_completion(&lease, &metadata)
    }

    fn has_unresolved(&self) -> Result<bool, BackendError> {
        self.catalog
            .has_unresolved(&self.scope, self.root_identity)
            .map_err(|_| BackendError::Unavailable)
    }

    fn dispatch_recovered_edit(
        &self,
        record_id: &str,
        generation: u64,
        remote: &dyn RecoveryRemote,
        approval: ExplicitRecoveryApproval,
    ) -> Result<ReconciliationOutcome, crate::JournalError> {
        if !valid_scope_binding(&self.scope, self.root_identity)
            || record_id.is_empty()
            || record_id.len() > 128
            || !record_id.bytes().all(|byte| byte.is_ascii_hexdigit())
            || generation == 0
        {
            return Err(crate::JournalError::ScopeMismatch);
        }
        let journal = self.catalog.journal_for_record(
            &self.scope,
            self.root_identity,
            record_id,
            generation,
        )?;
        let expected_scope = journal.scope().clone();
        crate::recovery_reconcile::dispatch_recovered_edit(
            &journal,
            record_id,
            generation,
            &expected_scope,
            remote,
            approval,
        )
    }
}

#[derive(Clone)]
struct ScopeCatalog {
    state_directory: PathBuf,
    protector: Arc<dyn EditRecordProtector>,
    lock: Arc<Mutex<()>>,
}

impl ScopeCatalog {
    fn directory(&self) -> PathBuf {
        self.state_directory.join(CATALOG_DIRECTORY)
    }

    fn preflight(
        &self,
        current_scope: &ProviderScope,
        root_identity: ConfiguredRootIdentity,
    ) -> Result<(), crate::JournalError> {
        let _guard = self.lock.lock().map_err(|_| crate::JournalError::Io)?;
        self.ensure_directory()?;
        // Check that current-user protection is functional before Cloud Files
        // registration, even when this root has no prior edit scopes.
        let challenge = b"raiun-edit-recovery-preflight-v1";
        let aad = root_aad(root_identity);
        let sealed = self.protector.seal(&aad, challenge)?;
        let opened = Zeroizing::new(self.protector.open(&aad, &sealed)?);
        if opened.as_slice() != challenge {
            return Err(crate::JournalError::ProtectionFailed);
        }
        self.probe_writable()?;

        let scopes = self.enumerate_scopes()?;
        self.verify_journal_directory_set(&scopes)?;
        for scope in scopes {
            let journal = self.open_existing_journal(&scope)?;
            let snapshot = journal.recover_all()?;
            // Recovering all scopes verifies DPAPI, associated data, record
            // bounds, and authenticated metadata before callbacks can run.
            drop_records(snapshot.records);
            let _ = snapshot.incomplete_staging_files;
        }
        // Use of this exact scope is checked independently of the catalog;
        // callers cannot substitute a stale account or root lease.
        if !valid_scope_binding(current_scope, root_identity) {
            return Err(crate::JournalError::InvalidScope);
        }
        Ok(())
    }

    fn unresolved_metadata_bounded(
        &self,
        provider_scope: &ProviderScope,
        root_identity: ConfiguredRootIdentity,
    ) -> Result<Vec<LocalEditMetadata>, crate::JournalError> {
        let _guard = self.lock.lock().map_err(|_| crate::JournalError::Io)?;
        let mut budget = crate::edit_journal::MetadataScanBudget::default();
        let scopes = self.enumerate_scopes_bounded(Some(&mut budget))?;
        self.verify_journal_directory_set(&scopes)?;
        // An authenticated catalog entry whose directory disappeared is not
        // evidence of an empty journal. Never recreate it during discovery.
        for scope in &scopes {
            let path = EditJournal::storage_root(&self.state_directory)
                .join(EditJournal::scope_directory_key(scope)?);
            verify_directory(&path)?;
        }
        let mut metadata = Vec::new();
        for scope in scopes
            .into_iter()
            .filter(|scope| scope_matches_provider(scope, provider_scope, root_identity))
        {
            let journal = EditJournal::open_existing(
                &self.state_directory,
                scope,
                SharedProtector(Arc::clone(&self.protector)),
            )?;
            metadata.extend(journal.recover_metadata_bounded(&mut budget)?);
        }
        Ok(metadata)
    }

    fn unresolved_edits(
        &self,
        provider_scope: &ProviderScope,
        root_identity: ConfiguredRootIdentity,
    ) -> Result<Vec<LocalEditMetadata>, crate::JournalError> {
        let _guard = self.lock.lock().map_err(|_| crate::JournalError::Io)?;
        let scopes = self.enumerate_scopes()?;
        self.verify_journal_directory_set(&scopes)?;
        let mut metadata = Vec::new();
        for scope in scopes
            .into_iter()
            .filter(|scope| scope_matches_provider(scope, provider_scope, root_identity))
        {
            let journal = self.open_existing_journal(&scope)?;
            let snapshot = journal.recover_all()?;
            for record in &snapshot.records {
                if snapshot.is_unresolved(record) {
                    metadata.push(record.metadata.clone());
                }
            }
        }
        Ok(metadata)
    }

    fn has_unresolved(
        &self,
        provider_scope: &ProviderScope,
        root_identity: ConfiguredRootIdentity,
    ) -> Result<bool, crate::JournalError> {
        let _guard = self.lock.lock().map_err(|_| crate::JournalError::Io)?;
        let scopes = self.enumerate_scopes()?;
        self.verify_journal_directory_set(&scopes)?;
        for scope in scopes
            .into_iter()
            .filter(|scope| scope_matches_provider(scope, provider_scope, root_identity))
        {
            let journal = self.open_existing_journal(&scope)?;
            let snapshot = journal.recover_all()?;
            if snapshot.incomplete_staging_files != 0
                || snapshot
                    .records
                    .iter()
                    .any(|record| snapshot.is_unresolved(record))
            {
                drop_records(snapshot.records);
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn journal_for_record(
        &self,
        provider_scope: &ProviderScope,
        root_identity: ConfiguredRootIdentity,
        record_id: &str,
        generation: u64,
    ) -> Result<EditJournal, crate::JournalError> {
        let _guard = crate::edit_journal::trace_journal_stage(
            "provider_journal_catalog_lock",
            self.lock.lock().map_err(|_| crate::JournalError::Io),
        )?;
        if !valid_scope_binding(provider_scope, root_identity)
            || record_id.is_empty()
            || record_id.len() > 128
            || !record_id.bytes().all(|byte| byte.is_ascii_hexdigit())
            || generation == 0
        {
            return Err(crate::JournalError::InvalidEdit);
        }
        let scopes = crate::edit_journal::trace_journal_stage(
            "provider_journal_enumerate_scopes",
            self.enumerate_scopes(),
        )?;
        crate::edit_journal::trace_journal_stage(
            "provider_journal_verify_directory_set",
            self.verify_journal_directory_set(&scopes),
        )?;
        let mut found: Option<EditJournal> = None;
        for scope in scopes
            .into_iter()
            .filter(|scope| scope_matches_provider(scope, provider_scope, root_identity))
        {
            let journal = crate::edit_journal::trace_journal_stage(
                "provider_journal_open_scope",
                self.open_existing_journal(&scope),
            )?;
            let snapshot = crate::edit_journal::trace_journal_stage(
                "provider_journal_recover_scope",
                journal.recover_all(),
            )?;
            let matching_id = snapshot
                .records
                .iter()
                .any(|record| record.metadata.record_id == record_id);
            let exact_record = snapshot.records.iter().any(|record| {
                record.metadata.record_id == record_id && record.metadata.generation == generation
            });
            drop_records(snapshot.records);
            if matching_id {
                if !exact_record || found.is_some() {
                    return Err(crate::JournalError::ScopeMismatch);
                }
                found = Some(journal);
            }
        }
        found.ok_or(crate::JournalError::ScopeMismatch)
    }

    fn register_scope(&self, scope: &EditJournalScope) -> Result<(), crate::JournalError> {
        let _guard = self.lock.lock().map_err(|_| crate::JournalError::Io)?;
        self.ensure_directory()?;
        let scopes = self.enumerate_scopes()?;
        self.verify_journal_directory_set(&scopes)?;
        let key = EditJournal::scope_directory_key(scope)?;
        if scopes.iter().any(|existing| {
            EditJournal::scope_directory_key(existing).is_ok_and(|existing_key| existing_key == key)
        }) {
            return Ok(());
        }
        if scopes.len() >= MAX_CATALOG_SCOPES {
            return Err(crate::JournalError::ScanLimit);
        }
        let body = serde_json::to_vec(&scope).map_err(|_| crate::JournalError::InvalidScope)?;
        if body.len() > MAX_CATALOG_RECORD_BYTES {
            return Err(crate::JournalError::LimitExceeded);
        }
        let aad = catalog_aad(&key);
        let sealed = self.protector.seal(&aad, &body)?;
        if sealed.is_empty() || sealed.len() > MAX_CATALOG_RECORD_BYTES {
            return Err(crate::JournalError::LimitExceeded);
        }
        match self.create_new_catalog_record(&key, &sealed) {
            Ok(()) => {}
            Err(crate::JournalError::ScopeMismatch) => {
                // Another provider instance may register the same immutable
                // scope concurrently. Re-open and validate it before reuse.
                let scopes = self.enumerate_scopes()?;
                if !scopes.iter().any(|existing| existing == scope) {
                    return Err(crate::JournalError::ScopeMismatch);
                }
            }
            Err(error) => return Err(error),
        }
        Ok(())
    }

    fn enumerate_scopes(&self) -> Result<Vec<EditJournalScope>, crate::JournalError> {
        self.enumerate_scopes_bounded(None)
    }

    fn enumerate_scopes_bounded(
        &self,
        mut budget: Option<&mut crate::edit_journal::MetadataScanBudget>,
    ) -> Result<Vec<EditJournalScope>, crate::JournalError> {
        let directory = self.directory();
        if budget.is_some()
            && matches!(fs::symlink_metadata(&directory), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
        {
            verify_directory(&self.state_directory)?;
            let journal_root = EditJournal::storage_root(&self.state_directory);
            match fs::read_dir(&journal_root) {
                Ok(mut entries) => {
                    verify_directory(&journal_root)?;
                    if entries.next().is_some() {
                        return Err(crate::JournalError::CorruptRecord);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(crate::JournalError::Io),
            }
            return Ok(Vec::new());
        }
        verify_directory(&directory)?;
        let mut result = Vec::new();
        for (index, entry) in fs::read_dir(&directory)
            .map_err(|_| crate::JournalError::Io)?
            .enumerate()
        {
            if index >= MAX_CATALOG_SCOPES {
                return Err(crate::JournalError::ScanLimit);
            }
            if let Some(budget) = budget.as_deref_mut() {
                if index >= MAX_DISCOVERY_CATALOG_SCOPES {
                    return Err(crate::JournalError::ScanLimit);
                }
                // Charge the full permitted read, not a racing path stat.
                budget.charge_read((MAX_CATALOG_RECORD_BYTES + 1) as u64)?;
                budget.entries = budget
                    .entries
                    .checked_sub(1)
                    .ok_or(crate::JournalError::ScanLimit)?;
            }
            let entry = entry.map_err(|_| crate::JournalError::Io)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| crate::JournalError::CorruptRecord)?;
            let key = name
                .strip_suffix(CATALOG_SUFFIX)
                .ok_or(crate::JournalError::CorruptRecord)?;
            if !valid_digest(key) {
                return Err(crate::JournalError::CorruptRecord);
            }
            let path = directory.join(&name);
            let sealed = read_private_catalog_file(&path)?;
            let aad = catalog_aad(key);
            let plain = Zeroizing::new(self.protector.open(&aad, &sealed)?);
            let scope: EditJournalScope =
                serde_json::from_slice(&plain).map_err(|_| crate::JournalError::CorruptRecord)?;
            let canonical =
                serde_json::to_vec(&scope).map_err(|_| crate::JournalError::CorruptRecord)?;
            if canonical.len() > MAX_CATALOG_RECORD_BYTES || digest_hex(&canonical) != key {
                return Err(crate::JournalError::ScopeMismatch);
            }
            validate_catalog_scope(&scope)?;
            result.push(scope);
        }
        result.sort_by_key(|scope| EditJournal::scope_directory_key(scope).unwrap_or_default());
        Ok(result)
    }

    fn verify_journal_directory_set(
        &self,
        scopes: &[EditJournalScope],
    ) -> Result<(), crate::JournalError> {
        let directory = EditJournal::storage_root(&self.state_directory);
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(crate::JournalError::Io),
        };
        let expected: std::collections::HashSet<String> = scopes
            .iter()
            .map(EditJournal::scope_directory_key)
            .collect::<Result<_, _>>()?;
        for entry in entries {
            let entry = entry.map_err(|_| crate::JournalError::Io)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| crate::JournalError::CorruptRecord)?;
            let metadata =
                fs::symlink_metadata(entry.path()).map_err(|_| crate::JournalError::Io)?;
            if !expected.contains(&name)
                || !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || has_reparse_attribute(&metadata)
            {
                return Err(crate::JournalError::CorruptRecord);
            }
        }
        Ok(())
    }

    fn open_existing_journal(
        &self,
        scope: &EditJournalScope,
    ) -> Result<EditJournal, crate::JournalError> {
        EditJournal::open_existing(
            &self.state_directory,
            scope.clone(),
            SharedProtector(Arc::clone(&self.protector)),
        )
    }

    fn open_journal(&self, scope: &EditJournalScope) -> Result<EditJournal, crate::JournalError> {
        EditJournal::open(
            &self.state_directory,
            scope.clone(),
            SharedProtector(Arc::clone(&self.protector)),
        )
    }

    fn ensure_directory(&self) -> Result<(), crate::JournalError> {
        let directory = self.directory();
        match fs::create_dir(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(crate::JournalError::Io),
        }
        let metadata = fs::symlink_metadata(&directory).map_err(|_| crate::JournalError::Io)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || has_reparse_attribute(&metadata)
        {
            return Err(crate::JournalError::Io);
        }
        self.protector.protect_directory(&directory)?;
        verify_directory(&directory)?;
        Ok(())
    }

    fn probe_writable(&self) -> Result<(), crate::JournalError> {
        let path = self
            .directory()
            .join(format!(".probe-{}", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|_| crate::JournalError::Io)?;
        set_private_file(&file)?;
        file.write_all(b"recovery-provider-preflight")
            .map_err(|_| crate::JournalError::Io)?;
        file.sync_all().map_err(|_| crate::JournalError::Io)?;
        drop(file);
        fs::remove_file(&path).map_err(|_| crate::JournalError::Io)?;
        sync_directory(&self.directory())
    }

    fn create_new_catalog_record(
        &self,
        key: &str,
        sealed: &[u8],
    ) -> Result<(), crate::JournalError> {
        let path = self.directory().join(format!("{key}{CATALOG_SUFFIX}"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    crate::JournalError::ScopeMismatch
                } else {
                    crate::JournalError::Io
                }
            })?;
        set_private_file(&file)?;
        file.write_all(sealed)
            .map_err(|_| crate::JournalError::Io)?;
        file.sync_all().map_err(|_| crate::JournalError::Io)?;
        drop(file);
        sync_directory(&self.directory())
    }
}

#[derive(Clone)]
struct SharedProtector(Arc<dyn EditRecordProtector>);

impl EditRecordProtector for SharedProtector {
    fn seal(
        &self,
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, crate::JournalError> {
        self.0.seal(associated_data, plaintext)
    }

    fn open(&self, associated_data: &[u8], sealed: &[u8]) -> Result<Vec<u8>, crate::JournalError> {
        self.0.open(associated_data, sealed)
    }

    fn protect_directory(&self, path: &Path) -> Result<(), crate::JournalError> {
        self.0.protect_directory(path)
    }
}

fn validate_catalog_scope(scope: &EditJournalScope) -> Result<(), crate::JournalError> {
    // EditJournal::open applies its full scope validation before a scope is
    // used. Here reject malformed values before deriving any storage path.
    for value in [
        &scope.profile_id,
        &scope.server_origin,
        &scope.account_subject,
        &scope.space_id,
        &scope.root_resource_id,
    ] {
        if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
            return Err(crate::JournalError::InvalidScope);
        }
    }
    Ok(())
}

fn valid_scope_binding(scope: &ProviderScope, root: ConfiguredRootIdentity) -> bool {
    !scope.profile_id().is_empty()
        && !scope.server_origin().is_empty()
        && !scope.account_id().is_empty()
        && scope.token_generation() != 0
        && root.file_index != 0
}

fn scope_matches_provider(
    scope: &EditJournalScope,
    provider_scope: &ProviderScope,
    root_identity: ConfiguredRootIdentity,
) -> bool {
    scope.profile_id == provider_scope.profile_id()
        && scope.server_origin == provider_scope.server_origin()
        && scope.account_subject == provider_scope.account_id()
        && scope_root_identity(scope) == root_identity
}

fn scope_root_identity(scope: &EditJournalScope) -> ConfiguredRootIdentity {
    ConfiguredRootIdentity {
        volume_serial: scope.root_volume_serial,
        file_index: scope.root_file_index,
    }
}

fn root_aad(root: ConfiguredRootIdentity) -> Vec<u8> {
    let mut bytes = b"raiun/windows-edit-recovery-root/v1\0".to_vec();
    bytes.extend_from_slice(&root.volume_serial.to_le_bytes());
    bytes.extend_from_slice(&root.file_index.to_le_bytes());
    bytes
}

fn catalog_aad(digest: &str) -> Vec<u8> {
    // The exact scope, including account, Space, remote root, and local-root
    // identity, is authenticated inside the protected payload and is also
    // hashed into the immutable catalog filename.
    let mut bytes = CATALOG_AAD_PREFIX.to_vec();
    bytes.extend_from_slice(digest.as_bytes());
    bytes
}

fn digest_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in Sha256::digest(bytes) {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn read_private_catalog_file(path: &Path) -> Result<Vec<u8>, crate::JournalError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| crate::JournalError::Io)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || has_reparse_attribute(&metadata)
    {
        return Err(crate::JournalError::CorruptRecord);
    }
    if metadata.len() == 0 || metadata.len() > MAX_CATALOG_RECORD_BYTES as u64 {
        return Err(crate::JournalError::LimitExceeded);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path).map_err(|_| crate::JournalError::Io)?;
    let opened = file.metadata().map_err(|_| crate::JournalError::Io)?;
    if !opened.is_file() || has_reparse_attribute(&opened) || opened.len() != metadata.len() {
        return Err(crate::JournalError::CorruptRecord);
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take((MAX_CATALOG_RECORD_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| crate::JournalError::Io)?;
    if bytes.len() > MAX_CATALOG_RECORD_BYTES {
        return Err(crate::JournalError::LimitExceeded);
    }
    Ok(bytes)
}

fn has_reparse_attribute(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        let _ = metadata;
        false
    }
}

fn verify_directory(path: &Path) -> Result<(), crate::JournalError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| crate::JournalError::Io)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || has_reparse_attribute(&metadata) {
        return Err(crate::JournalError::Io);
    }
    Ok(())
}

fn set_private_file(file: &File) -> Result<(), crate::JournalError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| crate::JournalError::Io)?;
    }
    #[cfg(not(unix))]
    let _ = file;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), crate::JournalError> {
    #[cfg(unix)]
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| crate::JournalError::Io)?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn drop_records(records: Vec<LocalEditRecord>) {
    drop(records);
}

#[cfg(test)]
mod tests {
    use super::*;
    use raiun_core::backend::CloudBackend;
    use raiun_opencloud::OpenCloudClient;

    #[derive(Clone)]
    struct TestProtector;

    impl EditRecordProtector for TestProtector {
        fn seal(
            &self,
            associated_data: &[u8],
            plaintext: &[u8],
        ) -> Result<Vec<u8>, crate::JournalError> {
            let mut output = Vec::with_capacity(associated_data.len() + plaintext.len() + 4);
            output.extend_from_slice(&(associated_data.len() as u32).to_le_bytes());
            output.extend_from_slice(associated_data);
            output.extend_from_slice(plaintext);
            Ok(output)
        }

        fn open(
            &self,
            associated_data: &[u8],
            sealed: &[u8],
        ) -> Result<Vec<u8>, crate::JournalError> {
            if sealed.len() < 4 {
                return Err(crate::JournalError::ProtectionFailed);
            }
            let length = u32::from_le_bytes(sealed[..4].try_into().unwrap()) as usize;
            if sealed.get(4..4 + length) != Some(associated_data) {
                return Err(crate::JournalError::ProtectionFailed);
            }
            Ok(sealed[4 + length..].to_vec())
        }
    }

    fn private_tempdir() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        temp
    }

    fn fixture() -> (ProviderScope, ConfiguredRootIdentity) {
        let client = OpenCloudClient::new("https://example.test", "fixture".into()).unwrap();
        let scope = ProviderScope::new(
            &client,
            "default".into(),
            "account-fixture".into(),
            client.server_origin().unwrap(),
        )
        .unwrap();
        (
            scope,
            ConfiguredRootIdentity {
                volume_serial: 17,
                file_index: 29,
            },
        )
    }

    fn identity_catalog_scope(
        scope: &ProviderScope,
        root: ConfiguredRootIdentity,
    ) -> crate::opencloud::ProviderIdentityCatalogScope {
        crate::opencloud::ProviderIdentityCatalogScope::new(scope, root, "personal", "root-1")
            .unwrap()
    }

    fn identity_binding(etag: &str, size: u64) -> crate::opencloud::ProviderIdentityBinding {
        crate::opencloud::ProviderIdentityBinding::File {
            identity: [3; 16],
            space_id: "personal".into(),
            root_resource_id: "root-1".into(),
            path: "/notes.txt".into(),
            remote_id: "file-1".into(),
            etag: etag.into(),
            size,
        }
    }

    #[test]
    fn identity_catalog_allows_exact_personal_root_path_only() {
        use crate::opencloud::ProviderIdentityBinding;

        let (provider_scope, root) = fixture();
        let scope = identity_catalog_scope(&provider_scope, root);
        let personal_root = ProviderIdentityBinding::Directory {
            identity: [4; 16],
            space_id: "personal".into(),
            root_resource_id: "root-1".into(),
            path: "/".into(),
            remote_id: "root-1".into(),
        };
        assert!(validate_identity_binding(&scope, &personal_root).is_ok());

        let trailing_slash_child = ProviderIdentityBinding::Directory {
            identity: [5; 16],
            space_id: "personal".into(),
            root_resource_id: "root-1".into(),
            path: "/nested/".into(),
            remote_id: "nested-1".into(),
        };
        assert!(validate_identity_binding(&scope, &trailing_slash_child).is_err());
    }

    #[test]
    fn provider_identity_catalog_survives_restart_refreshes_metadata_and_tombstones() {
        let temp = private_tempdir();
        let (scope, root) = fixture();
        let catalog_scope = identity_catalog_scope(&scope, root);
        let provider = DurableEditRecoveryProvider::new(
            temp.path().to_path_buf(),
            scope.clone(),
            root,
            TestProtector,
        );
        let catalog = provider.identity_catalog();
        let original = identity_binding("etag-a", 5);
        catalog.upsert(&catalog_scope, &original).unwrap();
        assert_eq!(
            catalog.load(&catalog_scope).unwrap(),
            vec![original.clone()]
        );
        drop(catalog);
        drop(provider);

        let restarted =
            DurableEditRecoveryProvider::new(temp.path().to_path_buf(), scope, root, TestProtector);
        let catalog = restarted.identity_catalog();
        assert_eq!(
            catalog.load(&catalog_scope).unwrap(),
            vec![original.clone()]
        );

        let refreshed = identity_binding("etag-b", 9);
        catalog.upsert(&catalog_scope, &refreshed).unwrap();
        assert_eq!(
            catalog.load(&catalog_scope).unwrap(),
            vec![refreshed.clone()]
        );

        let retargeted = crate::opencloud::ProviderIdentityBinding::File {
            identity: [3; 16],
            space_id: "personal".into(),
            root_resource_id: "root-1".into(),
            path: "/other.txt".into(),
            remote_id: "file-1".into(),
            etag: "etag-c".into(),
            size: 11,
        };
        assert!(catalog.upsert(&catalog_scope, &retargeted).is_err());
        let identity = refreshed.identity();
        catalog.remove(&catalog_scope, identity).unwrap();
        assert!(catalog.load(&catalog_scope).unwrap().is_empty());
        assert!(catalog.upsert(&catalog_scope, &refreshed).is_err());
    }

    #[test]
    fn provider_identity_catalog_is_exactly_scoped_and_fails_closed_on_corruption() {
        let temp = private_tempdir();
        let (scope, root) = fixture();
        let provider = DurableEditRecoveryProvider::new(
            temp.path().to_path_buf(),
            scope.clone(),
            root,
            TestProtector,
        );
        let catalog = provider.identity_catalog();
        let exact_scope = identity_catalog_scope(&scope, root);
        catalog
            .upsert(&exact_scope, &identity_binding("etag-a", 5))
            .unwrap();

        let other_account_client =
            OpenCloudClient::new("https://example.test", "fixture".into()).unwrap();
        let other_account = ProviderScope::new(
            &other_account_client,
            "default".into(),
            "different-account".into(),
            other_account_client.server_origin().unwrap(),
        )
        .unwrap();
        let other_scope = identity_catalog_scope(&other_account, root);
        assert!(catalog.load(&other_scope).is_err());
        let other_provider = DurableEditRecoveryProvider::new(
            temp.path().to_path_buf(),
            other_account,
            root,
            TestProtector,
        );
        assert!(
            other_provider
                .identity_catalog()
                .load(&other_scope)
                .unwrap()
                .is_empty()
        );

        let scope_key = identity_scope_key(&exact_scope).unwrap();
        let identity_dir = temp
            .path()
            .join(IDENTITY_CATALOG_DIRECTORY)
            .join(scope_key)
            .join(identity_hex(&[3; 16]));
        fs::write(
            identity_dir.join(format!("{:020}{IDENTITY_RECORD_SUFFIX}", 1)),
            b"corrupt",
        )
        .unwrap();
        assert!(catalog.load(&exact_scope).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn provider_identity_catalog_rejects_a_symlinked_state_root() {
        use std::os::unix::fs::symlink;

        let temp = private_tempdir();
        let real_state = temp.path().join("real-state");
        let linked_state = temp.path().join("linked-state");
        fs::create_dir(&real_state).unwrap();
        symlink(&real_state, &linked_state).unwrap();
        let (scope, root) = fixture();
        let catalog_scope = identity_catalog_scope(&scope, root);
        let provider = DurableEditRecoveryProvider::new(linked_state, scope, root, TestProtector);
        assert!(provider.identity_catalog().load(&catalog_scope).is_err());
    }

    #[test]
    fn catalog_byte_budget_rejects_append_before_creating_empty_identity_directories() {
        let temp = private_tempdir();
        let (provider_scope, root) = fixture();
        let scope = identity_catalog_scope(&provider_scope, root);
        let binding = identity_binding("etag-a", 5);
        let scope_key = identity_scope_key(&scope).unwrap();
        let catalog = DurableProviderIdentityCatalog {
            state_directory: temp.path().to_path_buf(),
            protector: Arc::new(TestProtector),
            owner_profile_id: provider_scope.profile_id().to_owned(),
            owner_account_id: provider_scope.account_id().to_owned(),
            owner_server_origin: provider_scope.server_origin().to_owned(),
            owner_root_identity: root,
        };
        let record = ProtectedIdentityRecord {
            schema_version: 1,
            scope,
            identity: *binding.identity().as_bytes(),
            generation: 1,
            binding: Some(binding),
        };

        assert!(matches!(
            catalog.append_record(&record, &scope_key, MAX_IDENTITY_CATALOG_BYTES),
            Err(IdentityAppendError::Failed)
        ));
        assert!(!temp.path().join(IDENTITY_CATALOG_DIRECTORY).exists());
    }

    #[test]
    fn identity_history_version_scan_stops_at_its_bound() {
        let temp = private_tempdir();
        let (scope, root) = fixture();
        let catalog_scope = identity_catalog_scope(&scope, root);
        let scope_key = identity_scope_key(&catalog_scope).unwrap();
        let identity = [3; 16];
        let identity_directory = temp
            .path()
            .join(IDENTITY_CATALOG_DIRECTORY)
            .join(scope_key)
            .join(identity_hex(&identity));
        fs::create_dir_all(&identity_directory).unwrap();
        for generation in 1..=MAX_IDENTITY_RECORD_VERSIONS + 1 {
            File::create(
                identity_directory.join(format!("{generation:020}{IDENTITY_RECORD_SUFFIX}")),
            )
            .unwrap();
        }

        let provider =
            DurableEditRecoveryProvider::new(temp.path().to_path_buf(), scope, root, TestProtector);
        assert!(provider.identity_catalog().load(&catalog_scope).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn current_user_dpapi_identity_catalog_survives_provider_restart() {
        let protector = DpapiEditRecordProtector::current_user().unwrap();
        // The production protector intentionally applies DACLs only below
        // its trusted LocalAppData root. Keep this isolated test directory
        // inside that root rather than weakening the production containment
        // check to accommodate a generic system temp directory.
        let temp = tempfile::Builder::new()
            .prefix("raiun-identity-catalog-test-")
            .tempdir_in(protector.local_state_directory())
            .unwrap();
        let (scope, root) = fixture();
        let catalog_scope = identity_catalog_scope(&scope, root);
        let binding = identity_binding("etag-dpapi", 12);
        {
            let provider = DurableEditRecoveryProvider::new(
                temp.path().to_path_buf(),
                scope.clone(),
                root,
                protector,
            );
            provider
                .identity_catalog()
                .upsert(&catalog_scope, &binding)
                .unwrap();
        }

        let protector = DpapiEditRecordProtector::current_user().unwrap();
        let restarted =
            DurableEditRecoveryProvider::new(temp.path().to_path_buf(), scope, root, protector);
        assert!(
            restarted
                .identity_catalog()
                .load(&catalog_scope)
                .is_ok_and(|bindings| bindings == vec![binding])
        );
    }

    fn binding(scope: &ProviderScope) -> PlaceholderEditBinding {
        PlaceholderEditBinding {
            profile_id: scope.profile_id().into(),
            server_origin: scope.server_origin().into(),
            account_subject: scope.account_id().into(),
            account_generation: scope.token_generation(),
            space_id: "personal".into(),
            root_resource_id: "root-1".into(),
            remote_resource_id: "file-1".into(),
            virtual_path: "/notes.txt".into(),
            base_etag: "\"v1\"".into(),
            base_size: 5,
        }
    }

    struct ReceiptRemote {
        expected: Vec<u8>,
        calls: Mutex<Vec<&'static str>>,
        authorized: bool,
    }

    impl ReceiptRemote {
        fn new(expected: &[u8]) -> Self {
            Self {
                expected: expected.to_vec(),
                calls: Mutex::new(Vec::new()),
                authorized: true,
            }
        }

        fn version(&self, updated: bool) -> crate::RecoveryRemoteVersion {
            crate::RecoveryRemoteVersion {
                resource_id: "file-1".into(),
                etag: if updated { "\"v2\"" } else { "\"v1\"" }.into(),
                size: if updated {
                    self.expected.len() as u64
                } else {
                    5
                },
                is_directory: false,
                encrypted: false,
                writable: true,
            }
        }
    }

    impl RecoveryRemote for ReceiptRemote {
        fn server_origin(&self) -> Option<&str> {
            Some("https://example.test")
        }
        fn ensure_authorized(
            &self,
            _: &EditJournalScope,
        ) -> Result<(), raiun_core::backend::CloudError> {
            if self.authorized {
                Ok(())
            } else {
                Err(raiun_core::backend::CloudError::new(
                    raiun_core::backend::ErrorKind::Unauthorized,
                    "synthetic generation revoked",
                ))
            }
        }
        fn stat(
            &self,
            _: &EditJournalScope,
            path: &str,
        ) -> Result<crate::RecoveryRemoteVersion, raiun_core::backend::CloudError> {
            assert_eq!(path, "notes.txt");
            self.calls.lock().unwrap().push("stat");
            Ok(self.version(false))
        }
        fn conditional_upload(
            &self,
            _: &EditJournalScope,
            path: &str,
            content: &[u8],
            id: &str,
            condition: raiun_core::backend::WriteCondition,
            size: u64,
        ) -> Result<crate::RecoveryRemoteVersion, raiun_core::backend::CloudError> {
            assert_eq!(path, "notes.txt");
            assert_eq!(id, "file-1");
            assert_eq!(content, self.expected);
            assert_eq!(
                condition,
                raiun_core::backend::WriteCondition::Match("\"v1\"".into())
            );
            assert_eq!(size, 5);
            self.calls.lock().unwrap().push("upload");
            Ok(self.version(true))
        }
        fn readback(
            &self,
            _: &EditJournalScope,
            _: &str,
            id: &str,
            etag: Option<&str>,
            _: usize,
        ) -> Result<crate::RecoveryRemoteBody, raiun_core::backend::CloudError> {
            assert_eq!(id, "file-1");
            assert_eq!(etag, Some("\"v2\""));
            self.calls.lock().unwrap().push("readback");
            Ok(crate::RecoveryRemoteBody::new(
                self.version(true),
                self.expected.clone(),
            ))
        }
    }

    fn append_receipt(prepared: &dyn PreparedEditRecovery, content: &[u8]) -> InitialEditReceipt {
        let root = prepared.root_identity();
        prepared
            .append_edit_for_initial_dispatch(
                &binding(prepared.provider_scope()),
                root,
                crate::LocalFileIdentity {
                    volume_serial: root.volume_serial,
                    file_index: 55,
                },
                "notes.txt",
                content,
            )
            .unwrap()
            .unwrap()
    }

    #[test]
    fn initial_receipt_selects_exact_append_and_cannot_replay_a_completed_attempt() {
        let temp = private_tempdir();
        let (scope, root) = fixture();
        let provider = DurableEditRecoveryProvider::new(
            temp.path().into(),
            scope.clone(),
            root,
            TestProtector,
        );
        let prepared = provider.prepare(&scope, root).unwrap();
        let first = append_receipt(prepared.as_ref(), b"first");
        let metadata = first.metadata.clone();
        // A forged duplicate is possible only inside this private test module.
        let duplicate = InitialEditReceipt {
            owner: Arc::clone(&first.owner),
            metadata: metadata.clone(),
        };
        let second = append_receipt(prepared.as_ref(), b"second edit");
        assert_ne!(metadata.record_id, second.metadata.record_id);
        let remote = ReceiptRemote::new(b"first");
        assert_eq!(
            prepared.dispatch_initial_receipt(first, &remote).unwrap(),
            ReconciliationOutcome::VerifiedApplied { attempts: 1 }
        );
        let before = remote.calls.lock().unwrap().clone();
        assert!(matches!(
            prepared.dispatch_initial_receipt(duplicate, &remote),
            Err(crate::JournalError::InvalidState)
        ));
        assert_eq!(*remote.calls.lock().unwrap(), before);
        let journal = provider.catalog().open_journal(&metadata.scope).unwrap();
        let saved = journal.recover_all().unwrap();
        assert_eq!(saved.records.len(), 2);
        assert!(
            saved
                .records
                .iter()
                .any(|r| r.metadata == metadata && r.content == b"first")
        );
        assert!(
            saved
                .records
                .iter()
                .any(|r| r.metadata == second.metadata && r.content == b"second edit")
        );
    }

    #[test]
    fn initial_receipt_is_bound_to_prepared_instance_and_lost_on_reopen() {
        let temp = private_tempdir();
        let (scope, root) = fixture();
        let provider = DurableEditRecoveryProvider::new(
            temp.path().into(),
            scope.clone(),
            root,
            TestProtector,
        );
        let prepared = provider.prepare(&scope, root).unwrap();
        let receipt = append_receipt(prepared.as_ref(), b"first");
        let metadata = receipt.metadata.clone();
        drop(prepared);
        drop(provider);
        let reopened = DurableEditRecoveryProvider::new(
            temp.path().into(),
            scope.clone(),
            root,
            TestProtector,
        );
        let next = reopened.prepare(&scope, root).unwrap();
        let remote = ReceiptRemote::new(b"first");
        assert!(matches!(
            next.dispatch_initial_receipt(receipt, &remote),
            Err(crate::JournalError::ScopeMismatch)
        ));
        assert!(remote.calls.lock().unwrap().is_empty());
        let saved = reopened
            .catalog()
            .open_journal(&metadata.scope)
            .unwrap()
            .recover_all()
            .unwrap();
        assert_eq!(saved.records[0].content, b"first");
        assert!(!saved.recovery_states.contains_key(&metadata.record_id));
    }

    #[test]
    fn initial_receipt_rejects_changed_binding_metadata_before_remote_access() {
        let temp = private_tempdir();
        let (scope, root) = fixture();
        let provider = DurableEditRecoveryProvider::new(
            temp.path().into(),
            scope.clone(),
            root,
            TestProtector,
        );
        let prepared = provider.prepare(&scope, root).unwrap();
        for field in 0..10 {
            let mut receipt = append_receipt(prepared.as_ref(), b"first");
            match field {
                0 => receipt.metadata.scope.profile_id.push('x'),
                1 => receipt.metadata.scope.server_origin.push('x'),
                2 => receipt.metadata.scope.account_subject.push('x'),
                3 => receipt.metadata.scope.space_id.push('x'),
                4 => receipt.metadata.scope.root_resource_id.push('x'),
                5 => receipt.metadata.scope.root_volume_serial += 1,
                6 => receipt.metadata.scope.root_file_index += 1,
                7 => receipt.metadata.generation += 1,
                8 => receipt.metadata.content_sha256.push('x'),
                _ => receipt
                    .metadata
                    .remote
                    .as_mut()
                    .unwrap()
                    .resource_id
                    .push('x'),
            }
            let remote = ReceiptRemote::new(b"first");
            assert!(matches!(
                prepared.dispatch_initial_receipt(receipt, &remote),
                Err(crate::JournalError::ScopeMismatch)
            ));
            assert!(remote.calls.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn initial_receipt_default_preserves_without_authority_and_failed_append_mints_nothing() {
        struct PreserveOnly {
            scope: ProviderScope,
            root: ConfiguredRootIdentity,
            bodies: Mutex<Vec<Vec<u8>>>,
        }
        impl PreparedEditRecovery for PreserveOnly {
            fn provider_scope(&self) -> &ProviderScope {
                &self.scope
            }
            fn root_identity(&self) -> ConfiguredRootIdentity {
                self.root
            }
            fn append_edit(
                &self,
                _: &PlaceholderEditBinding,
                _: ConfiguredRootIdentity,
                _: crate::LocalFileIdentity,
                _: &str,
                content: &[u8],
            ) -> Result<(), BackendError> {
                self.bodies.lock().unwrap().push(content.to_vec());
                Ok(())
            }
            fn has_unresolved(&self) -> Result<bool, BackendError> {
                Ok(true)
            }
        }
        let temp = private_tempdir();
        let (scope, root) = fixture();
        let fixture = PreserveOnly {
            scope: scope.clone(),
            root,
            bodies: Mutex::new(Vec::new()),
        };
        assert!(
            fixture
                .append_edit_for_initial_dispatch(
                    &binding(&scope),
                    root,
                    crate::LocalFileIdentity {
                        volume_serial: root.volume_serial,
                        file_index: 55
                    },
                    "notes.txt",
                    b"saved"
                )
                .unwrap()
                .is_none()
        );
        assert_eq!(*fixture.bodies.lock().unwrap(), [b"saved".to_vec()]);
        let provider = DurableEditRecoveryProvider::new(
            temp.path().into(),
            scope.clone(),
            root,
            TestProtector,
        );
        let prepared = provider.prepare(&scope, root).unwrap();
        assert!(
            prepared
                .append_edit_for_initial_dispatch(
                    &binding(&scope),
                    root,
                    crate::LocalFileIdentity {
                        volume_serial: root.volume_serial,
                        file_index: 55
                    },
                    "../escape",
                    b"rejected"
                )
                .is_err()
        );
        assert!(provider.unresolved_metadata_bounded().unwrap().is_empty());
        let receipt = append_receipt(prepared.as_ref(), b"first");
        let remote = ReceiptRemote::new(b"first");
        assert!(matches!(
            fixture.dispatch_initial_receipt(receipt, &remote),
            Err(crate::JournalError::InvalidState)
        ));
        assert!(remote.calls.lock().unwrap().is_empty());
        assert_eq!(provider.unresolved_metadata_bounded().unwrap().len(), 1);
    }

    #[test]
    fn initial_receipt_revoked_generation_never_uploads_and_preserves_body() {
        let temp = private_tempdir();
        let (scope, root) = fixture();
        let provider = DurableEditRecoveryProvider::new(
            temp.path().into(),
            scope.clone(),
            root,
            TestProtector,
        );
        let prepared = provider.prepare(&scope, root).unwrap();
        let receipt = append_receipt(prepared.as_ref(), b"first");
        let metadata = receipt.metadata.clone();
        let mut remote = ReceiptRemote::new(b"first");
        remote.authorized = false;
        assert_eq!(
            prepared.dispatch_initial_receipt(receipt, &remote).unwrap(),
            ReconciliationOutcome::Deferred
        );
        assert!(remote.calls.lock().unwrap().is_empty());
        let saved = provider
            .catalog()
            .open_journal(&metadata.scope)
            .unwrap()
            .recover_all()
            .unwrap();
        assert_eq!(saved.records[0].content, b"first");
        assert_eq!(
            saved.recovery_states[&metadata.record_id],
            crate::RecoveryAttemptState::Deferred {
                attempt_id: 0,
                attempts: 0
            }
        );
    }

    #[test]
    fn bounded_discovery_is_read_only_and_refuses_missing_or_corrupt_selected_evidence() {
        let temp = private_tempdir();
        let (scope, root) = fixture();
        let provider = DurableEditRecoveryProvider::new(
            temp.path().to_path_buf(),
            scope.clone(),
            root,
            TestProtector,
        );
        assert!(provider.unresolved_metadata_bounded().unwrap().is_empty());
        assert!(fs::read_dir(temp.path()).unwrap().next().is_none());
        let prepared = provider.prepare(&scope, root).unwrap();
        prepared
            .append_edit(
                &binding(&scope),
                root,
                crate::LocalFileIdentity {
                    volume_serial: root.volume_serial,
                    file_index: 55,
                },
                "notes.txt",
                b"local",
            )
            .unwrap();
        let catalog = provider.catalog();
        let selected = catalog.enumerate_scopes().unwrap().pop().unwrap();
        let item = catalog
            .open_journal(&selected)
            .unwrap()
            .recover_all()
            .unwrap()
            .records[0]
            .metadata
            .clone();
        let path = EditJournal::storage_root(temp.path())
            .join(EditJournal::scope_directory_key(&selected).unwrap());
        let edit = path.join(format!("{}.edit", item.record_id));
        let before = fs::read(&edit).unwrap();
        assert_eq!(
            provider.unresolved_metadata_bounded().unwrap(),
            vec![item.clone()]
        );
        assert_eq!(fs::read(&edit).unwrap(), before);
        let catalog_path = catalog.directory();
        let retained_catalog = temp.path().join("retained-missing-catalog");
        fs::rename(&catalog_path, &retained_catalog).unwrap();
        assert!(provider.unresolved_metadata_bounded().is_err());
        assert!(!catalog_path.exists());
        assert_eq!(fs::read(&edit).unwrap(), before);
        fs::rename(&retained_catalog, &catalog_path).unwrap();
        let moved = temp.path().join("retained-missing-journal");
        fs::rename(&path, &moved).unwrap();
        assert!(provider.unresolved_metadata_bounded().is_err());
        assert!(provider.prepare(&scope, root).is_err());
        assert!(provider.unresolved_edits().is_err());
        assert!(provider.has_unresolved_edits().is_err());
        assert!(
            catalog
                .journal_for_record(&scope, root, &item.record_id, item.generation)
                .is_err()
        );
        assert!(!path.exists());
        assert_eq!(
            fs::read(moved.join(edit.file_name().unwrap())).unwrap(),
            before
        );
        fs::rename(&moved, &path).unwrap();
        fs::write(&edit, b"corrupt retained synthetic evidence").unwrap();
        assert!(provider.unresolved_metadata_bounded().is_err());
        assert_eq!(
            fs::read(&edit).unwrap(),
            b"corrupt retained synthetic evidence"
        );
    }

    #[test]
    fn catalog_only_scope_is_not_silently_recreated_by_preflight_or_listing() {
        let temp = private_tempdir();
        let (scope, root) = fixture();
        let provider = DurableEditRecoveryProvider::new(
            temp.path().to_path_buf(),
            scope.clone(),
            root,
            TestProtector,
        );
        let prepared = provider.prepare(&scope, root).unwrap();
        let entry = EditJournalScope {
            profile_id: scope.profile_id().into(),
            server_origin: scope.server_origin().into(),
            account_subject: scope.account_id().into(),
            space_id: "personal".into(),
            root_resource_id: "root-1".into(),
            root_volume_serial: root.volume_serial,
            root_file_index: root.file_index,
        };
        let catalog = provider.catalog();
        catalog.register_scope(&entry).unwrap();
        let path = EditJournal::storage_root(temp.path())
            .join(EditJournal::scope_directory_key(&entry).unwrap());
        assert!(provider.prepare(&scope, root).is_err());
        assert!(provider.unresolved_metadata_bounded().is_err());
        assert!(provider.unresolved_edits().is_err());
        assert!(!path.exists());
        // Only the explicit append path may finish creation. A scan racing
        // registration refuses temporarily rather than fabricating emptiness.
        prepared
            .append_edit(
                &binding(&scope),
                root,
                crate::LocalFileIdentity {
                    volume_serial: root.volume_serial,
                    file_index: 55,
                },
                "notes.txt",
                b"retained after registration",
            )
            .unwrap();
        provider.prepare(&scope, root).unwrap();
        let records = provider.unresolved_metadata_bounded().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].content_len, 27);
    }

    #[test]
    fn bounded_discovery_catalog_limit_is_aggregate_and_does_not_open_foreign_bodies() {
        let temp = private_tempdir();
        let (scope, root) = fixture();
        let provider = DurableEditRecoveryProvider::new(
            temp.path().to_path_buf(),
            scope.clone(),
            root,
            TestProtector,
        );
        provider.prepare(&scope, root).unwrap();
        let catalog = provider.catalog();
        let foreign = EditJournalScope {
            profile_id: scope.profile_id().into(),
            server_origin: scope.server_origin().into(),
            account_subject: "foreign-account".into(),
            space_id: "foreign-space".into(),
            root_resource_id: "foreign-root".into(),
            root_volume_serial: root.volume_serial,
            root_file_index: root.file_index,
        };
        for index in 0..MAX_DISCOVERY_CATALOG_SCOPES {
            let mut entry = foreign.clone();
            entry.space_id = format!("foreign-{index}");
            catalog.register_scope(&entry).unwrap();
            let journal = catalog.open_journal(&entry).unwrap();
            if index == 0 {
                let item = journal
                    .append_edit(
                        1,
                        crate::LocalFileIdentity {
                            volume_serial: root.volume_serial,
                            file_index: 55,
                        },
                        "foreign.txt",
                        None,
                        b"foreign",
                    )
                    .unwrap();
                let path = EditJournal::storage_root(temp.path())
                    .join(EditJournal::scope_directory_key(&entry).unwrap())
                    .join(format!("{}.edit", item.record_id));
                fs::write(
                    path,
                    b"invalid foreign body must not be decrypted by selected listing",
                )
                .unwrap();
            }
        }
        assert!(provider.unresolved_metadata_bounded().unwrap().is_empty());
        let mut overflow = foreign;
        overflow.space_id = "one-over".into();
        catalog.register_scope(&overflow).unwrap();
        assert_eq!(
            provider.unresolved_metadata_bounded(),
            Err(crate::JournalError::ScanLimit)
        );
    }

    #[test]
    fn protected_scope_catalog_discovers_unresolved_edits_after_restart() {
        let temp = private_tempdir();
        let (scope, root) = fixture();
        let provider = DurableEditRecoveryProvider::new(
            temp.path().to_path_buf(),
            scope.clone(),
            root,
            TestProtector,
        );
        let prepared = provider.prepare(&scope, root).unwrap();
        prepared
            .append_edit(
                &binding(&scope),
                root,
                crate::LocalFileIdentity {
                    volume_serial: root.volume_serial,
                    file_index: 55,
                },
                "notes.txt",
                b"local",
            )
            .unwrap();
        assert!(prepared.has_unresolved().unwrap());
        drop(prepared);
        drop(provider);

        let restarted = DurableEditRecoveryProvider::new(
            temp.path().to_path_buf(),
            scope.clone(),
            root,
            TestProtector,
        );
        let reopened = restarted.prepare(&scope, root).unwrap();
        let records = restarted.unresolved_edits().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].relative_path, "notes.txt");
        assert_eq!(records[0].content_len, 5);
        assert!(reopened.has_unresolved().unwrap());
    }

    #[test]
    fn journal_append_failure_stage_is_not_hidden_by_provider_error_mapping() {
        let temp = private_tempdir();
        let (scope, root) = fixture();
        let provider = DurableEditRecoveryProvider::new(
            temp.path().to_path_buf(),
            scope.clone(),
            root,
            TestProtector,
        );
        provider.prepare(&scope, root).unwrap();
        let binding = binding(&scope);
        let journal_scope = EditJournalScope {
            profile_id: binding.profile_id.clone(),
            server_origin: binding.server_origin.clone(),
            account_subject: binding.account_subject.clone(),
            space_id: binding.space_id.clone(),
            root_resource_id: binding.root_resource_id.clone(),
            root_volume_serial: root.volume_serial,
            root_file_index: root.file_index,
        };
        let catalog = provider.catalog();
        catalog.register_scope(&journal_scope).unwrap();
        let journal = catalog.open_journal(&journal_scope).unwrap();
        journal
            .append_edit(
                binding.account_generation,
                crate::LocalFileIdentity {
                    volume_serial: root.volume_serial,
                    file_index: 99,
                },
                "diagnostic.txt",
                Some(crate::RemoteEditBaseline {
                    resource_id: binding.remote_resource_id,
                    etag: binding.base_etag,
                    byte_len: binding.base_size,
                }),
                b"test",
            )
            .unwrap();
    }

    #[test]
    fn corrupt_or_unindexed_journal_scopes_fail_closed() {
        let temp = private_tempdir();
        let (scope, root) = fixture();
        let provider = DurableEditRecoveryProvider::new(
            temp.path().to_path_buf(),
            scope.clone(),
            root,
            TestProtector,
        );
        provider.prepare(&scope, root).unwrap();

        let index_dir = temp.path().join(CATALOG_DIRECTORY);
        fs::write(index_dir.join("not-a-scope.scope"), b"bad").unwrap();
        assert!(provider.prepare(&scope, root).is_err());

        fs::remove_file(index_dir.join("not-a-scope.scope")).unwrap();
        let unknown_journal = EditJournal::storage_root(temp.path()).join("unindexed-scope");
        fs::create_dir_all(&unknown_journal).unwrap();
        assert!(provider.prepare(&scope, root).is_err());
    }

    #[test]
    fn discovery_is_exact_to_account_and_local_root_across_restart() {
        let temp = private_tempdir();
        let (scope, root) = fixture();
        let provider = DurableEditRecoveryProvider::new(
            temp.path().to_path_buf(),
            scope.clone(),
            root,
            TestProtector,
        );
        let prepared = provider.prepare(&scope, root).unwrap();
        prepared
            .append_edit(
                &binding(&scope),
                root,
                crate::LocalFileIdentity {
                    volume_serial: root.volume_serial,
                    file_index: 56,
                },
                "account-a.txt",
                b"a",
            )
            .unwrap();

        let other_client = OpenCloudClient::new("https://example.test", "fixture".into()).unwrap();
        let other_scope = ProviderScope::new(
            &other_client,
            "default".into(),
            "other-account".into(),
            other_client.server_origin().unwrap(),
        )
        .unwrap();
        let other_provider = DurableEditRecoveryProvider::new(
            temp.path().to_path_buf(),
            other_scope.clone(),
            root,
            TestProtector,
        );
        other_provider
            .prepare(&other_scope, root)
            .unwrap()
            .append_edit(
                &binding(&other_scope),
                root,
                crate::LocalFileIdentity {
                    volume_serial: root.volume_serial,
                    file_index: 57,
                },
                "account-b.txt",
                b"b",
            )
            .unwrap();

        let other_root = ConfiguredRootIdentity {
            file_index: root.file_index + 1,
            ..root
        };
        let other_root_provider = DurableEditRecoveryProvider::new(
            temp.path().to_path_buf(),
            scope.clone(),
            other_root,
            TestProtector,
        );
        other_root_provider
            .prepare(&scope, other_root)
            .unwrap()
            .append_edit(
                &binding(&scope),
                other_root,
                crate::LocalFileIdentity {
                    volume_serial: other_root.volume_serial,
                    file_index: 58,
                },
                "other-root.txt",
                b"c",
            )
            .unwrap();

        drop(prepared);
        drop(provider);
        let restarted =
            DurableEditRecoveryProvider::new(temp.path().to_path_buf(), scope, root, TestProtector);
        let records = restarted.unresolved_edits().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].relative_path, "account-a.txt");
        assert!(restarted.has_unresolved_edits().unwrap());
    }

    #[test]
    fn provider_rejects_a_different_account_scope_for_preflight() {
        let temp = private_tempdir();
        let (scope, root) = fixture();
        let provider = DurableEditRecoveryProvider::new(
            temp.path().to_path_buf(),
            scope.clone(),
            root,
            TestProtector,
        );
        let other_client = OpenCloudClient::new("https://example.test", "other".into()).unwrap();
        let other_scope = ProviderScope::new(
            &other_client,
            scope.profile_id().to_owned(),
            "other-account".into(),
            other_client.server_origin().unwrap(),
        )
        .unwrap();
        assert!(provider.prepare(&other_scope, root).is_err());
        assert!(
            provider
                .prepare(
                    &scope,
                    ConfiguredRootIdentity {
                        file_index: root.file_index + 1,
                        ..root
                    }
                )
                .is_err()
        );
    }
}
