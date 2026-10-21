//! Durable private working copies for a future encrypted-vault write path.
//!
//! This module stores private working copies and commit state. A trusted route
//! lease supplies upload callbacks; the spool itself does not encrypt, replay,
//! or automatically recover records. Callers validate binding and unlock
//! before each use. Dirty records remain across errors and lock/restart.
//!
//! Working-copy bytes are plaintext on local storage. Owner-only permissions
//! reduce access by other local users but do not provide disk encryption or
//! secure deletion; a crash may leave partial plaintext records or a temporary
//! upload snapshot for explicit recovery/manual cleanup.

use crate::vault_routes::{VaultUploadOutcome, VaultWriteSource};
use raiun_core::backend::{CloudError, RemoteEntry, WriteCondition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::{fmt, io::ErrorKind as IoErrorKind};
use tempfile::Builder;
use url::Url;

pub const MAX_VAULT_WORKING_COPY_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub const MAX_VAULT_WRITE_SCAN_ENTRIES: usize = 10_000;
pub const MAX_VAULT_WRITE_MANIFEST_BYTES: u64 = 16 * 1024;
const MAX_ID_BYTES: usize = 512;
const MAX_ORIGIN_BYTES: usize = 4096;
const MAX_TARGET_BYTES: usize = 4096;
const MAX_ETAG_BYTES: usize = 4096;
pub(super) const ROOT_DIR_NAME: &str = "raiun-vault-write";
const RECORD_PREFIX: &str = "raiun-vault-write-";
const CANCEL_CREATE_PREFIX: &str = "cancel-create-";
const RETARGET_SUBTREE_PREFIX: &str = "retarget-subtree-";
const MANIFEST_NAME: &str = "record.json";
const DATA_NAME: &str = "working-copy.bin";
const SCHEMA_VERSION: u32 = 1;

/// Account and remote-root identity for a working copy. It excludes the
/// logical target and the transient FUSE route generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultWriteScope {
    account_id: String,
    server_origin: String,
    space_id: String,
    root_resource_id: String,
}

impl VaultWriteScope {
    pub fn new(
        account_id: impl Into<String>,
        server_origin: impl Into<String>,
        space_id: impl Into<String>,
        root_resource_id: impl Into<String>,
    ) -> Result<Self, VaultWriteError> {
        let account_id = account_id.into();
        let server_origin = canonical_origin(&server_origin.into())?;
        let space_id = space_id.into();
        let root_resource_id = root_resource_id.into();
        let scope = Self {
            account_id,
            server_origin,
            space_id,
            root_resource_id,
        };
        validate_scope(&scope)?;
        Ok(scope)
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn server_origin(&self) -> &str {
        &self.server_origin
    }

    pub fn space_id(&self) -> &str {
        &self.space_id
    }

    pub fn root_resource_id(&self) -> &str {
        &self.root_resource_id
    }
}

/// Opaque remote target plus the condition captured when editing began.
/// `opaque_relative_target` is never interpreted as a host filesystem path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultWriteTarget {
    opaque_relative_target: String,
    condition: WriteCondition,
    #[serde(default)]
    parent_ref: Option<VaultParentRef>,
}

/// Exact identity of the directory in which a new encrypted item is being
/// created. A pending directory reference points to a durable CreateDirectory
/// operation; it is never inferred from a synthetic remote ID or local ETag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum VaultParentRef {
    Stable { resource_id: String },
    PendingCreate { write_id: String, revision: u64 },
}

impl VaultParentRef {
    pub fn stable(resource_id: impl Into<String>) -> Result<Self, VaultWriteError> {
        let parent = Self::Stable {
            resource_id: resource_id.into(),
        };
        validate_parent_ref(&parent)?;
        Ok(parent)
    }

    pub fn pending_create(
        write_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, VaultWriteError> {
        let parent = Self::PendingCreate {
            write_id: write_id.into(),
            revision,
        };
        validate_parent_ref(&parent)?;
        Ok(parent)
    }
}

impl VaultWriteTarget {
    pub fn new(
        opaque_relative_target: impl Into<String>,
        condition: WriteCondition,
    ) -> Result<Self, VaultWriteError> {
        let opaque_relative_target = opaque_relative_target.into();
        let target = Self {
            opaque_relative_target,
            condition,
            parent_ref: None,
        };
        validate_target(&target)?;
        Ok(target)
    }

    pub fn new_with_parent(
        opaque_relative_target: impl Into<String>,
        condition: WriteCondition,
        parent_ref: VaultParentRef,
    ) -> Result<Self, VaultWriteError> {
        let mut target = Self::new(opaque_relative_target, condition)?;
        validate_parent_ref(&parent_ref)?;
        target.parent_ref = Some(parent_ref);
        Ok(target)
    }

    pub fn opaque_relative_target(&self) -> &str {
        &self.opaque_relative_target
    }

    pub fn condition(&self) -> &WriteCondition {
        &self.condition
    }

    pub fn parent_ref(&self) -> Option<&VaultParentRef> {
        self.parent_ref.as_ref()
    }

    fn with_condition(&self, condition: WriteCondition) -> Result<Self, VaultWriteError> {
        match self.parent_ref.clone() {
            Some(parent_ref) => {
                Self::new_with_parent(self.opaque_relative_target.clone(), condition, parent_ref)
            }
            None => Self::new(self.opaque_relative_target.clone(), condition),
        }
    }

    fn without_parent_ref(&self) -> Result<Self, VaultWriteError> {
        Self::new(self.opaque_relative_target.clone(), self.condition.clone())
    }
}

/// Binding for one current write handle. The generation is transient and is
/// intentionally not persisted, so explicit recovery can bind a new route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultWriteBinding {
    scope: VaultWriteScope,
    target: VaultWriteTarget,
    route_generation: u64,
}

impl VaultWriteBinding {
    pub fn new(
        scope: VaultWriteScope,
        target: VaultWriteTarget,
        route_generation: u64,
    ) -> Result<Self, VaultWriteError> {
        validate_scope(&scope)?;
        validate_target(&target)?;
        if route_generation == 0 {
            return Err(VaultWriteError::InvalidBinding);
        }
        Ok(Self {
            scope,
            target,
            route_generation,
        })
    }

    pub fn scope(&self) -> &VaultWriteScope {
        &self.scope
    }

    pub fn target(&self) -> &VaultWriteTarget {
        &self.target
    }

    pub fn route_generation(&self) -> u64 {
        self.route_generation
    }
}

/// Generic errors that intentionally omit names, paths, and remote metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultWriteError {
    InvalidBinding,
    InvalidTarget,
    InvalidCondition,
    InvalidRecordId,
    ScanLimit,
    StaleGeneration,
    SizeLimit,
    UnsafeDirectory,
    RecordNotFound,
    RecordMismatch,
    CorruptRecord,
    ChangedDuringUpload,
    Backend(CloudError),
    Io,
}

impl fmt::Display for VaultWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidBinding => "vault write binding is invalid",
            Self::InvalidTarget => "vault write target is invalid",
            Self::InvalidCondition => "vault write condition is invalid",
            Self::InvalidRecordId => "vault write record identifier is invalid",
            Self::ScanLimit => "vault cancellation scan exceeded its safety bound",
            Self::StaleGeneration => "vault write handle belongs to an inactive route",
            Self::SizeLimit => "vault working copy exceeds its size limit",
            Self::UnsafeDirectory => "vault working-copy directory is unsafe",
            Self::RecordNotFound => "vault working-copy record was not found",
            Self::RecordMismatch => "vault working-copy record does not match this target",
            Self::CorruptRecord => "vault working-copy record is incomplete or corrupt",
            Self::ChangedDuringUpload => "vault working copy changed during upload",
            Self::Backend(error) => return write!(f, "{}", error.message),
            Self::Io => "could not access the vault working copy",
        })
    }
}

impl std::error::Error for VaultWriteError {}

/// One metadata-only record discovered in the private spool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingVaultWrite {
    pub record_id: String,
    pub scope: Option<VaultWriteScope>,
    pub target: Option<VaultWriteTarget>,
    pub bytes: Option<u64>,
    pub lifecycle: Option<VaultWriteLifecycle>,
    pub warning: Option<VaultWriteWarning>,
}

/// The only journal operation kinds eligible for a queued-directory subtree
/// retarget. This mirrors the backend's narrow NeverAttempted closure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingVaultRetargetOperation {
    CreateFile,
    CreateDirectory,
}

/// One authenticated operation identity recorded before the backend's atomic
/// subtree CAS. File rows bind the exact clean local spool record and digest;
/// directory rows have no local body record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingVaultRetargetRow {
    pub write_id: String,
    pub previous_revision: u64,
    pub revision: u64,
    pub operation: PendingVaultRetargetOperation,
    pub old_path: String,
    pub path: String,
    pub record_id: Option<String>,
    pub old_target: Option<VaultWriteTarget>,
    pub target: VaultWriteTarget,
    pub bytes: u64,
    pub sha256: String,
}

/// Root WAL for a bounded directory subtree retarget. It is durably published
/// before the backend cache transaction and remains until every matching file
/// manifest has been moved to the authenticated new revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingVaultDirectoryRetarget {
    pub scope: VaultWriteScope,
    pub root_write_id: String,
    pub root_previous_revision: u64,
    pub root_revision: u64,
    pub source_path: String,
    pub destination_path: String,
    pub rows: Vec<PendingVaultRetargetRow>,
}

/// Durable local intent for canceling one exact, never-attempted encrypted
/// file-create journal operation. This metadata is private and contains no
/// plaintext path; it survives working-copy removal until backend receipt ack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingVaultCreateCancellation {
    pub record_id: String,
    pub scope: VaultWriteScope,
    pub target: VaultWriteTarget,
    /// Virtual plaintext path needed to validate the backend receipt. This is
    /// stored only in the private local WAL, never in the encrypted cache.
    pub path: String,
    pub write_id: String,
    pub revision: u64,
    pub bytes: u64,
    pub sha256: String,
    /// Set only after the exact local manifest and data file were securely
    /// removed and the containing directory was synced. Recovery requires
    /// this proof before acknowledging a backend receipt without a record.
    #[serde(default)]
    pub local_retired: bool,
}

/// Durable state of one local encrypted-vault working copy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum VaultWriteLifecycle {
    Initializing,
    CleanBaseline {
        bytes: u64,
        sha256: String,
    },
    Dirty,
    Committed {
        bytes: u64,
        sha256: String,
        etag: String,
    },
    Queued {
        bytes: u64,
        sha256: String,
        write_id: String,
        revision: u64,
        uncertain: bool,
    },
    /// A create operation was reserved durably, but has no retryable content
    /// revision yet. The original Absent condition remains in the binding.
    BuildingCreate {
        write_id: String,
        revision: u64,
    },
    /// Local bytes changed after a create was reserved. Keep its operation
    /// reference so the next flush updates the same durable create record.
    DirtyBuildingCreate {
        write_id: String,
        revision: u64,
    },
    /// Bytes changed after a queued revision. The next flush must supersede
    /// that same operation rather than losing its identity on restart.
    DirtyQueued {
        write_id: String,
        revision: u64,
        uncertain: bool,
    },
    /// Local cancellation intent for an exact queued create. Ordinary flush
    /// and recovery paths must not replay this operation while the backend
    /// cancellation receipt is resolved.
    CancelPendingCreate {
        write_id: String,
        revision: u64,
        bytes: u64,
        sha256: String,
    },
    /// A local marker written before the backend's atomic retarget CAS. On
    /// restart, the exact operation ID resolver decides whether to restore the
    /// old queued binding or finish the new one.
    RetargetingCreate {
        write_id: String,
        previous_revision: u64,
        destination_path: String,
        destination: VaultWriteTarget,
        bytes: u64,
        sha256: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCreateContent {
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultWriteWarning {
    MissingManifest,
    MissingData,
    UnsafeManifest,
    UnsafeData,
    ManifestTooLarge,
    MalformedManifest,
    InvalidManifest,
    RecordNameMismatch,
    DataTooLarge,
    LifecycleMismatch,
}

/// A separate per-profile store. No record is automatically replayed or
/// deleted; even failed initial copies remain available for explicit recovery.
pub struct VaultWriteSpool {
    root: PathBuf,
}

impl VaultWriteSpool {
    /// Open or create a dedicated vault-write directory beneath a trusted
    /// profile state directory. Existing directories must already be private.
    pub fn open(profile_state_dir: &Path) -> Result<Self, VaultWriteError> {
        validate_private_dir(profile_state_dir)?;
        let root = profile_state_dir.join(ROOT_DIR_NAME);
        match create_private_dir(&root) {
            Ok(()) => sync_dir(profile_state_dir)?,
            Err(error) if error.kind() == IoErrorKind::AlreadyExists => {}
            Err(_) => return Err(VaultWriteError::Io),
        }
        validate_private_dir(&root)?;
        Ok(Self { root })
    }

    /// Open an existing private spool without creating it.
    pub fn open_existing(profile_state_dir: &Path) -> Result<Option<Self>, VaultWriteError> {
        validate_private_dir(profile_state_dir)?;
        let root = profile_state_dir.join(ROOT_DIR_NAME);
        match fs::symlink_metadata(&root) {
            Err(error) if error.kind() == IoErrorKind::NotFound => Ok(None),
            Err(_) => Err(VaultWriteError::Io),
            Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
                Err(VaultWriteError::UnsafeDirectory)
            }
            Ok(_) => {
                validate_private_dir(&root)?;
                Ok(Some(Self { root }))
            }
        }
    }

    /// Existing private spool root for trusted local maintenance commands.
    /// Do not pass this host path through untrusted UI payloads.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Durably record the complete bounded operation closure before the
    /// backend publishes its all-or-none subtree retarget.
    pub fn begin_directory_subtree_retarget(
        &self,
        retarget: &PendingVaultDirectoryRetarget,
    ) -> Result<(), VaultWriteError> {
        validate_directory_retarget(retarget)?;
        validate_private_dir(&self.root)?;
        self.validate_old_subtree_retarget_members(retarget)?;
        let path = directory_retarget_path(&self.root, &retarget.root_write_id)?;
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                if read_directory_retarget(&path)? == *retarget {
                    Ok(())
                } else {
                    Err(VaultWriteError::CorruptRecord)
                }
            }
            Err(error) if error.kind() == IoErrorKind::NotFound => {
                write_directory_retarget(&self.root, retarget)
            }
            Err(_) => Err(VaultWriteError::Io),
        }
    }

    /// Read all durable subtree retarget WAL records. A malformed record
    /// fails the scan; callers must not skip it and continue with path-based
    /// recovery.
    pub fn list_directory_subtree_retargets(
        &self,
    ) -> Result<Vec<PendingVaultDirectoryRetarget>, VaultWriteError> {
        validate_private_dir(&self.root)?;
        let mut retargets = Vec::new();
        for (index, entry) in fs::read_dir(&self.root)
            .map_err(|_| VaultWriteError::Io)?
            .enumerate()
        {
            if index >= MAX_VAULT_WRITE_SCAN_ENTRIES {
                return Err(VaultWriteError::ScanLimit);
            }
            let entry = entry.map_err(|_| VaultWriteError::Io)?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if !name.starts_with(RETARGET_SUBTREE_PREFIX) {
                continue;
            }
            let write_id = name
                .strip_prefix(RETARGET_SUBTREE_PREFIX)
                .and_then(|value| value.strip_suffix(".json"))
                .ok_or(VaultWriteError::CorruptRecord)?;
            validate_queued_id(write_id)?;
            let retarget = read_directory_retarget(&entry.path())?;
            if retarget.root_write_id != write_id {
                return Err(VaultWriteError::CorruptRecord);
            }
            retargets.push(retarget);
        }
        retargets.sort_by(|left, right| left.root_write_id.cmp(&right.root_write_id));
        Ok(retargets)
    }

    /// Apply the file-manifest half of a backend-proven all-new retarget.
    /// Each row accepts only the exact old or exact new revision, so this is
    /// safe to repeat after a crash between any two manifest replacements.
    pub fn apply_directory_subtree_retarget(
        &self,
        retarget: &PendingVaultDirectoryRetarget,
        active_generation: u64,
    ) -> Result<(), VaultWriteError> {
        validate_directory_retarget(retarget)?;
        validate_private_dir(&self.root)?;
        let wal_path = directory_retarget_path(&self.root, &retarget.root_write_id)?;
        if read_directory_retarget(&wal_path)? != *retarget {
            return Err(VaultWriteError::CorruptRecord);
        }
        for row in &retarget.rows {
            if row.operation != PendingVaultRetargetOperation::CreateFile {
                continue;
            }
            let record_id = row
                .record_id
                .as_deref()
                .ok_or(VaultWriteError::CorruptRecord)?;
            validate_record_id(record_id)?;
            let record_dir = self.root.join(record_id);
            let mut record = read_manifest(&record_dir)?;
            if record.scope != retarget.scope || record.record_id != record_id {
                return Err(VaultWriteError::RecordMismatch);
            }
            let data_path = record_dir.join(DATA_NAME);
            let mut data = open_private_read(&data_path)?;
            let metadata = data.metadata().map_err(|_| VaultWriteError::Io)?;
            if metadata.len() != row.bytes || hash_file(&mut data)? != row.sha256 {
                return Err(VaultWriteError::ChangedDuringUpload);
            }
            match (&record.target, &record.lifecycle) {
                (
                    old_target,
                    VaultWriteLifecycle::Queued {
                        bytes,
                        sha256,
                        write_id,
                        revision,
                        uncertain: false,
                    },
                ) if row.old_target.as_ref() == Some(old_target)
                    && *bytes == row.bytes
                    && sha256 == &row.sha256
                    && write_id == &row.write_id
                    && *revision == row.previous_revision =>
                {
                    record.target = row.target.clone();
                    record.lifecycle = VaultWriteLifecycle::Queued {
                        bytes: row.bytes,
                        sha256: row.sha256.clone(),
                        write_id: row.write_id.clone(),
                        revision: row.revision,
                        uncertain: false,
                    };
                    write_manifest_replace(&record_dir, &record)?;
                }
                (
                    new_target,
                    VaultWriteLifecycle::Queued {
                        bytes,
                        sha256,
                        write_id,
                        revision,
                        uncertain: false,
                    },
                ) if new_target == &row.target
                    && *bytes == row.bytes
                    && sha256 == &row.sha256
                    && write_id == &row.write_id
                    && *revision == row.revision => {}
                _ => return Err(VaultWriteError::RecordMismatch),
            }
            let binding = VaultWriteBinding::new(
                retarget.scope.clone(),
                row.target.clone(),
                active_generation,
            )?;
            validate_generation(&binding, active_generation)?;
        }
        sync_dir(&self.root)?;
        Ok(())
    }

    fn validate_old_subtree_retarget_members(
        &self,
        retarget: &PendingVaultDirectoryRetarget,
    ) -> Result<(), VaultWriteError> {
        for row in &retarget.rows {
            if row.operation != PendingVaultRetargetOperation::CreateFile {
                continue;
            }
            let record_id = row
                .record_id
                .as_deref()
                .ok_or(VaultWriteError::CorruptRecord)?;
            let old_target = row
                .old_target
                .as_ref()
                .ok_or(VaultWriteError::CorruptRecord)?;
            let record_dir = self.root.join(record_id);
            let record = read_manifest(&record_dir)?;
            if record.scope != retarget.scope
                || record.record_id != record_id
                || record.target != *old_target
                || !matches!(record.lifecycle,
                    VaultWriteLifecycle::Queued { ref write_id, revision, bytes, ref sha256, uncertain: false }
                    if write_id == &row.write_id && revision == row.previous_revision
                        && bytes == row.bytes && sha256 == &row.sha256)
            {
                return Err(VaultWriteError::RecordMismatch);
            }
            let mut data = open_private_read(&record_dir.join(DATA_NAME))?;
            if data.metadata().map_err(|_| VaultWriteError::Io)?.len() != row.bytes
                || hash_file(&mut data)? != row.sha256
            {
                return Err(VaultWriteError::ChangedDuringUpload);
            }
        }
        Ok(())
    }

    /// Remove the local WAL only after every file member is at its exact new
    /// binding. The backend proof is checked by the caller before this step.
    pub fn finish_directory_subtree_retarget(
        &self,
        retarget: &PendingVaultDirectoryRetarget,
    ) -> Result<(), VaultWriteError> {
        validate_directory_retarget(retarget)?;
        let path = directory_retarget_path(&self.root, &retarget.root_write_id)?;
        if read_directory_retarget(&path)? != *retarget {
            return Err(VaultWriteError::CorruptRecord);
        }
        for row in &retarget.rows {
            if row.operation != PendingVaultRetargetOperation::CreateFile {
                continue;
            }
            let record_id = row
                .record_id
                .as_deref()
                .ok_or(VaultWriteError::CorruptRecord)?;
            let record = read_manifest(&self.root.join(record_id))?;
            if record.scope != retarget.scope
                || record.target != row.target
                || !matches!(record.lifecycle,
                    VaultWriteLifecycle::Queued { ref write_id, revision, bytes, ref sha256, uncertain: false }
                    if write_id == &row.write_id && revision == row.revision
                        && bytes == row.bytes && sha256 == &row.sha256)
            {
                return Err(VaultWriteError::RecordMismatch);
            }
        }
        fs::remove_file(path).map_err(|_| VaultWriteError::Io)?;
        sync_dir(&self.root)
    }

    /// Discard a pre-publish retarget WAL only when the backend proved the
    /// entire operation set is still old and every local file manifest is
    /// still at its exact old binding. A mixed local batch is retained for
    /// attention rather than rolled back or guessed at.
    pub fn discard_directory_subtree_retarget_if_unchanged(
        &self,
        retarget: &PendingVaultDirectoryRetarget,
    ) -> Result<(), VaultWriteError> {
        validate_directory_retarget(retarget)?;
        validate_private_dir(&self.root)?;
        let path = directory_retarget_path(&self.root, &retarget.root_write_id)?;
        if read_directory_retarget(&path)? != *retarget {
            return Err(VaultWriteError::CorruptRecord);
        }
        self.validate_old_subtree_retarget_members(retarget)?;
        fs::remove_file(path).map_err(|_| VaultWriteError::Io)?;
        sync_dir(&self.root)
    }

    /// Begin an explicitly bound working copy. A read error leaves a record
    /// with the bytes copied so far; callers must not discard it automatically.
    pub fn begin<R: Read>(
        &self,
        binding: VaultWriteBinding,
        initial: &mut R,
        active_generation: u64,
    ) -> Result<VaultWorkingCopy, VaultWriteError> {
        validate_generation(&binding, active_generation)?;
        validate_private_dir(&self.root)?;
        let temp = Builder::new()
            .prefix(RECORD_PREFIX)
            .rand_bytes(16)
            .tempdir_in(&self.root)
            .map_err(|_| VaultWriteError::Io)?;
        let record_dir = temp.keep();
        // Persist the new record directory entry before storing its manifest or
        // data so a crash cannot silently lose the spool's directory entry.
        sync_dir(&self.root)?;
        set_private_dir(&record_dir)?;
        let record_id = record_id_from_path(&record_dir)?;
        let persistent =
            PersistentRecord::from_binding(&binding, VaultWriteLifecycle::Initializing);
        write_manifest(&record_dir, &persistent)?;
        let mut data = create_private_file(&record_dir.join(DATA_NAME))?;
        let copy_result = copy_bounded(initial, &mut data);
        let sync_result = data
            .sync_all()
            .map_err(|_| VaultWriteError::Io)
            .and_then(|()| sync_dir(&record_dir));
        if let Err(error) = copy_result {
            let _ = sync_result;
            return Err(error);
        }
        sync_result?;
        let baseline = lifecycle_for_data(&mut data, LifecycleKind::CleanBaseline)?;
        write_manifest_replace(
            &record_dir,
            &PersistentRecord::from_binding(&binding, baseline.clone()),
        )?;
        Ok(VaultWorkingCopy {
            record_id,
            record_dir,
            binding,
            data,
            lifecycle: baseline,
        })
    }

    /// List a bounded number of records using metadata only. No working-copy
    /// body is read. Unsafe/corrupt entries are reported without exposing paths.
    pub fn list_pending(&self) -> Result<(Vec<PendingVaultWrite>, bool), VaultWriteError> {
        validate_private_dir(&self.root)?;
        let entries = fs::read_dir(&self.root).map_err(|_| VaultWriteError::Io)?;
        let mut records = Vec::new();
        let mut truncated = false;
        for (index, entry) in entries.enumerate() {
            if index >= MAX_VAULT_WRITE_SCAN_ENTRIES {
                truncated = true;
                break;
            }
            let entry = entry.map_err(|_| VaultWriteError::Io)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.starts_with(RECORD_PREFIX) {
                continue;
            }
            let path = entry.path();
            records.push(inspect_record(&path, name));
        }
        records.sort_by(|left, right| left.record_id.cmp(&right.record_id));
        Ok((records, truncated))
    }

    /// Discover cancellation WAL records, including a marker left inside a
    /// working-copy directory if the process stopped before publishing its
    /// separate post-retirement tombstone.
    pub fn list_create_cancellations(
        &self,
    ) -> Result<Vec<PendingVaultCreateCancellation>, VaultWriteError> {
        validate_private_dir(&self.root)?;
        let entries = fs::read_dir(&self.root).map_err(|_| VaultWriteError::Io)?;
        let mut cancellations = std::collections::BTreeMap::new();
        let mut scanned = 0usize;
        for entry in entries {
            scanned += 1;
            if scanned > MAX_VAULT_WRITE_SCAN_ENTRIES {
                return Err(VaultWriteError::ScanLimit);
            }
            let entry = entry.map_err(|_| VaultWriteError::Io)?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if name.starts_with(CANCEL_CREATE_PREFIX) {
                let record_id = name
                    .strip_prefix(CANCEL_CREATE_PREFIX)
                    .and_then(|name| name.strip_suffix(".json"))
                    .ok_or(VaultWriteError::CorruptRecord)?;
                validate_record_id(record_id)?;
                let marker = read_create_cancellation(&entry.path())?;
                validate_create_cancellation(&marker)?;
                if marker.record_id != record_id {
                    return Err(VaultWriteError::CorruptRecord);
                }
                cancellations.insert(record_id.to_owned(), marker);
            }
        }

        let entries = fs::read_dir(&self.root).map_err(|_| VaultWriteError::Io)?;
        for entry in entries {
            let entry = entry.map_err(|_| VaultWriteError::Io)?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if !name.starts_with(RECORD_PREFIX) {
                continue;
            }
            validate_record_id(&name)?;
            let record_dir = entry.path();
            let record = read_manifest(&record_dir)?;
            let VaultWriteLifecycle::CancelPendingCreate {
                write_id,
                revision,
                bytes,
                sha256,
            } = record.lifecycle
            else {
                continue;
            };
            let Some(marker) = cancellations.get(&name) else {
                // The root WAL is written before the lifecycle transition.
                // A markerless cancellation lifecycle is therefore corrupt.
                return Err(VaultWriteError::CorruptRecord);
            };
            if marker.scope != record.scope
                || marker.target != record.target
                || marker.write_id != write_id
                || marker.revision != revision
                || marker.bytes != bytes
                || marker.sha256 != sha256
            {
                return Err(VaultWriteError::CorruptRecord);
            }
        }
        Ok(cancellations.into_values().collect())
    }

    /// Ensure the separate post-retirement WAL exists before the journal can
    /// be acknowledged. The filename derives only from a validated random
    /// spool record ID; contents are bounded and atomically published.
    pub fn ensure_create_cancellation_tombstone(
        &self,
        cancellation: &PendingVaultCreateCancellation,
    ) -> Result<(), VaultWriteError> {
        validate_private_dir(&self.root)?;
        write_create_cancellation_tombstone(&self.root, cancellation)
    }

    /// Remove the exact local WAL only after the backend receipt has been
    /// acknowledged. Missing or replaced tombstones are never treated as
    /// permission to acknowledge another operation.
    pub fn remove_create_cancellation_tombstone(
        &self,
        cancellation: &PendingVaultCreateCancellation,
    ) -> Result<(), VaultWriteError> {
        validate_create_cancellation(cancellation)?;
        validate_private_dir(&self.root)?;
        let path = self.cancellation_path(&cancellation.record_id);
        let actual = read_create_cancellation(&path)?;
        if actual != *cancellation {
            return Err(VaultWriteError::CorruptRecord);
        }
        fs::remove_file(path).map_err(|_| VaultWriteError::Io)?;
        sync_dir(&self.root)
    }

    pub fn mark_create_cancellation_local_retired(
        &self,
        cancellation: &PendingVaultCreateCancellation,
    ) -> Result<PendingVaultCreateCancellation, VaultWriteError> {
        validate_create_cancellation(cancellation)?;
        validate_private_dir(&self.root)?;
        let record_dir = self.root.join(&cancellation.record_id);
        match fs::symlink_metadata(&record_dir) {
            Err(error) if error.kind() == IoErrorKind::NotFound => {}
            Ok(_) => return Err(VaultWriteError::RecordMismatch),
            Err(_) => return Err(VaultWriteError::Io),
        }
        let path = self.cancellation_path(&cancellation.record_id);
        let actual = read_create_cancellation(&path)?;
        if actual != *cancellation {
            return Err(VaultWriteError::CorruptRecord);
        }
        let mut updated = cancellation.clone();
        updated.local_retired = true;
        replace_create_cancellation_tombstone(&self.root, &updated)?;
        Ok(updated)
    }

    fn cancellation_path(&self, record_id: &str) -> PathBuf {
        self.root
            .join(format!("{CANCEL_CREATE_PREFIX}{record_id}.json"))
    }

    /// Reopen one record only when its durable account/root/target/condition
    /// exactly matches the caller's current explicit recovery binding. The
    /// caller supplies the fresh route generation; the saved generation is not
    /// an authority to resume after lock or restart.
    pub fn recover(
        &self,
        record_id: &str,
        binding: VaultWriteBinding,
        active_generation: u64,
    ) -> Result<VaultWorkingCopy, VaultWriteError> {
        validate_generation(&binding, active_generation)?;
        validate_record_id(record_id)?;
        validate_private_dir(&self.root)?;
        let record_dir = self.root.join(record_id);
        let metadata = fs::symlink_metadata(&record_dir).map_err(|error| {
            if error.kind() == IoErrorKind::NotFound {
                VaultWriteError::RecordNotFound
            } else {
                VaultWriteError::Io
            }
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(VaultWriteError::CorruptRecord);
        }
        validate_private_dir(&record_dir).map_err(|_| VaultWriteError::CorruptRecord)?;
        let mut persistent = read_manifest(&record_dir)?;
        if !persistent.matches(&binding) {
            return Err(VaultWriteError::RecordMismatch);
        }
        let data_path = record_dir.join(DATA_NAME);
        let data_meta =
            fs::symlink_metadata(&data_path).map_err(|_| VaultWriteError::CorruptRecord)?;
        if !data_meta.is_file() || data_meta.file_type().is_symlink() {
            return Err(VaultWriteError::CorruptRecord);
        }
        validate_private_file_metadata(&data_meta).map_err(|_| VaultWriteError::CorruptRecord)?;
        let mut data = open_private_rw(&data_path)?;
        let opened_meta = data.metadata().map_err(|_| VaultWriteError::Io)?;
        if !same_identity(&data_meta, &opened_meta)
            || !opened_meta.is_file()
            || opened_meta.len() > MAX_VAULT_WORKING_COPY_BYTES
        {
            return Err(VaultWriteError::CorruptRecord);
        }
        let expected = match &persistent.lifecycle {
            VaultWriteLifecycle::CleanBaseline { bytes, sha256 }
            | VaultWriteLifecycle::Committed { bytes, sha256, .. }
            | VaultWriteLifecycle::Queued { bytes, sha256, .. }
            | VaultWriteLifecycle::RetargetingCreate { bytes, sha256, .. }
            | VaultWriteLifecycle::CancelPendingCreate { bytes, sha256, .. } => {
                Some((*bytes, sha256.clone()))
            }
            VaultWriteLifecycle::Initializing
            | VaultWriteLifecycle::Dirty
            | VaultWriteLifecycle::BuildingCreate { .. }
            | VaultWriteLifecycle::DirtyBuildingCreate { .. }
            | VaultWriteLifecycle::DirtyQueued { .. } => None,
        };
        let state_changed = if let Some((bytes, hash)) = expected {
            bytes != opened_meta.len() || hash_file(&mut data)? != hash
        } else {
            false
        };
        if state_changed {
            if matches!(
                persistent.lifecycle,
                VaultWriteLifecycle::CancelPendingCreate { .. }
            ) {
                return Err(VaultWriteError::ChangedDuringUpload);
            }
            persistent.lifecycle = VaultWriteLifecycle::Dirty;
            write_manifest_replace(&record_dir, &persistent)?;
        }
        let record_id = record_id.to_owned();
        Ok(VaultWorkingCopy {
            record_id,
            record_dir,
            binding,
            data,
            lifecycle: persistent.lifecycle,
        })
    }
}

/// A random-access local plaintext working copy. It is not a remote commit and
/// has no automatic replay/removal API. Each method requires the active route
/// generation so stale handles cannot mutate after a lock/revoke transition.
pub struct VaultWorkingCopy {
    record_id: String,
    record_dir: PathBuf,
    binding: VaultWriteBinding,
    data: File,
    lifecycle: VaultWriteLifecycle,
}

impl VaultWorkingCopy {
    pub fn record_id(&self) -> &str {
        &self.record_id
    }

    pub fn binding(&self) -> &VaultWriteBinding {
        &self.binding
    }

    pub fn lifecycle(&self) -> &VaultWriteLifecycle {
        &self.lifecycle
    }

    /// Mark an intentional empty/new/truncated replacement dirty before the
    /// FUSE handle is published, so a crash cannot mislabel it as a clean copy.
    pub fn mark_dirty(&mut self, active_generation: u64) -> Result<(), VaultWriteError> {
        self.check_generation(active_generation)?;
        self.mark_dirty_before_mutation()
    }

    /// Persist the backend's non-retryable create reservation before exposing
    /// the FUSE handle. Its content remains local until a later flush publishes
    /// a retryable create revision.
    pub fn record_building_create(
        &mut self,
        active_generation: u64,
        write_id: &str,
        revision: u64,
    ) -> Result<(), VaultWriteError> {
        self.check_generation(active_generation)?;
        if !matches!(self.binding.target.condition(), WriteCondition::Absent) {
            return Err(VaultWriteError::RecordMismatch);
        }
        validate_queued_id(write_id)?;
        if revision == 0 {
            return Err(VaultWriteError::CorruptRecord);
        }
        let lifecycle = VaultWriteLifecycle::BuildingCreate {
            write_id: write_id.to_owned(),
            revision,
        };
        write_manifest_replace(
            &self.record_dir,
            &PersistentRecord {
                schema: SCHEMA_VERSION,
                record_id: self.record_id.clone(),
                scope: self.binding.scope.clone(),
                target: self.binding.target.clone(),
                lifecycle: lifecycle.clone(),
            },
        )?;
        self.lifecycle = lifecycle;
        Ok(())
    }

    /// Persist a local WAL marker before the backend retarget CAS. If the
    /// process stops after the remote journal changes, restart can resolve the
    /// operation by ID and finish this exact destination without path replay.
    pub fn begin_never_attempted_create_retarget(
        &mut self,
        active_generation: u64,
        expected_write_id: &str,
        expected_revision: u64,
        destination_path: &str,
        destination: VaultWriteTarget,
    ) -> Result<(), VaultWriteError> {
        self.check_generation(active_generation)?;
        validate_target(&destination)?;
        validate_virtual_path(destination_path)?;
        if !matches!(self.binding.target.condition(), WriteCondition::Absent)
            || self.binding.target.parent_ref().is_none()
            || !matches!(destination.condition(), WriteCondition::Absent)
            || destination.parent_ref().is_none()
        {
            return Err(VaultWriteError::RecordMismatch);
        }
        let (bytes, sha256) = match &self.lifecycle {
            VaultWriteLifecycle::Queued {
                bytes,
                sha256,
                write_id,
                revision,
                uncertain: false,
            } if write_id == expected_write_id && *revision == expected_revision => {
                (*bytes, sha256.clone())
            }
            _ => return Err(VaultWriteError::RecordMismatch),
        };
        if self.data.metadata().map_err(|_| VaultWriteError::Io)?.len() != bytes
            || hash_file(&mut self.data)? != sha256
        {
            return Err(VaultWriteError::ChangedDuringUpload);
        }
        let lifecycle = VaultWriteLifecycle::RetargetingCreate {
            write_id: expected_write_id.to_owned(),
            previous_revision: expected_revision,
            destination_path: destination_path.to_owned(),
            destination,
            bytes,
            sha256,
        };
        write_manifest_replace(
            &self.record_dir,
            &PersistentRecord {
                schema: SCHEMA_VERSION,
                record_id: self.record_id.clone(),
                scope: self.binding.scope.clone(),
                target: self.binding.target.clone(),
                lifecycle: lifecycle.clone(),
            },
        )?;
        self.lifecycle = lifecycle;
        Ok(())
    }

    /// Persist a cancellation intent before the backend attempts its atomic
    /// NeverAttempted-to-CancelledReceipt transition. Only a clean, exact
    /// queued create can enter this state; its body remains in the private
    /// working-copy record until an authenticated cancellation receipt exists.
    pub fn begin_never_attempted_create_cancel(
        &mut self,
        active_generation: u64,
        expected_write_id: &str,
        expected_revision: u64,
        logical_path: &str,
    ) -> Result<VerifiedCreateContent, VaultWriteError> {
        self.check_generation(active_generation)?;
        if !matches!(self.binding.target.condition(), WriteCondition::Absent)
            || self.binding.target.parent_ref().is_none()
        {
            return Err(VaultWriteError::RecordMismatch);
        }
        let (bytes, sha256) = match &self.lifecycle {
            VaultWriteLifecycle::Queued {
                bytes,
                sha256,
                write_id,
                revision,
                uncertain: false,
            } if write_id == expected_write_id && *revision == expected_revision => {
                (*bytes, sha256.clone())
            }
            _ => return Err(VaultWriteError::RecordMismatch),
        };
        if self.data.metadata().map_err(|_| VaultWriteError::Io)?.len() != bytes
            || hash_file(&mut self.data)? != sha256
        {
            return Err(VaultWriteError::ChangedDuringUpload);
        }
        let cancellation = PendingVaultCreateCancellation {
            record_id: self.record_id.clone(),
            scope: self.binding.scope.clone(),
            target: self.binding.target.clone(),
            path: logical_path.to_owned(),
            write_id: expected_write_id.to_owned(),
            revision: expected_revision,
            bytes,
            sha256: sha256.clone(),
            local_retired: false,
        };
        let root = self
            .record_dir
            .parent()
            .ok_or(VaultWriteError::CorruptRecord)?;
        // Publish the recovery identity first. If the process stops before the
        // manifest transition, recovery can still promote the exact queued
        // record; no backend cancellation is attempted without this WAL.
        write_create_cancellation_tombstone(root, &cancellation)?;
        let lifecycle = VaultWriteLifecycle::CancelPendingCreate {
            write_id: expected_write_id.to_owned(),
            revision: expected_revision,
            bytes,
            sha256: sha256.clone(),
        };
        write_manifest_replace(
            &self.record_dir,
            &PersistentRecord {
                schema: SCHEMA_VERSION,
                record_id: self.record_id.clone(),
                scope: self.binding.scope.clone(),
                target: self.binding.target.clone(),
                lifecycle: lifecycle.clone(),
            },
        )?;
        self.lifecycle = lifecycle;
        Ok(VerifiedCreateContent { bytes, sha256 })
    }

    /// Remove a cancellation-marked create only after the caller has verified
    /// the matching backend receipt. The receipt's authenticated body identity
    /// must match both this marker and the unchanged local data file.
    pub fn retire_cancelled_create_if_unchanged(
        mut self,
        active_generation: u64,
        expected_write_id: &str,
        expected_revision: u64,
        verified_content: &VerifiedCreateContent,
    ) -> Result<bool, VaultWriteError> {
        self.check_generation(active_generation)?;
        let (bytes, sha256) = match &self.lifecycle {
            VaultWriteLifecycle::CancelPendingCreate {
                write_id,
                revision,
                bytes,
                sha256,
            } if write_id == expected_write_id && *revision == expected_revision => {
                (*bytes, sha256)
            }
            _ => return Err(VaultWriteError::RecordMismatch),
        };
        if verified_content.bytes != bytes
            || verified_content.sha256 != *sha256
            || self.data.metadata().map_err(|_| VaultWriteError::Io)?.len() != bytes
            || hash_file(&mut self.data)? != *sha256
        {
            return Ok(false);
        }
        self.retire_verified_record(active_generation)
    }

    /// Finish a verified retarget after backend CAS or after exact-ID restart
    /// resolution. The caller supplies the authenticated full-content digest.
    pub fn finish_verified_create_retarget(
        &mut self,
        active_generation: u64,
        expected_write_id: &str,
        previous_revision: u64,
        new_revision: u64,
        target: VaultWriteTarget,
        verified_content: VerifiedCreateContent,
    ) -> Result<(), VaultWriteError> {
        self.check_generation(active_generation)?;
        validate_target(&target)?;
        let (bytes, sha256, destination) = match &self.lifecycle {
            VaultWriteLifecycle::RetargetingCreate {
                write_id,
                previous_revision: prior,
                destination,
                bytes,
                sha256,
                ..
            } if write_id == expected_write_id && *prior == previous_revision => {
                (*bytes, sha256.clone(), destination)
            }
            _ => return Err(VaultWriteError::RecordMismatch),
        };
        if new_revision <= previous_revision
            || target != *destination
            || verified_content.bytes != bytes
            || verified_content.sha256 != sha256
            || self.data.metadata().map_err(|_| VaultWriteError::Io)?.len() != bytes
            || hash_file(&mut self.data)? != sha256
        {
            return Err(VaultWriteError::ChangedDuringUpload);
        }
        let lifecycle = VaultWriteLifecycle::Queued {
            bytes,
            sha256,
            write_id: expected_write_id.to_owned(),
            revision: new_revision,
            uncertain: false,
        };
        write_manifest_replace(
            &self.record_dir,
            &PersistentRecord {
                schema: SCHEMA_VERSION,
                record_id: self.record_id.clone(),
                scope: self.binding.scope.clone(),
                target: target.clone(),
                lifecycle: lifecycle.clone(),
            },
        )?;
        self.binding.target = target;
        self.lifecycle = lifecycle;
        Ok(())
    }

    /// Roll back only the local WAL marker when the authenticated backend
    /// proves the original operation revision is still current.
    pub fn restore_original_create_binding(
        &mut self,
        active_generation: u64,
        expected_write_id: &str,
        revision: u64,
    ) -> Result<(), VaultWriteError> {
        self.check_generation(active_generation)?;
        let (bytes, sha256) = match &self.lifecycle {
            VaultWriteLifecycle::RetargetingCreate {
                write_id,
                previous_revision,
                bytes,
                sha256,
                ..
            } if write_id == expected_write_id && *previous_revision == revision => {
                (*bytes, sha256.clone())
            }
            _ => return Err(VaultWriteError::RecordMismatch),
        };
        if self.data.metadata().map_err(|_| VaultWriteError::Io)?.len() != bytes
            || hash_file(&mut self.data)? != sha256
        {
            return Err(VaultWriteError::ChangedDuringUpload);
        }
        let lifecycle = VaultWriteLifecycle::Queued {
            bytes,
            sha256,
            write_id: expected_write_id.to_owned(),
            revision,
            uncertain: false,
        };
        write_manifest_replace(
            &self.record_dir,
            &PersistentRecord::from_binding(&self.binding, lifecycle.clone()),
        )?;
        self.lifecycle = lifecycle;
        Ok(())
    }

    /// Rebind an unchanged, never-attempted create after the remote encrypted
    /// journal has atomically retargeted that exact operation. The data file
    /// is never replaced or removed; any mismatch leaves its prior manifest
    /// intact for recovery.
    pub fn retarget_never_attempted_create(
        &mut self,
        active_generation: u64,
        expected_write_id: &str,
        expected_revision: u64,
        new_revision: u64,
        target: VaultWriteTarget,
    ) -> Result<(), VaultWriteError> {
        self.check_generation(active_generation)?;
        validate_target(&target)?;
        if !matches!(self.binding.target.condition(), WriteCondition::Absent)
            || self.binding.target.parent_ref().is_none()
            || !matches!(target.condition(), WriteCondition::Absent)
            || target.parent_ref().is_none()
            || new_revision <= expected_revision
        {
            return Err(VaultWriteError::RecordMismatch);
        }
        let (bytes, sha256) = match &self.lifecycle {
            VaultWriteLifecycle::Queued {
                bytes,
                sha256,
                write_id,
                revision,
                uncertain: false,
            } if write_id == expected_write_id && *revision == expected_revision => {
                (*bytes, sha256.clone())
            }
            _ => return Err(VaultWriteError::RecordMismatch),
        };
        if self.data.metadata().map_err(|_| VaultWriteError::Io)?.len() != bytes
            || hash_file(&mut self.data)? != sha256
        {
            return Err(VaultWriteError::ChangedDuringUpload);
        }
        let lifecycle = VaultWriteLifecycle::Queued {
            bytes,
            sha256,
            write_id: expected_write_id.to_owned(),
            revision: new_revision,
            uncertain: false,
        };
        write_manifest_replace(
            &self.record_dir,
            &PersistentRecord {
                schema: SCHEMA_VERSION,
                record_id: self.record_id.clone(),
                scope: self.binding.scope.clone(),
                target: target.clone(),
                lifecycle: lifecycle.clone(),
            },
        )?;
        self.binding.target = target;
        self.lifecycle = lifecycle;
        Ok(())
    }

    pub fn len(&self, active_generation: u64) -> Result<u64, VaultWriteError> {
        self.check_generation(active_generation)?;
        self.data
            .metadata()
            .map(|meta| meta.len())
            .map_err(|_| VaultWriteError::Io)
    }

    pub fn read_at(
        &mut self,
        offset: u64,
        buffer: &mut [u8],
        active_generation: u64,
    ) -> Result<usize, VaultWriteError> {
        self.check_generation(active_generation)?;
        self.data
            .seek(SeekFrom::Start(offset))
            .map_err(|_| VaultWriteError::Io)?;
        self.data.read(buffer).map_err(|_| VaultWriteError::Io)
    }

    pub fn write_at(
        &mut self,
        offset: u64,
        bytes: &[u8],
        active_generation: u64,
    ) -> Result<usize, VaultWriteError> {
        self.check_generation(active_generation)?;
        let end = offset
            .checked_add(bytes.len() as u64)
            .filter(|end| *end <= MAX_VAULT_WORKING_COPY_BYTES)
            .ok_or(VaultWriteError::SizeLimit)?;
        let current = self.data.metadata().map_err(|_| VaultWriteError::Io)?.len();
        if end.max(current) > MAX_VAULT_WORKING_COPY_BYTES {
            return Err(VaultWriteError::SizeLimit);
        }
        self.mark_dirty_before_mutation()?;
        self.data
            .seek(SeekFrom::Start(offset))
            .map_err(|_| VaultWriteError::Io)?;
        let written = self.data.write(bytes).map_err(|_| VaultWriteError::Io)?;
        self.data.sync_data().map_err(|_| VaultWriteError::Io)?;
        sync_dir(&self.record_dir)?;
        Ok(written)
    }

    pub fn truncate(&mut self, size: u64, active_generation: u64) -> Result<(), VaultWriteError> {
        self.check_generation(active_generation)?;
        if size > MAX_VAULT_WORKING_COPY_BYTES {
            return Err(VaultWriteError::SizeLimit);
        }
        self.mark_dirty_before_mutation()?;
        self.data.set_len(size).map_err(|_| VaultWriteError::Io)?;
        self.data.sync_all().map_err(|_| VaultWriteError::Io)?;
        sync_dir(&self.record_dir)
    }

    pub fn sync(&mut self, active_generation: u64) -> Result<(), VaultWriteError> {
        self.check_generation(active_generation)?;
        self.data.sync_all().map_err(|_| VaultWriteError::Io)?;
        sync_dir(&self.record_dir)
    }

    /// Stream one immutable working-copy snapshot to the backend. The caller
    /// must hold its handle mutex and route lease for the entire call. A
    /// successful backend result is persisted as committed only after basic
    /// identity/size/ETag checks; uncertain failures leave the record dirty.
    pub fn commit_snapshot(
        &mut self,
        active_generation: u64,
        upload: impl FnOnce(&mut dyn VaultWriteSource, u64) -> Result<RemoteEntry, CloudError>,
    ) -> Result<RemoteEntry, VaultWriteError> {
        match self.commit_snapshot_outcome(active_generation, |source, length| {
            upload(source, length).map(VaultUploadOutcome::Committed)
        })? {
            VaultUploadOutcome::Committed(entry) => Ok(entry),
            VaultUploadOutcome::Queued { .. }
            | VaultUploadOutcome::QueuedCreate { .. }
            | VaultUploadOutcome::BuildingCreate { .. } => Err(VaultWriteError::CorruptRecord),
        }
    }

    pub fn commit_snapshot_outcome(
        &mut self,
        active_generation: u64,
        upload: impl FnOnce(&mut dyn VaultWriteSource, u64) -> Result<VaultUploadOutcome, CloudError>,
    ) -> Result<VaultUploadOutcome, VaultWriteError> {
        self.check_generation(active_generation)?;
        self.mark_dirty_before_mutation()?;
        self.data.sync_all().map_err(|_| VaultWriteError::Io)?;
        let length = self.data.metadata().map_err(|_| VaultWriteError::Io)?.len();
        if length > MAX_VAULT_WORKING_COPY_BYTES {
            return Err(VaultWriteError::SizeLimit);
        }
        let mut snapshot_file = Builder::new()
            .prefix(".upload-snapshot-")
            .rand_bytes(16)
            .tempfile_in(&self.record_dir)
            .map_err(|_| VaultWriteError::Io)?;
        set_private_file(snapshot_file.as_file())?;
        self.data
            .seek(SeekFrom::Start(0))
            .map_err(|_| VaultWriteError::Io)?;
        copy_bounded(&mut self.data, snapshot_file.as_file_mut())?;
        snapshot_file
            .as_file()
            .sync_all()
            .map_err(|_| VaultWriteError::Io)?;
        let snapshot_len = snapshot_file
            .as_file()
            .metadata()
            .map_err(|_| VaultWriteError::Io)?
            .len();
        let snapshot_hash = hash_file(snapshot_file.as_file_mut())?;
        if snapshot_len != length || hash_file(&mut self.data)? != snapshot_hash {
            return Err(VaultWriteError::ChangedDuringUpload);
        }
        snapshot_file
            .as_file_mut()
            .seek(SeekFrom::Start(0))
            .map_err(|_| VaultWriteError::Io)?;
        let outcome =
            upload(snapshot_file.as_file_mut(), length).map_err(VaultWriteError::Backend)?;
        self.check_generation(active_generation)?;
        let result = match &outcome {
            VaultUploadOutcome::Committed(entry)
            | VaultUploadOutcome::Queued { entry, .. }
            | VaultUploadOutcome::QueuedCreate { entry, .. }
            | VaultUploadOutcome::BuildingCreate { entry, .. } => entry,
        };
        if result.directory
            || result.id.is_empty()
            || result.size != length
            || result.etag.is_empty()
            || validate_condition(&WriteCondition::Match(result.etag.clone())).is_err()
        {
            return Err(VaultWriteError::CorruptRecord);
        }
        if hash_file(&mut self.data)? != snapshot_hash
            || self.data.metadata().map_err(|_| VaultWriteError::Io)?.len() != length
        {
            let (next_condition, lifecycle) = match &outcome {
                VaultUploadOutcome::QueuedCreate {
                    write_id,
                    revision,
                    uncertain,
                    ..
                } => (
                    self.binding.target.condition.clone(),
                    VaultWriteLifecycle::DirtyQueued {
                        write_id: write_id.clone(),
                        revision: *revision,
                        uncertain: *uncertain,
                    },
                ),
                VaultUploadOutcome::Queued {
                    write_id,
                    revision,
                    uncertain,
                    ..
                } => (
                    WriteCondition::Match(result.etag.clone()),
                    VaultWriteLifecycle::DirtyQueued {
                        write_id: write_id.clone(),
                        revision: *revision,
                        uncertain: *uncertain,
                    },
                ),
                VaultUploadOutcome::BuildingCreate {
                    write_id, revision, ..
                } => (
                    self.binding.target.condition.clone(),
                    VaultWriteLifecycle::DirtyBuildingCreate {
                        write_id: write_id.clone(),
                        revision: *revision,
                    },
                ),
                VaultUploadOutcome::Committed(entry) => (
                    WriteCondition::Match(entry.etag.clone()),
                    VaultWriteLifecycle::Dirty,
                ),
            };
            let mut next_target = self.binding.target.with_condition(next_condition)?;
            if matches!(outcome, VaultUploadOutcome::Committed(_)) {
                next_target = next_target.without_parent_ref()?;
            }
            write_manifest_replace(
                &self.record_dir,
                &PersistentRecord {
                    schema: SCHEMA_VERSION,
                    record_id: self.record_id.clone(),
                    scope: self.binding.scope.clone(),
                    target: next_target.clone(),
                    lifecycle: lifecycle.clone(),
                },
            )?;
            self.binding.target = next_target;
            self.lifecycle = lifecycle;
            return Err(VaultWriteError::ChangedDuringUpload);
        }
        let next_condition = match &outcome {
            VaultUploadOutcome::QueuedCreate { .. } | VaultUploadOutcome::BuildingCreate { .. } => {
                self.binding.target.condition.clone()
            }
            VaultUploadOutcome::Committed(_) | VaultUploadOutcome::Queued { .. } => {
                WriteCondition::Match(result.etag.clone())
            }
        };
        let mut next_target = self.binding.target.with_condition(next_condition)?;
        if matches!(outcome, VaultUploadOutcome::Committed(_)) {
            next_target = next_target.without_parent_ref()?;
        }
        let lifecycle = match &outcome {
            VaultUploadOutcome::Committed(entry) => VaultWriteLifecycle::Committed {
                bytes: length,
                sha256: snapshot_hash,
                etag: entry.etag.clone(),
            },
            VaultUploadOutcome::Queued {
                write_id,
                revision,
                uncertain,
                ..
            } => VaultWriteLifecycle::Queued {
                bytes: length,
                sha256: snapshot_hash,
                write_id: write_id.clone(),
                revision: *revision,
                uncertain: *uncertain,
            },
            VaultUploadOutcome::QueuedCreate {
                write_id,
                revision,
                uncertain,
                ..
            } => VaultWriteLifecycle::Queued {
                bytes: length,
                sha256: snapshot_hash,
                write_id: write_id.clone(),
                revision: *revision,
                uncertain: *uncertain,
            },
            VaultUploadOutcome::BuildingCreate {
                write_id, revision, ..
            } => VaultWriteLifecycle::BuildingCreate {
                write_id: write_id.clone(),
                revision: *revision,
            },
        };
        let persistent = PersistentRecord {
            schema: SCHEMA_VERSION,
            record_id: self.record_id.clone(),
            scope: self.binding.scope.clone(),
            target: next_target.clone(),
            lifecycle: lifecycle.clone(),
        };
        write_manifest_replace(&self.record_dir, &persistent)?;
        self.binding.target = next_target;
        self.lifecycle = lifecycle;
        Ok(outcome)
    }

    /// Remove only a pristine baseline or a committed snapshot whose bytes,
    /// manifest, and record directory still match the verified state. Dirty
    /// and initializing records are intentionally retained.
    pub fn retire_if_unchanged(mut self, active_generation: u64) -> Result<bool, VaultWriteError> {
        self.check_generation(active_generation)?;
        let (expected_bytes, expected_hash) = match &self.lifecycle {
            VaultWriteLifecycle::CleanBaseline { bytes, sha256 }
            | VaultWriteLifecycle::Committed { bytes, sha256, .. } => (*bytes, sha256.clone()),
            VaultWriteLifecycle::Queued { .. } => return Ok(false),
            VaultWriteLifecycle::Initializing
            | VaultWriteLifecycle::Dirty
            | VaultWriteLifecycle::BuildingCreate { .. }
            | VaultWriteLifecycle::DirtyBuildingCreate { .. }
            | VaultWriteLifecycle::DirtyQueued { .. }
            | VaultWriteLifecycle::CancelPendingCreate { .. }
            | VaultWriteLifecycle::RetargetingCreate { .. } => return Ok(false),
        };
        let actual_bytes = self.data.metadata().map_err(|_| VaultWriteError::Io)?.len();
        let actual_hash = hash_file(&mut self.data)?;
        if actual_bytes != expected_bytes || actual_hash != expected_hash {
            return Ok(false);
        }
        let manifest = read_manifest(&self.record_dir)?;
        if manifest.record_id != self.record_id
            || manifest.scope != self.binding.scope
            || manifest.target != self.binding.target
            || manifest.lifecycle != self.lifecycle
        {
            return Err(VaultWriteError::CorruptRecord);
        }
        let data_path = self.record_dir.join(DATA_NAME);
        let data_before =
            fs::symlink_metadata(&data_path).map_err(|_| VaultWriteError::CorruptRecord)?;
        let opened = self.data.metadata().map_err(|_| VaultWriteError::Io)?;
        if !same_identity(&data_before, &opened) {
            return Err(VaultWriteError::CorruptRecord);
        }
        let dir_before =
            fs::symlink_metadata(&self.record_dir).map_err(|_| VaultWriteError::CorruptRecord)?;
        drop(self.data);
        fs::remove_file(&data_path).map_err(|_| VaultWriteError::Io)?;
        fs::remove_file(self.record_dir.join(MANIFEST_NAME)).map_err(|_| VaultWriteError::Io)?;
        sync_dir(&self.record_dir)?;
        let dir_after =
            fs::symlink_metadata(&self.record_dir).map_err(|_| VaultWriteError::CorruptRecord)?;
        if !same_identity(&dir_before, &dir_after) {
            return Err(VaultWriteError::CorruptRecord);
        }
        fs::remove_dir(&self.record_dir).map_err(|_| VaultWriteError::Io)?;
        sync_dir(
            self.record_dir
                .parent()
                .ok_or(VaultWriteError::CorruptRecord)?,
        )?;
        Ok(true)
    }

    fn mark_dirty_before_mutation(&mut self) -> Result<(), VaultWriteError> {
        let lifecycle = match &self.lifecycle {
            VaultWriteLifecycle::Dirty
            | VaultWriteLifecycle::DirtyBuildingCreate { .. }
            | VaultWriteLifecycle::DirtyQueued { .. } => return Ok(()),
            VaultWriteLifecycle::BuildingCreate { write_id, revision } => {
                VaultWriteLifecycle::DirtyBuildingCreate {
                    write_id: write_id.clone(),
                    revision: *revision,
                }
            }
            VaultWriteLifecycle::Queued {
                write_id,
                revision,
                uncertain,
                ..
            } => VaultWriteLifecycle::DirtyQueued {
                write_id: write_id.clone(),
                revision: *revision,
                uncertain: *uncertain,
            },
            VaultWriteLifecycle::CancelPendingCreate { .. } => {
                return Err(VaultWriteError::RecordMismatch);
            }
            VaultWriteLifecycle::Initializing
            | VaultWriteLifecycle::RetargetingCreate { .. }
            | VaultWriteLifecycle::CleanBaseline { .. }
            | VaultWriteLifecycle::Committed { .. } => VaultWriteLifecycle::Dirty,
        };
        let persistent = PersistentRecord {
            schema: SCHEMA_VERSION,
            record_id: self.record_id.clone(),
            scope: self.binding.scope.clone(),
            target: self.binding.target.clone(),
            lifecycle: lifecycle.clone(),
        };
        write_manifest_replace(&self.record_dir, &persistent)?;
        self.lifecycle = lifecycle;
        Ok(())
    }

    fn check_generation(&self, active_generation: u64) -> Result<(), VaultWriteError> {
        validate_generation(&self.binding, active_generation)
    }

    fn retire_verified_record(self, active_generation: u64) -> Result<bool, VaultWriteError> {
        self.check_generation(active_generation)?;
        let manifest = read_manifest(&self.record_dir)?;
        if manifest.record_id != self.record_id
            || manifest.scope != self.binding.scope
            || manifest.target != self.binding.target
            || manifest.lifecycle != self.lifecycle
        {
            return Err(VaultWriteError::CorruptRecord);
        }
        let data_path = self.record_dir.join(DATA_NAME);
        let data_before =
            fs::symlink_metadata(&data_path).map_err(|_| VaultWriteError::CorruptRecord)?;
        let opened = self.data.metadata().map_err(|_| VaultWriteError::Io)?;
        if !same_identity(&data_before, &opened) {
            return Err(VaultWriteError::CorruptRecord);
        }
        let dir_before =
            fs::symlink_metadata(&self.record_dir).map_err(|_| VaultWriteError::CorruptRecord)?;
        drop(self.data);
        fs::remove_file(&data_path).map_err(|_| VaultWriteError::Io)?;
        fs::remove_file(self.record_dir.join(MANIFEST_NAME)).map_err(|_| VaultWriteError::Io)?;
        sync_dir(&self.record_dir)?;
        let dir_after =
            fs::symlink_metadata(&self.record_dir).map_err(|_| VaultWriteError::CorruptRecord)?;
        if !same_identity(&dir_before, &dir_after) {
            return Err(VaultWriteError::CorruptRecord);
        }
        fs::remove_dir(&self.record_dir).map_err(|_| VaultWriteError::Io)?;
        sync_dir(
            self.record_dir
                .parent()
                .ok_or(VaultWriteError::CorruptRecord)?,
        )?;
        Ok(true)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PersistentRecord {
    schema: u32,
    record_id: String,
    scope: VaultWriteScope,
    target: VaultWriteTarget,
    lifecycle: VaultWriteLifecycle,
}

impl PersistentRecord {
    fn from_binding(binding: &VaultWriteBinding, lifecycle: VaultWriteLifecycle) -> Self {
        // Record ID is filled after the tempfile has reserved its unique name.
        Self {
            schema: SCHEMA_VERSION,
            record_id: String::new(),
            scope: binding.scope.clone(),
            target: binding.target.clone(),
            lifecycle,
        }
    }

    fn matches(&self, binding: &VaultWriteBinding) -> bool {
        self.schema == SCHEMA_VERSION
            && self.scope == binding.scope
            && self.target == binding.target
    }
}

fn canonical_origin(input: &str) -> Result<String, VaultWriteError> {
    if input.len() > MAX_ORIGIN_BYTES
        || input.is_empty()
        || input.bytes().any(|b| b.is_ascii_control())
    {
        return Err(VaultWriteError::InvalidBinding);
    }
    let parsed = Url::parse(input).map_err(|_| VaultWriteError::InvalidBinding)?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(VaultWriteError::InvalidBinding);
    }
    let mut origin = parsed.origin().ascii_serialization();
    // Url::origin omits the trailing slash and normalizes scheme/host/default port.
    if origin.ends_with('/') {
        origin.pop();
    }
    Ok(origin)
}

fn validate_identifier(value: &str) -> Result<(), VaultWriteError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        Err(VaultWriteError::InvalidBinding)
    } else {
        Ok(())
    }
}

fn validate_scope(scope: &VaultWriteScope) -> Result<(), VaultWriteError> {
    validate_identifier(&scope.account_id)?;
    validate_identifier(&scope.space_id)?;
    validate_identifier(&scope.root_resource_id)?;
    if canonical_origin(&scope.server_origin)? != scope.server_origin {
        return Err(VaultWriteError::InvalidBinding);
    }
    Ok(())
}

fn validate_virtual_path(path: &str) -> Result<(), VaultWriteError> {
    if path.is_empty()
        || path.len() > MAX_TARGET_BYTES
        || !path.starts_with('/')
        || path
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'\\')
        || path
            .split('/')
            .skip(1)
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(VaultWriteError::InvalidTarget);
    }
    Ok(())
}

fn validate_target(target: &VaultWriteTarget) -> Result<(), VaultWriteError> {
    validate_opaque_target(&target.opaque_relative_target)?;
    validate_condition(&target.condition)?;
    if let Some(parent_ref) = &target.parent_ref {
        validate_parent_ref(parent_ref)?;
    }
    Ok(())
}

fn validate_parent_ref(parent_ref: &VaultParentRef) -> Result<(), VaultWriteError> {
    match parent_ref {
        VaultParentRef::Stable { resource_id } => {
            validate_identifier(resource_id)?;
            if resource_id.starts_with("raiun-pending-") {
                return Err(VaultWriteError::InvalidBinding);
            }
            Ok(())
        }
        VaultParentRef::PendingCreate { write_id, revision } => {
            validate_identifier(write_id)?;
            if *revision == 0 {
                return Err(VaultWriteError::InvalidBinding);
            }
            Ok(())
        }
    }
}

fn validate_opaque_target(value: &str) -> Result<(), VaultWriteError> {
    if value.is_empty()
        || value.len() > MAX_TARGET_BYTES
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\\')
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(VaultWriteError::InvalidTarget);
    }
    let path = Path::new(value);
    if value
        .split('/')
        .any(|segment| matches!(segment, "." | ".."))
        || path.components().any(|component| {
            matches!(
                component,
                Component::RootDir
                    | Component::ParentDir
                    | Component::CurDir
                    | Component::Prefix(_)
            )
        })
        || value.split('/').any(str::is_empty)
    {
        return Err(VaultWriteError::InvalidTarget);
    }
    Ok(())
}

fn validate_condition(condition: &WriteCondition) -> Result<(), VaultWriteError> {
    match condition {
        WriteCondition::Absent => Ok(()),
        WriteCondition::Match(etag)
            if !etag.is_empty()
                && etag.len() <= MAX_ETAG_BYTES
                && !etag.bytes().any(|byte| byte.is_ascii_control()) =>
        {
            Ok(())
        }
        WriteCondition::Match(_) => Err(VaultWriteError::InvalidCondition),
    }
}

fn validate_generation(binding: &VaultWriteBinding, active: u64) -> Result<(), VaultWriteError> {
    if active != binding.route_generation {
        Err(VaultWriteError::StaleGeneration)
    } else {
        Ok(())
    }
}

fn copy_bounded<R: Read>(reader: &mut R, output: &mut File) -> Result<(), VaultWriteError> {
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let count = reader.read(&mut buffer).map_err(|_| VaultWriteError::Io)?;
        if count == 0 {
            return Ok(());
        }
        total = total
            .checked_add(count as u64)
            .filter(|length| *length <= MAX_VAULT_WORKING_COPY_BYTES)
            .ok_or(VaultWriteError::SizeLimit)?;
        output
            .write_all(&buffer[..count])
            .map_err(|_| VaultWriteError::Io)?;
    }
}

fn lifecycle_for_data(
    data: &mut File,
    kind: LifecycleKind,
) -> Result<VaultWriteLifecycle, VaultWriteError> {
    let bytes = data.metadata().map_err(|_| VaultWriteError::Io)?.len();
    let sha256 = hash_file(data)?;
    Ok(match kind {
        LifecycleKind::CleanBaseline => VaultWriteLifecycle::CleanBaseline { bytes, sha256 },
    })
}

enum LifecycleKind {
    CleanBaseline,
}

fn hash_file(file: &mut File) -> Result<String, VaultWriteError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| VaultWriteError::Io)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|_| VaultWriteError::Io)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| VaultWriteError::Io)?;
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn validate_lifecycle(state: &VaultWriteLifecycle) -> Result<(), VaultWriteError> {
    match state {
        VaultWriteLifecycle::Initializing | VaultWriteLifecycle::Dirty => Ok(()),
        VaultWriteLifecycle::RetargetingCreate {
            write_id,
            previous_revision: revision,
            destination_path,
            destination,
            bytes,
            sha256,
        } => {
            validate_queued_id(write_id)?;
            validate_virtual_path(destination_path)?;
            validate_target(destination)?;
            if *revision == 0
                || *bytes > MAX_VAULT_WORKING_COPY_BYTES
                || sha256.len() != 64
                || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
                || !matches!(destination.condition(), WriteCondition::Absent)
                || destination.parent_ref().is_none()
            {
                return Err(VaultWriteError::CorruptRecord);
            }
            Ok(())
        }
        VaultWriteLifecycle::BuildingCreate { write_id, revision }
        | VaultWriteLifecycle::DirtyBuildingCreate { write_id, revision }
        | VaultWriteLifecycle::DirtyQueued {
            write_id, revision, ..
        } => {
            validate_queued_id(write_id)?;
            if *revision == 0 {
                return Err(VaultWriteError::CorruptRecord);
            }
            Ok(())
        }
        VaultWriteLifecycle::CancelPendingCreate {
            write_id,
            revision,
            bytes,
            sha256,
        } => {
            validate_queued_id(write_id)?;
            if *revision == 0
                || *bytes > MAX_VAULT_WORKING_COPY_BYTES
                || sha256.len() != 64
                || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(VaultWriteError::CorruptRecord);
            }
            Ok(())
        }
        VaultWriteLifecycle::CleanBaseline { bytes, sha256 }
        | VaultWriteLifecycle::Committed { bytes, sha256, .. }
        | VaultWriteLifecycle::Queued { bytes, sha256, .. }
            if *bytes <= MAX_VAULT_WORKING_COPY_BYTES
                && sha256.len() == 64
                && sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            if let VaultWriteLifecycle::Committed { etag, .. } = state {
                validate_condition(&WriteCondition::Match(etag.clone()))?;
            }
            if let VaultWriteLifecycle::Queued {
                write_id, revision, ..
            } = state
            {
                validate_queued_id(write_id)?;
                if *revision == 0 {
                    return Err(VaultWriteError::CorruptRecord);
                }
            }
            Ok(())
        }
        _ => Err(VaultWriteError::CorruptRecord),
    }
}

fn validate_create_cancellation(
    cancellation: &PendingVaultCreateCancellation,
) -> Result<(), VaultWriteError> {
    validate_record_id(&cancellation.record_id)?;
    validate_scope(&cancellation.scope)?;
    validate_target(&cancellation.target)?;
    validate_queued_id(&cancellation.write_id)?;
    if cancellation.revision == 0
        || cancellation.bytes > MAX_VAULT_WORKING_COPY_BYTES
        || cancellation.sha256.len() != 64
        || !cancellation
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || !matches!(cancellation.target.condition(), WriteCondition::Absent)
        || cancellation.target.parent_ref().is_none()
        || !valid_virtual_path(&cancellation.path)
    {
        return Err(VaultWriteError::CorruptRecord);
    }
    Ok(())
}

fn valid_virtual_path(path: &str) -> bool {
    path.len() <= MAX_TARGET_BYTES
        && path.starts_with('/')
        && path != "/"
        && !path.contains('\0')
        && !path.contains("//")
        && !path
            .split('/')
            .any(|component| component == "." || component == "..")
}

fn directory_retarget_path(root: &Path, write_id: &str) -> Result<PathBuf, VaultWriteError> {
    validate_queued_id(write_id)?;
    Ok(root.join(format!("{RETARGET_SUBTREE_PREFIX}{write_id}.json")))
}

fn validate_directory_retarget(
    retarget: &PendingVaultDirectoryRetarget,
) -> Result<(), VaultWriteError> {
    validate_scope(&retarget.scope)?;
    validate_queued_id(&retarget.root_write_id)?;
    validate_virtual_path(&retarget.source_path)?;
    validate_virtual_path(&retarget.destination_path)?;
    if retarget.source_path == "/"
        || retarget.destination_path == "/"
        || retarget.source_path == retarget.destination_path
        || retarget
            .destination_path
            .starts_with(&format!("{}/", retarget.source_path.trim_end_matches('/')))
        || retarget.source_path.starts_with(&format!(
            "{}/",
            retarget.destination_path.trim_end_matches('/')
        ))
        || retarget.root_previous_revision == 0
        || retarget.root_revision != retarget.root_previous_revision + 1
        || retarget.rows.is_empty()
        || retarget.rows.len() > 64
    {
        return Err(VaultWriteError::InvalidBinding);
    }
    let mut ids = std::collections::HashSet::new();
    let mut records = std::collections::HashSet::new();
    let mut total_bytes = 0u64;
    let mut root_found = false;
    for row in &retarget.rows {
        validate_queued_id(&row.write_id)?;
        validate_virtual_path(&row.old_path)?;
        validate_virtual_path(&row.path)?;
        if let Some(old_target) = &row.old_target {
            validate_target(old_target)?;
        }
        validate_target(&row.target)?;
        if !ids.insert(row.write_id.as_str())
            || row.previous_revision == 0
            || row.revision != row.previous_revision + 1
            || row
                .old_target
                .as_ref()
                .is_some_and(|target| !matches!(target.condition(), WriteCondition::Absent))
            || !matches!(row.target.condition(), WriteCondition::Absent)
        {
            return Err(VaultWriteError::InvalidBinding);
        }
        let suffix = row
            .old_path
            .strip_prefix(&retarget.source_path)
            .filter(|suffix| suffix.is_empty() || suffix.starts_with('/'))
            .ok_or(VaultWriteError::InvalidBinding)?;
        if row.path != format!("{}{suffix}", retarget.destination_path) {
            return Err(VaultWriteError::InvalidBinding);
        }
        match row.operation {
            PendingVaultRetargetOperation::CreateDirectory => {
                if row.write_id == retarget.root_write_id {
                    root_found = row.old_path == retarget.source_path
                        && row.path == retarget.destination_path
                        && row.previous_revision == retarget.root_previous_revision
                        && row.revision == retarget.root_revision;
                }
                if row.record_id.is_some() || row.bytes != 0 || !row.sha256.is_empty() {
                    return Err(VaultWriteError::InvalidBinding);
                }
            }
            PendingVaultRetargetOperation::CreateFile => {
                if row.old_target.is_none() {
                    return Err(VaultWriteError::InvalidBinding);
                }
                let record_id = row
                    .record_id
                    .as_deref()
                    .ok_or(VaultWriteError::InvalidBinding)?;
                validate_record_id(record_id)?;
                if !records.insert(record_id)
                    || row.sha256.len() != 64
                    || !row.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(VaultWriteError::InvalidBinding);
                }
                total_bytes = total_bytes
                    .checked_add(row.bytes)
                    .filter(|bytes| *bytes <= 64 * 1024 * 1024)
                    .ok_or(VaultWriteError::SizeLimit)?;
            }
        }
    }
    if !root_found {
        return Err(VaultWriteError::InvalidBinding);
    }
    Ok(())
}

fn write_directory_retarget(
    root: &Path,
    retarget: &PendingVaultDirectoryRetarget,
) -> Result<(), VaultWriteError> {
    validate_directory_retarget(retarget)?;
    validate_private_dir(root)?;
    let bytes = serde_json::to_vec(retarget).map_err(|_| VaultWriteError::Io)?;
    if bytes.len() as u64 > 1024 * 1024 {
        return Err(VaultWriteError::InvalidBinding);
    }
    let destination = directory_retarget_path(root, &retarget.root_write_id)?;
    let mut tmp = Builder::new()
        .prefix(".retarget-subtree-")
        .tempfile_in(root)
        .map_err(|_| VaultWriteError::Io)?;
    set_private_file(tmp.as_file())?;
    tmp.write_all(&bytes).map_err(|_| VaultWriteError::Io)?;
    tmp.as_file().sync_all().map_err(|_| VaultWriteError::Io)?;
    match tmp.persist_noclobber(&destination) {
        Ok(_) => sync_dir(root),
        Err(error) if error.error.kind() == IoErrorKind::AlreadyExists => {
            if read_directory_retarget(&destination)? == *retarget {
                Ok(())
            } else {
                Err(VaultWriteError::CorruptRecord)
            }
        }
        Err(_) => Err(VaultWriteError::Io),
    }
}

fn read_directory_retarget(path: &Path) -> Result<PendingVaultDirectoryRetarget, VaultWriteError> {
    let before = fs::symlink_metadata(path).map_err(|_| VaultWriteError::CorruptRecord)?;
    if !before.is_file() || before.file_type().is_symlink() || before.len() > 1024 * 1024 {
        return Err(VaultWriteError::CorruptRecord);
    }
    validate_private_file_metadata(&before).map_err(|_| VaultWriteError::CorruptRecord)?;
    let file = open_private_read(path)?;
    let opened = file.metadata().map_err(|_| VaultWriteError::Io)?;
    if !same_identity(&before, &opened) || opened.len() != before.len() {
        return Err(VaultWriteError::CorruptRecord);
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| VaultWriteError::Io)?;
    if bytes.len() as u64 != before.len() {
        return Err(VaultWriteError::CorruptRecord);
    }
    let after = fs::symlink_metadata(path).map_err(|_| VaultWriteError::CorruptRecord)?;
    if !same_identity(&before, &after) || after.len() != before.len() {
        return Err(VaultWriteError::CorruptRecord);
    }
    let retarget: PendingVaultDirectoryRetarget =
        serde_json::from_slice(&bytes).map_err(|_| VaultWriteError::CorruptRecord)?;
    validate_directory_retarget(&retarget)?;
    Ok(retarget)
}

fn cancellation_tombstone_path(root: &Path, record_id: &str) -> Result<PathBuf, VaultWriteError> {
    validate_record_id(record_id)?;
    Ok(root.join(format!("{CANCEL_CREATE_PREFIX}{record_id}.json")))
}

fn write_create_cancellation_tombstone(
    root: &Path,
    cancellation: &PendingVaultCreateCancellation,
) -> Result<(), VaultWriteError> {
    validate_create_cancellation(cancellation)?;
    validate_private_dir(root)?;
    let destination = cancellation_tombstone_path(root, &cancellation.record_id)?;
    match fs::symlink_metadata(&destination) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(VaultWriteError::CorruptRecord);
            }
            let existing = read_create_cancellation(&destination)?;
            return if existing == *cancellation {
                Ok(())
            } else {
                Err(VaultWriteError::CorruptRecord)
            };
        }
        Err(error) if error.kind() == IoErrorKind::NotFound => {}
        Err(_) => return Err(VaultWriteError::Io),
    }
    let bytes = serde_json::to_vec(cancellation).map_err(|_| VaultWriteError::Io)?;
    if bytes.len() as u64 > MAX_VAULT_WRITE_MANIFEST_BYTES {
        return Err(VaultWriteError::InvalidBinding);
    }
    let mut tmp = Builder::new()
        .prefix(".cancel-create-")
        .tempfile_in(root)
        .map_err(|_| VaultWriteError::Io)?;
    set_private_file(tmp.as_file())?;
    tmp.write_all(&bytes).map_err(|_| VaultWriteError::Io)?;
    tmp.as_file().sync_all().map_err(|_| VaultWriteError::Io)?;
    match tmp.persist_noclobber(&destination) {
        Ok(_) => sync_dir(root),
        Err(error) if error.error.kind() == IoErrorKind::AlreadyExists => {
            let existing = read_create_cancellation(&destination)?;
            if existing == *cancellation {
                Ok(())
            } else {
                Err(VaultWriteError::CorruptRecord)
            }
        }
        Err(_) => Err(VaultWriteError::Io),
    }
}

fn replace_create_cancellation_tombstone(
    root: &Path,
    cancellation: &PendingVaultCreateCancellation,
) -> Result<(), VaultWriteError> {
    validate_create_cancellation(cancellation)?;
    validate_private_dir(root)?;
    let destination = cancellation_tombstone_path(root, &cancellation.record_id)?;
    let current = read_create_cancellation(&destination)?;
    if current.record_id != cancellation.record_id
        || current.scope != cancellation.scope
        || current.target != cancellation.target
        || current.path != cancellation.path
        || current.write_id != cancellation.write_id
        || current.revision != cancellation.revision
        || current.bytes != cancellation.bytes
        || current.sha256 != cancellation.sha256
        || current.local_retired
    {
        return Err(VaultWriteError::CorruptRecord);
    }
    let bytes = serde_json::to_vec(cancellation).map_err(|_| VaultWriteError::Io)?;
    if bytes.len() as u64 > MAX_VAULT_WRITE_MANIFEST_BYTES {
        return Err(VaultWriteError::InvalidBinding);
    }
    let mut tmp = Builder::new()
        .prefix(".cancel-create-retired-")
        .tempfile_in(root)
        .map_err(|_| VaultWriteError::Io)?;
    set_private_file(tmp.as_file())?;
    tmp.write_all(&bytes).map_err(|_| VaultWriteError::Io)?;
    tmp.as_file().sync_all().map_err(|_| VaultWriteError::Io)?;
    tmp.persist(&destination).map_err(|_| VaultWriteError::Io)?;
    sync_dir(root)
}

fn read_create_cancellation(
    path: &Path,
) -> Result<PendingVaultCreateCancellation, VaultWriteError> {
    let before = fs::symlink_metadata(path).map_err(|_| VaultWriteError::CorruptRecord)?;
    if !before.is_file()
        || before.file_type().is_symlink()
        || before.len() > MAX_VAULT_WRITE_MANIFEST_BYTES
    {
        return Err(VaultWriteError::CorruptRecord);
    }
    validate_private_file_metadata(&before).map_err(|_| VaultWriteError::CorruptRecord)?;
    let file = open_private_read(path)?;
    let opened = file.metadata().map_err(|_| VaultWriteError::Io)?;
    if !same_identity(&before, &opened) || opened.len() != before.len() {
        return Err(VaultWriteError::CorruptRecord);
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.take(MAX_VAULT_WRITE_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| VaultWriteError::Io)?;
    if bytes.len() as u64 != before.len() {
        return Err(VaultWriteError::CorruptRecord);
    }
    let after = fs::symlink_metadata(path).map_err(|_| VaultWriteError::CorruptRecord)?;
    if !same_identity(&before, &after) || after.len() != before.len() {
        return Err(VaultWriteError::CorruptRecord);
    }
    let cancellation: PendingVaultCreateCancellation =
        serde_json::from_slice(&bytes).map_err(|_| VaultWriteError::CorruptRecord)?;
    validate_create_cancellation(&cancellation)?;
    Ok(cancellation)
}

fn record_id_from_path(path: &Path) -> Result<String, VaultWriteError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(VaultWriteError::Io)?;
    validate_record_id(name)?;
    Ok(name.to_owned())
}

fn validate_record_id(value: &str) -> Result<(), VaultWriteError> {
    if value.starts_with(RECORD_PREFIX)
        && value.len() <= 128
        && value[RECORD_PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        Ok(())
    } else {
        Err(VaultWriteError::InvalidRecordId)
    }
}

fn validate_queued_id(value: &str) -> Result<(), VaultWriteError> {
    if value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(VaultWriteError::CorruptRecord)
    }
}

fn write_manifest(directory: &Path, record: &PersistentRecord) -> Result<(), VaultWriteError> {
    write_manifest_inner(directory, record, false)
}

fn write_manifest_replace(
    directory: &Path,
    record: &PersistentRecord,
) -> Result<(), VaultWriteError> {
    write_manifest_inner(directory, record, true)
}

fn write_manifest_inner(
    directory: &Path,
    record: &PersistentRecord,
    replace: bool,
) -> Result<(), VaultWriteError> {
    let mut record = record.clone();
    record.record_id = record_id_from_path(directory)?;
    let bytes = serde_json::to_vec(&record).map_err(|_| VaultWriteError::Io)?;
    if bytes.len() as u64 > MAX_VAULT_WRITE_MANIFEST_BYTES {
        return Err(VaultWriteError::InvalidBinding);
    }
    let mut tmp = Builder::new()
        .prefix(".manifest-")
        .tempfile_in(directory)
        .map_err(|_| VaultWriteError::Io)?;
    set_private_file(tmp.as_file())?;
    tmp.write_all(&bytes).map_err(|_| VaultWriteError::Io)?;
    tmp.as_file().sync_all().map_err(|_| VaultWriteError::Io)?;
    let destination = directory.join(MANIFEST_NAME);
    if replace {
        tmp.persist(&destination).map_err(|_| VaultWriteError::Io)?;
    } else {
        tmp.persist_noclobber(&destination)
            .map_err(|_| VaultWriteError::Io)?;
    }
    sync_dir(directory)
}

fn read_manifest(directory: &Path) -> Result<PersistentRecord, VaultWriteError> {
    let path = directory.join(MANIFEST_NAME);
    let before = fs::symlink_metadata(&path).map_err(|_| VaultWriteError::CorruptRecord)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(VaultWriteError::CorruptRecord);
    }
    validate_private_file_metadata(&before).map_err(|_| VaultWriteError::CorruptRecord)?;
    if before.len() > MAX_VAULT_WRITE_MANIFEST_BYTES {
        return Err(VaultWriteError::CorruptRecord);
    }
    let file = open_private_read(&path)?;
    let opened = file.metadata().map_err(|_| VaultWriteError::Io)?;
    if !same_identity(&before, &opened) || opened.len() > MAX_VAULT_WRITE_MANIFEST_BYTES {
        return Err(VaultWriteError::CorruptRecord);
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take(MAX_VAULT_WRITE_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| VaultWriteError::Io)?;
    if bytes.len() as u64 > MAX_VAULT_WRITE_MANIFEST_BYTES {
        return Err(VaultWriteError::CorruptRecord);
    }
    let record: PersistentRecord =
        serde_json::from_slice(&bytes).map_err(|_| VaultWriteError::CorruptRecord)?;
    let after = fs::symlink_metadata(&path).map_err(|_| VaultWriteError::CorruptRecord)?;
    if !same_identity(&opened, &after) {
        return Err(VaultWriteError::CorruptRecord);
    }
    validate_record_id(&record.record_id).map_err(|_| VaultWriteError::CorruptRecord)?;
    if record.record_id
        != record_id_from_path(directory).map_err(|_| VaultWriteError::CorruptRecord)?
    {
        return Err(VaultWriteError::CorruptRecord);
    }
    validate_identifier(&record.scope.account_id).map_err(|_| VaultWriteError::CorruptRecord)?;
    validate_identifier(&record.scope.space_id).map_err(|_| VaultWriteError::CorruptRecord)?;
    validate_identifier(&record.scope.root_resource_id)
        .map_err(|_| VaultWriteError::CorruptRecord)?;
    if validate_scope(&record.scope).is_err()
        || record.target.opaque_relative_target.is_empty()
        || validate_target(&record.target).is_err()
        || validate_lifecycle(&record.lifecycle).is_err()
        || matches!(
            &record.lifecycle,
            VaultWriteLifecycle::BuildingCreate { .. }
                | VaultWriteLifecycle::DirtyBuildingCreate { .. }
                if record.target.condition != WriteCondition::Absent
        )
        || matches!(
            &record.lifecycle,
            VaultWriteLifecycle::RetargetingCreate { .. }
                if record.target.condition != WriteCondition::Absent
        )
        || matches!(
            &record.lifecycle,
            VaultWriteLifecycle::CancelPendingCreate { .. }
                if record.target.condition != WriteCondition::Absent
                    || record.target.parent_ref.is_none()
        )
        || matches!(
            &record.lifecycle,
            VaultWriteLifecycle::Committed { etag, .. }
                if record.target.condition != WriteCondition::Match(etag.clone())
        )
    {
        return Err(VaultWriteError::CorruptRecord);
    }
    Ok(record)
}

fn inspect_record(path: &Path, name: &str) -> PendingVaultWrite {
    let bad = |warning| PendingVaultWrite {
        record_id: name.to_owned(),
        scope: None,
        target: None,
        bytes: None,
        lifecycle: None,
        warning: Some(warning),
    };
    if validate_record_id(name).is_err() {
        return bad(VaultWriteWarning::RecordNameMismatch);
    }
    let directory = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => metadata,
        _ => return bad(VaultWriteWarning::UnsafeData),
    };
    let record = match read_manifest(path) {
        Ok(record) if record.record_id == name => record,
        Ok(_) => return bad(VaultWriteWarning::RecordNameMismatch),
        Err(VaultWriteError::CorruptRecord) => {
            let manifest_path = path.join(MANIFEST_NAME);
            return bad(match fs::symlink_metadata(manifest_path) {
                Err(error) if error.kind() == IoErrorKind::NotFound => {
                    VaultWriteWarning::MissingManifest
                }
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                    VaultWriteWarning::UnsafeManifest
                }
                Ok(metadata) if metadata.len() > MAX_VAULT_WRITE_MANIFEST_BYTES => {
                    VaultWriteWarning::ManifestTooLarge
                }
                Ok(_) => VaultWriteWarning::MalformedManifest,
                Err(_) => VaultWriteWarning::UnsafeManifest,
            });
        }
        Err(_) => return bad(VaultWriteWarning::UnsafeManifest),
    };
    let data_path = path.join(DATA_NAME);
    let (bytes, mut warning) = match fs::symlink_metadata(&data_path) {
        Ok(metadata)
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && validate_private_file_metadata(&metadata).is_ok() =>
        {
            (Some(metadata.len()), None)
        }
        Ok(_) => (None, Some(VaultWriteWarning::UnsafeData)),
        Err(error) if error.kind() == IoErrorKind::NotFound => {
            (None, Some(VaultWriteWarning::MissingData))
        }
        Err(_) => (None, Some(VaultWriteWarning::UnsafeData)),
    };
    if warning.is_none() {
        if let Some(length) = bytes {
            if length > MAX_VAULT_WORKING_COPY_BYTES {
                warning = Some(VaultWriteWarning::DataTooLarge);
            } else if matches!(
                &record.lifecycle,
                VaultWriteLifecycle::CleanBaseline { bytes: expected, .. }
                    | VaultWriteLifecycle::Committed { bytes: expected, .. }
                    | VaultWriteLifecycle::Queued { bytes: expected, .. }
                    if *expected != length
            ) {
                warning = Some(VaultWriteWarning::LifecycleMismatch);
            }
        }
    }
    let after = fs::symlink_metadata(path).ok();
    if after
        .as_ref()
        .is_none_or(|after| !same_identity(&directory, after))
    {
        return bad(VaultWriteWarning::UnsafeData);
    }
    PendingVaultWrite {
        record_id: name.to_owned(),
        scope: Some(record.scope),
        target: Some(record.target),
        bytes,
        lifecycle: Some(record.lifecycle),
        warning,
    }
}

fn validate_private_dir(path: &Path) -> Result<(), VaultWriteError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| VaultWriteError::UnsafeDirectory)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(VaultWriteError::UnsafeDirectory);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(VaultWriteError::UnsafeDirectory);
        }
    }
    Ok(())
}

fn validate_private_file_metadata(metadata: &fs::Metadata) -> Result<(), VaultWriteError> {
    if !metadata.is_file() {
        return Err(VaultWriteError::CorruptRecord);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(VaultWriteError::CorruptRecord);
        }
    }
    Ok(())
}

fn set_private_dir(path: &Path) -> Result<(), VaultWriteError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| VaultWriteError::Io)?;
    }
    validate_private_dir(path)
}

fn create_private_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path)
    }
}

fn create_private_file(path: &Path) -> Result<File, VaultWriteError> {
    let mut options = OpenOptions::new();
    options.write(true).read(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path).map_err(|_| VaultWriteError::Io)?;
    set_private_file(&file)?;
    Ok(file)
}

fn open_private_read(path: &Path) -> Result<File, VaultWriteError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options
        .open(path)
        .map_err(|_| VaultWriteError::CorruptRecord)
}

fn open_private_rw(path: &Path) -> Result<File, VaultWriteError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options
        .open(path)
        .map_err(|_| VaultWriteError::CorruptRecord)
}

fn set_private_file(file: &File) -> Result<(), VaultWriteError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| VaultWriteError::Io)?;
    }
    Ok(())
}

fn sync_dir(path: &Path) -> Result<(), VaultWriteError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| VaultWriteError::Io)
}

#[cfg(unix)]
fn same_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len()
        && left.is_file() == right.is_file()
        && left.is_dir() == right.is_dir()
}

#[cfg(test)]
mod tests {
    use super::*;
    use raiun_core::backend::ErrorKind;
    use std::io::Cursor;

    fn remote_entry(size: u64, etag: &str) -> RemoteEntry {
        RemoteEntry {
            id: "resource-1".into(),
            path: "/notes.txt".into(),
            directory: false,
            size,
            etag: etag.into(),
            modified_unix: 1,
            writable: true,
            encrypted: false,
        }
    }

    fn scope() -> VaultWriteScope {
        VaultWriteScope::new("account-a", "HTTPS://Example.COM:443/", "space-1", "root-1")
            .expect("valid scope")
    }

    fn binding(generation: u64) -> VaultWriteBinding {
        VaultWriteBinding::new(
            scope(),
            VaultWriteTarget::new(
                "encrypted/opaque-name",
                WriteCondition::Match("etag-1".into()),
            )
            .expect("valid target"),
            generation,
        )
        .expect("valid binding")
    }

    fn absent_binding(generation: u64) -> VaultWriteBinding {
        VaultWriteBinding::new(
            scope(),
            VaultWriteTarget::new("encrypted/new-name", WriteCondition::Absent)
                .expect("valid create target"),
            generation,
        )
        .expect("valid create binding")
    }

    fn spool() -> (tempfile::TempDir, VaultWriteSpool) {
        let temp = tempfile::tempdir().expect("temporary profile directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
                .expect("restrict profile directory");
        }
        let spool = VaultWriteSpool::open(temp.path()).expect("private spool");
        (temp, spool)
    }

    #[test]
    fn durable_record_recovers_only_with_matching_scope_and_fresh_generation() {
        let (_temp, spool) = spool();
        let mut source = Cursor::new(b"uncommitted plaintext".to_vec());
        let work = spool
            .begin(binding(4), &mut source, 4)
            .expect("working copy");
        let id = work.record_id().to_owned();
        assert_eq!(work.len(4).expect("size"), 21);
        assert_eq!(work.len(5), Err(VaultWriteError::StaleGeneration));

        let mut wrong_scope =
            VaultWriteScope::new("account-b", "https://example.com", "space-1", "root-1")
                .expect("valid other account");
        wrong_scope.account_id = "account-b".to_owned();
        let mismatch =
            VaultWriteBinding::new(wrong_scope, binding(5).target, 5).expect("mismatch binding");
        assert_eq!(
            spool.recover(&id, mismatch, 5).err(),
            Some(VaultWriteError::RecordMismatch)
        );

        let recovered = spool
            .recover(&id, binding(9), 9)
            .expect("fresh explicit recovery");
        assert_eq!(recovered.len(9).expect("size after recovery"), 21);
        let (records, truncated) = spool.list_pending().expect("metadata listing");
        assert!(!truncated);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record_id, id);
        assert_eq!(records[0].bytes, Some(21));
        assert!(matches!(
            records[0].lifecycle,
            Some(VaultWriteLifecycle::CleanBaseline { bytes: 21, .. })
        ));
        assert!(records[0].warning.is_none());
    }

    #[test]
    fn open_existing_does_not_create_and_baseline_can_be_retired() {
        let temp = tempfile::tempdir().expect("temporary profile directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
                .expect("restrict profile directory");
        }
        assert!(
            VaultWriteSpool::open_existing(temp.path())
                .expect("missing spool is safe")
                .is_none()
        );
        assert!(!temp.path().join(ROOT_DIR_NAME).exists());

        let spool = VaultWriteSpool::open(temp.path()).expect("create spool");
        let mut source = Cursor::new(b"unchanged".to_vec());
        let work = spool.begin(binding(3), &mut source, 3).expect("baseline");
        let id = work.record_id().to_owned();
        assert!(
            work.retire_if_unchanged(3)
                .expect("pristine baseline retirement")
        );
        assert_eq!(
            spool.recover(&id, binding(4), 4).err(),
            Some(VaultWriteError::RecordNotFound)
        );
        assert!(
            VaultWriteSpool::open_existing(temp.path())
                .expect("existing spool")
                .is_some()
        );
    }

    #[test]
    fn commit_persists_next_etag_and_later_edit_becomes_dirty() {
        let (_temp, spool) = spool();
        let mut source = Cursor::new(b"before".to_vec());
        let mut work = spool.begin(binding(5), &mut source, 5).expect("baseline");
        let id = work.record_id().to_owned();
        let entry = work
            .commit_snapshot(5, |snapshot, length| {
                let mut actual = Vec::new();
                snapshot.read_to_end(&mut actual).expect("read snapshot");
                assert_eq!(actual, b"before");
                assert_eq!(length, actual.len() as u64);
                Ok(remote_entry(length, "etag-2"))
            })
            .expect("upload and commit");
        assert_eq!(entry.etag, "etag-2");
        assert_eq!(
            work.binding().target().condition(),
            &WriteCondition::Match("etag-2".into())
        );
        let (records, _) = spool.list_pending().expect("list committed record");
        assert!(matches!(
            records[0].lifecycle,
            Some(VaultWriteLifecycle::Committed { bytes: 6, .. })
        ));

        work.write_at(0, b"later!", 5).expect("second local edit");
        assert_eq!(work.lifecycle(), &VaultWriteLifecycle::Dirty);
        let (records, _) = spool.list_pending().expect("list dirty record");
        assert_eq!(records[0].lifecycle, Some(VaultWriteLifecycle::Dirty));
        let recovered = spool
            .recover(&id, binding_with_etag(6, "etag-2"), 6)
            .expect("record uses next remote condition");
        assert_eq!(recovered.lifecycle(), &VaultWriteLifecycle::Dirty);
    }

    #[test]
    fn verified_create_commit_retires_pending_parent_binding() {
        let (_temp, spool) = spool();
        let scope = scope();
        let parent = VaultParentRef::pending_create("a".repeat(32), 3).unwrap();
        let target =
            VaultWriteTarget::new_with_parent("nested/file.txt", WriteCondition::Absent, parent)
                .unwrap();
        let binding = VaultWriteBinding::new(scope, target, 9).unwrap();
        let mut empty = Cursor::new(Vec::<u8>::new());
        let mut working = spool.begin(binding, &mut empty, 9).unwrap();
        working.write_at(0, b"file", 9).unwrap();
        let entry = working
            .commit_snapshot(9, |_source, len| {
                Ok(RemoteEntry {
                    id: "stable-file-id".into(),
                    path: "/nested/file.txt".into(),
                    directory: false,
                    size: len,
                    etag: "strong-v1".into(),
                    modified_unix: 1,
                    writable: true,
                    encrypted: true,
                })
            })
            .unwrap();
        assert_eq!(entry.id, "stable-file-id");
        assert_eq!(working.binding().target().parent_ref(), None);
    }

    #[test]
    fn queued_create_keeps_absent_binding_across_revision_and_restart() {
        let (_temp, spool) = spool();
        let mut empty = Cursor::new(Vec::<u8>::new());
        let mut work = spool
            .begin(absent_binding(7), &mut empty, 7)
            .expect("empty create working copy");
        let operation_id = "a".repeat(32);
        work.record_building_create(7, &operation_id, 1)
            .expect("persist non-retryable create reservation");
        let id = work.record_id().to_owned();
        drop(work);
        let mut work = spool
            .recover(&id, absent_binding(8), 8)
            .expect("building operation survives restart");
        assert!(matches!(
            work.lifecycle(),
            VaultWriteLifecycle::BuildingCreate { write_id, revision: 1 }
                if write_id == &operation_id
        ));

        work.write_at(0, b"body", 8)
            .expect("write through same handle");
        assert!(matches!(
            work.lifecycle(),
            VaultWriteLifecycle::DirtyBuildingCreate { write_id, revision: 1 }
                if write_id == &operation_id
        ));
        let second = work
            .commit_snapshot_outcome(8, |_source, length| {
                assert_eq!(length, 4);
                Ok(VaultUploadOutcome::QueuedCreate {
                    entry: RemoteEntry {
                        id: "pending-create:op-a".into(),
                        path: "/notes.txt".into(),
                        directory: false,
                        size: 4,
                        etag: "pending-create:op-a:2".into(),
                        modified_unix: 0,
                        writable: true,
                        encrypted: true,
                    },
                    write_id: operation_id.clone(),
                    revision: 2,
                    uncertain: false,
                })
            })
            .expect("publish first queued create revision");
        assert!(matches!(
            second,
            VaultUploadOutcome::QueuedCreate { revision: 2, .. }
        ));
        assert_eq!(work.binding().target().condition(), &WriteCondition::Absent);
        assert!(matches!(
            work.lifecycle(),
            VaultWriteLifecycle::Queued { write_id, revision: 2, .. } if write_id == &operation_id
        ));

        work.write_at(0, b"later", 8)
            .expect("later edit preserves operation identity");
        assert!(matches!(
            work.lifecycle(),
            VaultWriteLifecycle::DirtyQueued { write_id, revision: 2, .. }
                if write_id == &operation_id
        ));
        let third = work
            .commit_snapshot_outcome(8, |_source, length| {
                assert_eq!(length, 5);
                Ok(VaultUploadOutcome::QueuedCreate {
                    entry: RemoteEntry {
                        id: "pending-create:op-a".into(),
                        path: "/notes.txt".into(),
                        directory: false,
                        size: 5,
                        etag: "pending-create:op-a:3".into(),
                        modified_unix: 0,
                        writable: true,
                        encrypted: true,
                    },
                    write_id: operation_id.clone(),
                    revision: 3,
                    uncertain: false,
                })
            })
            .expect("replace same operation revision");
        assert!(matches!(
            third,
            VaultUploadOutcome::QueuedCreate { revision: 3, .. }
        ));

        drop(work);
        let restored = spool
            .recover(&id, absent_binding(9), 9)
            .expect("restart restores original absence condition");
        assert_eq!(
            restored.binding().target().condition(),
            &WriteCondition::Absent
        );
        assert!(matches!(
            restored.lifecycle(),
            VaultWriteLifecycle::Queued { write_id, revision: 3, .. } if write_id == &operation_id
        ));
    }

    #[test]
    fn never_attempted_create_retarget_rebinds_manifest_without_changing_bytes() {
        let (_temp, spool) = spool();
        let operation_id = "b".repeat(32);
        let source_parent = VaultParentRef::stable("parent-a").unwrap();
        let source_target = VaultWriteTarget::new_with_parent(
            "encrypted/source",
            WriteCondition::Absent,
            source_parent,
        )
        .unwrap();
        let source_binding = VaultWriteBinding::new(scope(), source_target.clone(), 11).unwrap();
        let mut empty = Cursor::new(Vec::<u8>::new());
        let mut work = spool.begin(source_binding, &mut empty, 11).unwrap();
        let record_id = work.record_id().to_owned();
        work.record_building_create(11, &operation_id, 1).unwrap();
        work.write_at(0, b"same bytes", 11).unwrap();
        work.commit_snapshot_outcome(11, |_source, length| {
            Ok(VaultUploadOutcome::QueuedCreate {
                entry: remote_entry(length, "raiun-pending-v1"),
                write_id: operation_id.clone(),
                revision: 2,
                uncertain: false,
            })
        })
        .unwrap();
        let destination_parent = VaultParentRef::pending_create("c".repeat(32), 4).unwrap();
        let destination_target = VaultWriteTarget::new_with_parent(
            "encrypted/destination",
            WriteCondition::Absent,
            destination_parent,
        )
        .unwrap();

        work.retarget_never_attempted_create(11, &operation_id, 2, 3, destination_target.clone())
            .unwrap();
        assert_eq!(work.binding().target(), &destination_target);
        assert!(matches!(
            work.lifecycle(),
            VaultWriteLifecycle::Queued { write_id, revision: 3, uncertain: false, bytes: 10, .. }
                if write_id == &operation_id
        ));
        let mut actual = vec![0; 10];
        work.read_at(0, &mut actual, 11).unwrap();
        assert_eq!(actual, b"same bytes");
        drop(work);

        let recovered_binding = VaultWriteBinding::new(scope(), destination_target, 12).unwrap();
        let restored = spool
            .recover(&record_id, recovered_binding, 12)
            .expect("retargeted manifest survives restart");
        assert!(matches!(
            restored.lifecycle(),
            VaultWriteLifecycle::Queued { write_id, revision: 3, uncertain: false, .. }
                if write_id == &operation_id
        ));
    }

    #[test]
    fn subtree_retarget_wal_recovers_after_a_partial_manifest_batch() {
        let (temp, spool) = spool();
        let root_id = "a".repeat(32);
        let old_parent = VaultParentRef::pending_create(root_id.clone(), 1).unwrap();
        let new_parent = VaultParentRef::pending_create(root_id.clone(), 2).unwrap();
        let mut file_rows = Vec::new();
        for (index, (id, name, body)) in [
            ("b", "one.txt", b"first".as_slice()),
            ("c", "two.txt", b"second".as_slice()),
        ]
        .into_iter()
        .enumerate()
        {
            let write_id = id.repeat(32);
            let old_target = VaultWriteTarget::new_with_parent(
                format!("old/{name}"),
                WriteCondition::Absent,
                old_parent.clone(),
            )
            .unwrap();
            let mut empty = Cursor::new(Vec::<u8>::new());
            let mut work = spool
                .begin(
                    VaultWriteBinding::new(scope(), old_target.clone(), 1).unwrap(),
                    &mut empty,
                    1,
                )
                .unwrap();
            let record_id = work.record_id().to_owned();
            work.record_building_create(1, &write_id, 1).unwrap();
            work.write_at(0, body, 1).unwrap();
            work.commit_snapshot_outcome(1, |_body, len| {
                Ok(VaultUploadOutcome::QueuedCreate {
                    entry: RemoteEntry {
                        id: format!("raiun-pending-create:{write_id}"),
                        path: format!("/old/{name}"),
                        directory: false,
                        size: len,
                        etag: format!("raiun-pending-v1:{write_id}:2"),
                        modified_unix: 0,
                        writable: true,
                        encrypted: false,
                    },
                    write_id: write_id.clone(),
                    revision: 2,
                    uncertain: false,
                })
            })
            .unwrap();
            let (bytes, sha256) = match work.lifecycle() {
                VaultWriteLifecycle::Queued { bytes, sha256, .. } => (*bytes, sha256.clone()),
                _ => panic!("expected queued local file"),
            };
            file_rows.push(PendingVaultRetargetRow {
                write_id,
                previous_revision: 2,
                revision: 3,
                operation: PendingVaultRetargetOperation::CreateFile,
                old_path: format!("/old/{name}"),
                path: format!("/new/{name}"),
                record_id: Some(record_id),
                old_target: Some(old_target),
                target: VaultWriteTarget::new_with_parent(
                    format!("new/{name}"),
                    WriteCondition::Absent,
                    new_parent.clone(),
                )
                .unwrap(),
                bytes,
                sha256,
            });
            drop(work);
            assert_eq!(index, file_rows.len() - 1);
        }
        let root_target = VaultWriteTarget::new_with_parent(
            "new/root",
            WriteCondition::Absent,
            VaultParentRef::stable("root-resource").unwrap(),
        )
        .unwrap();
        let mut rows = vec![PendingVaultRetargetRow {
            write_id: root_id.clone(),
            previous_revision: 1,
            revision: 2,
            operation: PendingVaultRetargetOperation::CreateDirectory,
            old_path: "/old".into(),
            path: "/new".into(),
            record_id: None,
            old_target: None,
            target: root_target,
            bytes: 0,
            sha256: String::new(),
        }];
        rows.extend(file_rows);
        let wal = PendingVaultDirectoryRetarget {
            scope: scope(),
            root_write_id: root_id,
            root_previous_revision: 1,
            root_revision: 2,
            source_path: "/old".into(),
            destination_path: "/new".into(),
            rows,
        };
        spool
            .begin_directory_subtree_retarget(&wal)
            .expect("persist complete WAL before backend publish");
        spool
            .discard_directory_subtree_retarget_if_unchanged(&wal)
            .expect("an all-old backend proof can safely discard an untouched WAL");
        assert!(spool.list_directory_subtree_retargets().unwrap().is_empty());
        spool
            .begin_directory_subtree_retarget(&wal)
            .expect("a later exact attempt can write the durable WAL again");

        // Simulate a crash after the first of two local manifest replacements.
        let first = &wal.rows[1];
        let first_dir = spool.root().join(first.record_id.as_ref().unwrap());
        let mut first_record = read_manifest(&first_dir).unwrap();
        first_record.target = first.target.clone();
        first_record.lifecycle = VaultWriteLifecycle::Queued {
            bytes: first.bytes,
            sha256: first.sha256.clone(),
            write_id: first.write_id.clone(),
            revision: first.revision,
            uncertain: false,
        };
        write_manifest_replace(&first_dir, &first_record).unwrap();

        let reopened = VaultWriteSpool::open_existing(temp.path())
            .unwrap()
            .expect("spool survives restart");
        let durable = reopened.list_directory_subtree_retargets().unwrap();
        assert_eq!(durable, vec![wal.clone()]);
        assert_eq!(
            reopened.discard_directory_subtree_retarget_if_unchanged(&wal),
            Err(VaultWriteError::RecordMismatch),
            "a mixed local manifest batch must not discard its recovery WAL"
        );
        assert_eq!(
            reopened.list_directory_subtree_retargets().unwrap(),
            vec![wal.clone()]
        );
        reopened.apply_directory_subtree_retarget(&wal, 2).expect(
            "all-new proof applies remaining manifests and tolerates the first already done",
        );
        reopened
            .apply_directory_subtree_retarget(&wal, 2)
            .expect("recovery is idempotent");
        reopened
            .finish_directory_subtree_retarget(&wal)
            .expect("remove WAL only after all manifests are new");
        assert!(
            reopened
                .list_directory_subtree_retargets()
                .unwrap()
                .is_empty()
        );
        for row in wal.rows.iter().filter(|row| row.record_id.is_some()) {
            let recovered = reopened
                .recover(
                    row.record_id.as_deref().unwrap(),
                    VaultWriteBinding::new(scope(), row.target.clone(), 2).unwrap(),
                    2,
                )
                .expect("retargeted local copy is bound to new target");
            assert!(matches!(recovered.lifecycle(),
                VaultWriteLifecycle::Queued { write_id, revision: 3, uncertain: false, .. }
                    if write_id == &row.write_id));
        }
    }

    #[test]
    fn uncertain_or_dirty_create_cannot_be_retargeted() {
        let (_temp, spool) = spool();
        let operation_id = "d".repeat(32);
        let source_target = VaultWriteTarget::new_with_parent(
            "encrypted/source",
            WriteCondition::Absent,
            VaultParentRef::stable("parent-a").unwrap(),
        )
        .unwrap();
        let mut empty = Cursor::new(Vec::<u8>::new());
        let binding = VaultWriteBinding::new(scope(), source_target, 13).unwrap();
        let mut work = spool.begin(binding, &mut empty, 13).unwrap();
        work.record_building_create(13, &operation_id, 1).unwrap();
        work.write_at(0, b"body", 13).unwrap();
        work.commit_snapshot_outcome(13, |_source, length| {
            Ok(VaultUploadOutcome::QueuedCreate {
                entry: remote_entry(length, "raiun-pending-v1"),
                write_id: operation_id.clone(),
                revision: 2,
                uncertain: true,
            })
        })
        .unwrap();
        let new_target = VaultWriteTarget::new_with_parent(
            "encrypted/other",
            WriteCondition::Absent,
            VaultParentRef::stable("parent-a").unwrap(),
        )
        .unwrap();
        assert_eq!(
            work.retarget_never_attempted_create(13, &operation_id, 2, 3, new_target.clone()),
            Err(VaultWriteError::RecordMismatch)
        );

        work.write_at(0, b"new", 13).unwrap();
        assert!(matches!(
            work.lifecycle(),
            VaultWriteLifecycle::DirtyQueued { .. }
        ));
        assert_eq!(
            work.retarget_never_attempted_create(13, &operation_id, 2, 3, new_target),
            Err(VaultWriteError::RecordMismatch)
        );
    }

    #[test]
    fn cancellation_wal_survives_record_removal_until_receipt_ack() {
        let (_temp, spool) = spool();
        let operation_id = "e".repeat(32);
        let target = VaultWriteTarget::new_with_parent(
            "encrypted/new-name",
            WriteCondition::Absent,
            VaultParentRef::stable("parent-a").unwrap(),
        )
        .unwrap();
        let binding = VaultWriteBinding::new(scope(), target, 21).unwrap();
        let mut empty = Cursor::new(Vec::<u8>::new());
        let mut working = spool.begin(binding.clone(), &mut empty, 21).unwrap();
        let record_id = working.record_id().to_owned();
        working
            .record_building_create(21, &operation_id, 1)
            .unwrap();
        working.write_at(0, b"cancel me", 21).unwrap();
        working
            .commit_snapshot_outcome(21, |_source, length| {
                Ok(VaultUploadOutcome::QueuedCreate {
                    entry: RemoteEntry {
                        id: format!("raiun-pending-create:{operation_id}"),
                        path: "/new-name".into(),
                        directory: false,
                        size: length,
                        etag: format!("raiun-pending-v1:{operation_id}:2"),
                        modified_unix: 0,
                        writable: true,
                        encrypted: true,
                    },
                    write_id: operation_id.clone(),
                    revision: 2,
                    uncertain: false,
                })
            })
            .unwrap();
        let verified = working
            .begin_never_attempted_create_cancel(21, &operation_id, 2, "/new-name")
            .unwrap();
        assert!(matches!(
            working.lifecycle(),
            VaultWriteLifecycle::CancelPendingCreate { write_id, revision: 2, .. }
                if write_id == &operation_id
        ));
        assert_eq!(
            working.write_at(0, b"must not mutate", 21),
            Err(VaultWriteError::RecordMismatch)
        );
        drop(working);

        let cancellations = spool.list_create_cancellations().unwrap();
        assert_eq!(cancellations.len(), 1);
        let cancellation = cancellations[0].clone();
        assert_eq!(cancellation.record_id, record_id);
        assert_eq!(cancellation.write_id, operation_id);
        assert_eq!(cancellation.revision, 2);
        assert_eq!(cancellation.bytes, verified.bytes);
        assert_eq!(cancellation.sha256, verified.sha256);

        let reopened_binding =
            VaultWriteBinding::new(binding.scope().clone(), binding.target().clone(), 22).unwrap();
        let reopened = spool.recover(&record_id, reopened_binding, 22).unwrap();
        assert!(matches!(
            reopened.lifecycle(),
            VaultWriteLifecycle::CancelPendingCreate { .. }
        ));
        assert!(
            reopened
                .retire_cancelled_create_if_unchanged(22, &cancellation.write_id, 2, &verified)
                .unwrap()
        );

        // The exact root tombstone outlives the working copy so a crash before
        // backend receipt acknowledgement can safely finish that same ack.
        assert_eq!(spool.list_pending().unwrap().0.len(), 0);
        assert_eq!(
            spool.list_create_cancellations().unwrap(),
            vec![cancellation.clone()]
        );
        spool
            .remove_create_cancellation_tombstone(&cancellation)
            .unwrap();
        assert!(spool.list_create_cancellations().unwrap().is_empty());
    }

    fn binding_with_etag(generation: u64, etag: &str) -> VaultWriteBinding {
        VaultWriteBinding::new(
            scope(),
            VaultWriteTarget::new("encrypted/opaque-name", WriteCondition::Match(etag.into()))
                .expect("valid target"),
            generation,
        )
        .expect("valid binding")
    }

    #[test]
    fn remote_error_is_preserved_and_record_stays_dirty() {
        let (_temp, spool) = spool();
        let mut source = Cursor::new(b"data".to_vec());
        let mut work = spool.begin(binding(1), &mut source, 1).expect("baseline");
        let err = work
            .commit_snapshot(1, |_snapshot, _length| {
                Err(CloudError::new(
                    ErrorKind::Conflict,
                    "remote version changed",
                ))
            })
            .expect_err("conditional failure");
        assert_eq!(
            err,
            VaultWriteError::Backend(CloudError::new(
                ErrorKind::Conflict,
                "remote version changed"
            ))
        );
        assert_eq!(work.lifecycle(), &VaultWriteLifecycle::Dirty);
    }

    #[test]
    fn external_edit_during_upload_keeps_dirty_record_and_advances_condition() {
        let (_temp, spool) = spool();
        let mut source = Cursor::new(b"snapshot".to_vec());
        let mut work = spool.begin(binding(2), &mut source, 2).expect("baseline");
        let data_path = work.record_dir.join(DATA_NAME);
        let result = work.commit_snapshot(2, |_snapshot, length| {
            fs::write(&data_path, b"external edit").expect("synthetic external edit");
            Ok(remote_entry(length, "etag-after-put"))
        });
        assert_eq!(result, Err(VaultWriteError::ChangedDuringUpload));
        assert_eq!(work.lifecycle(), &VaultWriteLifecycle::Dirty);
        assert_eq!(
            work.binding().target().condition(),
            &WriteCondition::Match("etag-after-put".into())
        );
        let (records, _) = spool.list_pending().expect("list retained edit");
        assert_eq!(records[0].lifecycle, Some(VaultWriteLifecycle::Dirty));
        assert_eq!(records[0].bytes, Some(b"external edit".len() as u64));
    }

    #[test]
    fn recovery_reconciles_same_length_external_edit_to_dirty() {
        let (_temp, spool) = spool();
        let mut source = Cursor::new(b"initial".to_vec());
        let mut work = spool.begin(binding(1), &mut source, 1).expect("baseline");
        let id = work.record_id().to_owned();
        work.commit_snapshot(1, |_snapshot, length| {
            Ok(remote_entry(length, "etag-committed"))
        })
        .expect("commit");
        let path = work.record_dir.join(DATA_NAME);
        drop(work);
        fs::write(&path, b"changed").expect("same length external edit");

        let recovered = spool
            .recover(&id, binding_with_etag(2, "etag-committed"), 2)
            .expect("explicit recovery preserves modified data");
        assert_eq!(recovered.lifecycle(), &VaultWriteLifecycle::Dirty);
        let (records, _) = spool.list_pending().expect("list reconciled record");
        assert_eq!(records[0].lifecycle, Some(VaultWriteLifecycle::Dirty));
    }

    #[test]
    fn stale_handles_cannot_write_and_uncommitted_bytes_are_retained() {
        let (_temp, spool) = spool();
        let mut source = Cursor::new(b"old".to_vec());
        let mut work = spool
            .begin(binding(2), &mut source, 2)
            .expect("working copy");
        assert_eq!(
            work.write_at(0, b"new", 3),
            Err(VaultWriteError::StaleGeneration)
        );
        assert_eq!(
            work.write_at(MAX_VAULT_WORKING_COPY_BYTES, b"x", 2),
            Err(VaultWriteError::SizeLimit)
        );
        work.write_at(0, b"new", 2).expect("write");
        work.sync(2).expect("sync");

        let recovered = spool
            .recover(work.record_id(), binding(8), 8)
            .expect("retained record");
        let mut recovered = recovered;
        let mut bytes = [0; 3];
        assert_eq!(recovered.read_at(0, &mut bytes, 8).expect("read"), 3);
        assert_eq!(&bytes, b"new");
    }

    struct FailsAfterBytes;

    impl Read for FailsAfterBytes {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if buffer.is_empty() {
                return Ok(0);
            }
            if buffer[0] == 0 {
                buffer[0] = 1;
                Ok(1)
            } else {
                Err(io::Error::other("synthetic read failure"))
            }
        }
    }

    #[test]
    fn failed_initial_copy_keeps_partial_record_for_manual_recovery() {
        let (_temp, spool) = spool();
        assert_eq!(
            spool.begin(binding(1), &mut FailsAfterBytes, 1).err(),
            Some(VaultWriteError::Io)
        );
        let (records, _) = spool.list_pending().expect("list retained record");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].bytes, Some(1));
        assert!(records[0].warning.is_none());
    }

    #[test]
    fn swapped_manifest_cannot_be_recovered_as_another_record() {
        let (_temp, spool) = spool();
        let mut first_bytes = Cursor::new(b"first".to_vec());
        let first = spool
            .begin(binding(1), &mut first_bytes, 1)
            .expect("first record");
        let first_id = first.record_id().to_owned();
        drop(first);
        let mut second_bytes = Cursor::new(b"second".to_vec());
        let second = spool
            .begin(binding(1), &mut second_bytes, 1)
            .expect("second record");
        let second_id = second.record_id().to_owned();
        drop(second);

        let first_manifest = spool.root.join(&first_id).join(MANIFEST_NAME);
        let second_manifest = spool.root.join(&second_id).join(MANIFEST_NAME);
        let moved = spool.root.join("swapped-manifest.tmp");
        fs::rename(&first_manifest, &moved).expect("move first manifest away");
        fs::rename(&second_manifest, &first_manifest).expect("install wrong manifest");
        fs::rename(&moved, &second_manifest).expect("restore first manifest");

        assert_eq!(
            spool.recover(&first_id, binding(2), 2).err(),
            Some(VaultWriteError::CorruptRecord)
        );
    }

    #[test]
    fn target_and_origin_validation_reject_host_paths_and_non_origins() {
        assert_eq!(
            VaultWriteTarget::new("../host-path", WriteCondition::Absent).err(),
            Some(VaultWriteError::InvalidTarget)
        );
        assert_eq!(
            VaultWriteTarget::new("/absolute", WriteCondition::Absent).err(),
            Some(VaultWriteError::InvalidTarget)
        );
        assert_eq!(
            VaultWriteScope::new("a", "https://example.com/dav", "s", "r").err(),
            Some(VaultWriteError::InvalidBinding)
        );
        assert_eq!(
            VaultWriteScope::new("a", "https://user@example.com/", "s", "r").err(),
            Some(VaultWriteError::InvalidBinding)
        );
        assert_eq!(scope().server_origin(), "https://example.com");
    }

    #[test]
    fn create_target_persists_exact_parent_reference_and_rejects_invalid_pending_refs() {
        let target = VaultWriteTarget::new_with_parent(
            "opaque/child",
            WriteCondition::Absent,
            VaultParentRef::pending_create("a".repeat(32), 7).expect("valid pending parent"),
        )
        .expect("parent-bound target");
        let encoded = serde_json::to_vec(&target).expect("serialize target");
        let decoded: VaultWriteTarget =
            serde_json::from_slice(&encoded).expect("deserialize target");
        assert_eq!(decoded, target);
        assert_eq!(
            decoded.parent_ref(),
            Some(&VaultParentRef::PendingCreate {
                write_id: "a".repeat(32),
                revision: 7,
            })
        );

        assert!(VaultParentRef::pending_create("a".repeat(32), 0).is_err());
        assert!(VaultParentRef::stable("raiun-pending-directory:guess").is_err());
        assert!(
            VaultWriteTarget::new_with_parent(
                "opaque/child",
                WriteCondition::Absent,
                VaultParentRef::stable("parent-resource").expect("stable parent"),
            )
            .is_ok()
        );
    }

    #[test]
    fn queued_create_revisions_retain_parent_binding() {
        let (_temp, spool) = spool();
        let parent =
            VaultParentRef::pending_create("b".repeat(32), 3).expect("valid pending directory ref");
        let target = VaultWriteTarget::new_with_parent(
            "opaque/child",
            WriteCondition::Absent,
            parent.clone(),
        )
        .expect("bound create target");
        let binding = VaultWriteBinding::new(scope(), target, 4).expect("binding");
        let mut source = Cursor::new(Vec::<u8>::new());
        let mut work = spool.begin(binding, &mut source, 4).expect("working copy");
        work.mark_dirty(4).expect("durable dirty state");
        work.write_at(0, b"nested", 4).expect("write nested file");
        let outcome = work
            .commit_snapshot_outcome(4, |reader, length| {
                assert_eq!(length, 6);
                let mut bytes = Vec::new();
                reader
                    .read_to_end(&mut bytes)
                    .map_err(|_| CloudError::new(ErrorKind::Io, "fixture read"))?;
                assert_eq!(bytes, b"nested");
                Ok(VaultUploadOutcome::QueuedCreate {
                    entry: RemoteEntry {
                        id: format!("raiun-pending-create:{}", "c".repeat(32)),
                        path: "/opaque/child".into(),
                        directory: false,
                        size: length,
                        etag: format!("raiun-pending-v1:{}:2", "c".repeat(32)),
                        modified_unix: 0,
                        writable: true,
                        encrypted: true,
                    },
                    write_id: "c".repeat(32),
                    revision: 2,
                    uncertain: false,
                })
            })
            .expect("queue create revision");
        assert!(matches!(outcome, VaultUploadOutcome::QueuedCreate { .. }));
        assert_eq!(work.binding().target().condition(), &WriteCondition::Absent);
        assert_eq!(work.binding().target().parent_ref(), Some(&parent));
        assert!(matches!(
            work.lifecycle(),
            VaultWriteLifecycle::Queued { .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn spool_records_are_private_and_symlink_data_is_never_reopened() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let (temp, spool) = spool();
        let mut source = Cursor::new(b"plaintext".to_vec());
        let work = spool
            .begin(binding(1), &mut source, 1)
            .expect("working copy");
        let root_mode = fs::metadata(spool.root())
            .expect("root metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(root_mode, 0o700);
        let data_path = work.record_dir.join(DATA_NAME);
        let data_mode = fs::metadata(&data_path)
            .expect("data metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(data_mode, 0o600);

        fs::remove_file(&data_path).expect("remove fixture data");
        let target = temp.path().join("outside-data");
        fs::write(&target, b"must not be read").expect("external fixture");
        symlink(&target, &data_path).expect("install data symlink");
        let (items, _) = spool.list_pending().expect("safe metadata scan");
        assert_eq!(items[0].warning, Some(VaultWriteWarning::UnsafeData));
        assert_eq!(
            spool.recover(work.record_id(), binding(2), 2).err(),
            Some(VaultWriteError::CorruptRecord)
        );

        let manifest = work.record_dir.join(MANIFEST_NAME);
        fs::remove_file(&manifest).expect("remove fixture manifest");
        symlink(&target, &manifest).expect("install manifest symlink");
        let (items, _) = spool.list_pending().expect("safe metadata scan");
        assert_eq!(items[0].warning, Some(VaultWriteWarning::UnsafeManifest));
        assert_eq!(
            spool.recover(work.record_id(), binding(2), 2).err(),
            Some(VaultWriteError::CorruptRecord)
        );
    }
}
