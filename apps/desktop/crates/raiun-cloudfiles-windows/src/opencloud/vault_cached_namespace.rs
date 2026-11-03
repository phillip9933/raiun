//! Explicit local journal receipts. No value in this module proves that a
//! remote mutation occurred or grants authority to replay one after restart.
use crate::vault_file_delete::VaultFileDeleteDescriptor;
use crate::{
    ConfiguredRootIdentity, LocalFileIdentity, ProviderScope, VaultChildCreateDescriptor,
    VaultFileRenameDescriptor,
};
use raiun_cache::CiphertextWriteState;
use raiun_core::backend::RemoteEntry;
use raiun_opencloud::vault_cache::VaultPendingParentRef;
use raiun_opencloud::vault_cache::{
    VaultPendingDirectorySubtreeRetarget, VaultPendingDirectorySubtreeRetargetRow,
    VaultPendingEditMetadata, VaultPendingOperationKind,
};
use raiun_vault::session::VaultSessionScope;

#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum VaultCachedNamespaceOperation {
    CreateFile,
    CreateDirectory,
    RenameFile,
    DeleteFile,
    RetargetNeverAttemptedFile,
    RetargetNeverAttemptedDirectory,
}

/// Full original native/account/root facts are retained separately from the
/// resulting journal alias. Online descriptor validators remain unchanged.
#[derive(Clone)]
pub enum VaultCachedNamespaceDescriptor {
    ChildCreate(VaultChildCreateDescriptor),
    FileRename(VaultFileRenameDescriptor),
    FileDelete(VaultFileDeleteDescriptor),
    PendingRetarget(VaultCachedRetargetDescriptor),
}

/// Original native owner facts for a queued create retarget. The synthetic
/// source is deliberately separate from online strong-ETag descriptors.
#[derive(Clone)]
pub struct VaultCachedRetargetDescriptor {
    pub owner: ProviderScope,
    pub vault: VaultSessionScope,
    pub remote_root: String,
    pub root: ConfiguredRootIdentity,
    pub identity: [u8; 16],
    pub original: RemoteEntry,
    pub parent_identity: [u8; 16],
    pub parent: RemoteEntry,
    pub destination_parent: RemoteEntry,
    pub destination_parent_identity: [u8; 16],
    pub historical_unlock_epoch: u64,
    pub original_file: LocalFileIdentity,
    pub original_usn: i64,
    pub parent_file: LocalFileIdentity,
    pub parent_usn: i64,
    pub destination_parent_file: LocalFileIdentity,
    pub destination_parent_usn: i64,
    pub old_components: Vec<String>,
    pub new_components: Vec<String>,
    pub destination_parent_ref: VaultPendingParentRef,
}
impl VaultCachedRetargetDescriptor {
    pub fn validate(&self) -> Result<(), crate::BackendError> {
        let bad = || crate::BackendError::Unavailable;
        let joined = |parent: &RemoteEntry, leaf: &String| {
            format!("{}/{}", parent.path.trim_end_matches('/'), leaf)
        };
        let pending_prefix = if self.original.directory {
            "raiun-pending-directory:"
        } else {
            "raiun-pending-create:"
        };
        let Some(id) = self.original.id.strip_prefix(pending_prefix) else {
            return Err(bad());
        };
        if self.owner.profile_id() != self.vault.account_id()
            || self.owner.server_origin() != self.vault.server_origin()
            || self.owner.token_generation() == 0
            || self.historical_unlock_epoch == 0
            || self.root.volume_serial == 0
            || self.root.file_index == 0
            || self.identity == [0; 16]
            || self.parent_identity == [0; 16]
            || self.destination_parent_identity == [0; 16]
            || self.identity == self.parent_identity
            || self.identity == self.destination_parent_identity
            || self.original_file.volume_serial != self.root.volume_serial
            || self.parent_file.volume_serial != self.root.volume_serial
            || self.destination_parent_file.volume_serial != self.root.volume_serial
            || self.original_file.file_index == 0
            || self.parent_file.file_index == 0
            || self.destination_parent_file.file_index == 0
            || self.original_file.file_index == self.parent_file.file_index
            || self.original_usn <= 0
            || self.parent_usn <= 0
            || self.destination_parent_usn <= 0
            || self.old_components.len() < 2
            || self.new_components.len() < 2
            || self.old_components.len() > 256
            || self.new_components.len() > 256
            || self
                .old_components
                .iter()
                .chain(&self.new_components)
                .any(|p| !super::valid_windows_component(p))
            || self.old_components == self.new_components
            || self.original.path
                != joined(&self.parent, self.old_components.last().ok_or_else(bad)?)
            || !self.parent.directory
            || !self.destination_parent.directory
            || self.destination_parent.path == self.original.path
            || self.original.directory && self.original.size != 0
            || !valid_journal_id(id, 1)
            || !self
                .original
                .etag
                .starts_with(&format!("raiun-pending-v1:{id}:"))
            || raiun_core::validate_remote_path(&self.remote_root).is_err()
        {
            return Err(bad());
        }
        Ok(())
    }
}

pub struct VaultCachedNamespaceQueued {
    pub(super) descriptor: VaultCachedNamespaceDescriptor,
    pub(super) operation: VaultCachedNamespaceOperation,
    pub(super) write_id: String,
    pub(super) revision: u64,
    pub(super) original: Option<RemoteEntry>,
    pub(super) parent: RemoteEntry,
    pub(super) entry: Option<RemoteEntry>,
    pub(super) source_sha256: Option<[u8; 32]>,
    pub(super) plaintext_len: u64,
    pub(super) retarget_rows: Option<Vec<VaultPendingDirectorySubtreeRetargetRow>>,
}
impl VaultCachedNamespaceQueued {
    pub(crate) fn pending_file_retarget(
        descriptor: &VaultCachedRetargetDescriptor,
        result: VaultPendingEditMetadata,
    ) -> Result<Self, crate::BackendError> {
        descriptor.validate()?;
        let id = descriptor
            .original
            .id
            .strip_prefix("raiun-pending-create:")
            .ok_or(crate::BackendError::Unavailable)?;
        let old_revision = pending_revision(&descriptor.original.etag, id)?;
        let destination = format!(
            "{}/{}",
            descriptor.destination_parent.path.trim_end_matches('/'),
            descriptor
                .new_components
                .last()
                .ok_or(crate::BackendError::Unavailable)?
        );
        if descriptor.original.directory
            || result.operation != VaultPendingOperationKind::CreateFile
            || result.state != CiphertextWriteState::NeverAttempted
            || result.id != id
            || result.revision <= old_revision
            || result.path != destination
            || result.parent_ref.as_ref() != Some(&descriptor.destination_parent_ref)
            || result.plaintext_len != descriptor.original.size
        {
            return Err(crate::BackendError::Unavailable);
        }
        let entry = RemoteEntry {
            path: result.path,
            etag: pending_etag(id, result.revision),
            ..descriptor.original.clone()
        };
        Ok(Self {
            descriptor: VaultCachedNamespaceDescriptor::PendingRetarget(descriptor.clone()),
            operation: VaultCachedNamespaceOperation::RetargetNeverAttemptedFile,
            write_id: result.id,
            revision: result.revision,
            original: Some(descriptor.original.clone()),
            parent: descriptor.destination_parent.clone(),
            entry: Some(entry),
            source_sha256: None,
            plaintext_len: descriptor.original.size,
            retarget_rows: None,
        })
    }

    pub(crate) fn pending_directory_retarget(
        descriptor: &VaultCachedRetargetDescriptor,
        result: VaultPendingDirectorySubtreeRetarget,
    ) -> Result<Self, crate::BackendError> {
        descriptor.validate()?;
        let id = descriptor
            .original
            .id
            .strip_prefix("raiun-pending-directory:")
            .ok_or(crate::BackendError::Unavailable)?;
        let old_revision = pending_revision(&descriptor.original.etag, id)?;
        let destination = format!(
            "{}/{}",
            descriptor.destination_parent.path.trim_end_matches('/'),
            descriptor
                .new_components
                .last()
                .ok_or(crate::BackendError::Unavailable)?
        );
        let root = result
            .rows
            .iter()
            .find(|row| row.write_id == result.root_write_id)
            .ok_or(crate::BackendError::Unavailable)?;
        let bytes = result
            .rows
            .iter()
            .try_fold(0u64, |total, row| total.checked_add(row.plaintext_len));
        if !descriptor.original.directory
            || result.root_write_id != id
            || result.root_previous_revision != old_revision
            || result.root_revision <= old_revision
            || result.rows.is_empty()
            || result.rows.len() > 64
            || bytes.is_none_or(|bytes| bytes > 64 * 1024 * 1024)
            || result.rows.iter().any(|row| {
                !matches!(
                    row.operation,
                    VaultPendingOperationKind::CreateFile
                        | VaultPendingOperationKind::CreateDirectory
                ) || row.state != CiphertextWriteState::NeverAttempted
                    || row.revision <= row.previous_revision
            })
            || root.revision != result.root_revision
            || root.old_path != descriptor.original.path
            || root.path != destination
            || root.parent_ref != descriptor.destination_parent_ref
            || root.operation != VaultPendingOperationKind::CreateDirectory
            || root.state != CiphertextWriteState::NeverAttempted
        {
            return Err(crate::BackendError::Unavailable);
        }
        let entry = RemoteEntry {
            path: destination,
            etag: pending_etag(id, result.root_revision),
            ..descriptor.original.clone()
        };
        Ok(Self {
            descriptor: VaultCachedNamespaceDescriptor::PendingRetarget(descriptor.clone()),
            operation: VaultCachedNamespaceOperation::RetargetNeverAttemptedDirectory,
            write_id: result.root_write_id,
            revision: result.root_revision,
            original: Some(descriptor.original.clone()),
            parent: descriptor.destination_parent.clone(),
            entry: Some(entry),
            source_sha256: None,
            plaintext_len: 0,
            retarget_rows: Some(result.rows),
        })
    }

    pub(crate) fn file_rename(
        descriptor: &VaultFileRenameDescriptor,
        result: raiun_opencloud::vault_backend::VaultRenameOutcome,
        source_sha256: [u8; 32],
    ) -> Result<Self, crate::BackendError> {
        descriptor.validate()?;
        if descriptor.facts.original.directory || descriptor.facts.children.is_some() {
            return Err(crate::BackendError::Unavailable);
        }
        let raiun_opencloud::vault_backend::VaultRenameOutcome::Queued {
            entry,
            write_id,
            revision,
            uncertain: false,
        } = result
        else {
            return Err(crate::BackendError::Unavailable);
        };
        let facts = &descriptor.facts;
        if !valid_journal_id(&write_id, revision)
            || entry.id != facts.original.id
            || entry.path != facts.destination
            || entry.directory
            || entry.size != facts.original.size
            || entry.etag != pending_etag(&write_id, revision)
        {
            return Err(crate::BackendError::Unavailable);
        }
        Ok(Self {
            descriptor: VaultCachedNamespaceDescriptor::FileRename(descriptor.clone()),
            operation: VaultCachedNamespaceOperation::RenameFile,
            write_id,
            revision,
            original: Some(facts.original.clone()),
            parent: facts
                .destination_parent
                .as_ref()
                .map(|p| p.parent.clone())
                .unwrap_or_else(|| facts.parent.clone()),
            entry: Some(entry),
            source_sha256: Some(source_sha256),
            plaintext_len: facts.original.size,
            retarget_rows: None,
        })
    }

    pub(crate) fn file_delete(
        descriptor: &VaultFileDeleteDescriptor,
        result: raiun_opencloud::vault_backend::VaultDeleteOutcome,
    ) -> Result<Self, crate::BackendError> {
        descriptor.validate()?;
        if descriptor.empty_directory {
            return Err(crate::BackendError::Unavailable);
        }
        let raiun_opencloud::vault_backend::VaultDeleteOutcome::Queued {
            write_id,
            revision,
            uncertain: false,
        } = result
        else {
            return Err(crate::BackendError::Unavailable);
        };
        if !valid_journal_id(&write_id, revision) {
            return Err(crate::BackendError::Unavailable);
        }
        Ok(Self {
            descriptor: VaultCachedNamespaceDescriptor::FileDelete(descriptor.clone()),
            operation: VaultCachedNamespaceOperation::DeleteFile,
            write_id,
            revision,
            original: Some(descriptor.original.clone()),
            parent: descriptor.parent.clone(),
            entry: None,
            source_sha256: None,
            plaintext_len: descriptor.original.size,
            retarget_rows: None,
        })
    }

    pub(crate) fn child(
        descriptor: &VaultChildCreateDescriptor,
        result: raiun_opencloud::vault_backend::VaultUploadOutcome,
    ) -> Result<Self, crate::BackendError> {
        descriptor.validate()?;
        let raiun_opencloud::vault_backend::VaultUploadOutcome::QueuedCreate {
            entry,
            write_id,
            revision,
            uncertain: false,
        } = result
        else {
            return Err(crate::BackendError::Unavailable);
        };
        let directory =
            descriptor.source.kind == crate::namespace_intent::NamespaceObjectKind::Directory;
        if entry.path != descriptor.logical_path
            || entry.directory != directory
            || entry.size != descriptor.source.plaintext_len
            || !valid_journal_id(&write_id, revision)
            || entry.id
                != format!(
                    "raiun-pending-{}:{}",
                    if directory { "directory" } else { "create" },
                    write_id
                )
        {
            return Err(crate::BackendError::Unavailable);
        }
        Ok(Self {
            descriptor: VaultCachedNamespaceDescriptor::ChildCreate(descriptor.clone()),
            operation: if directory {
                VaultCachedNamespaceOperation::CreateDirectory
            } else {
                VaultCachedNamespaceOperation::CreateFile
            },
            write_id,
            revision,
            original: None,
            parent: descriptor.parent.clone(),
            entry: Some(entry),
            source_sha256: descriptor.source.plaintext_sha256,
            plaintext_len: descriptor.source.plaintext_len,
            retarget_rows: None,
        })
    }

    pub fn descriptor(&self) -> &VaultCachedNamespaceDescriptor {
        &self.descriptor
    }
    pub fn operation(&self) -> VaultCachedNamespaceOperation {
        self.operation
    }
    pub fn write_id(&self) -> &str {
        &self.write_id
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn original(&self) -> Option<&RemoteEntry> {
        self.original.as_ref()
    }
    pub fn parent(&self) -> &RemoteEntry {
        &self.parent
    }
    pub fn entry(&self) -> Option<&RemoteEntry> {
        self.entry.as_ref()
    }
    pub fn source_sha256(&self) -> Option<[u8; 32]> {
        self.source_sha256
    }
    pub fn plaintext_len(&self) -> u64 {
        self.plaintext_len
    }
    pub fn retarget_rows(&self) -> Option<&[VaultPendingDirectorySubtreeRetargetRow]> {
        self.retarget_rows.as_deref()
    }
}

fn valid_journal_id(id: &str, revision: u64) -> bool {
    id.len() == 32
        && id.bytes().all(|b| b.is_ascii_hexdigit())
        && revision > 0
        && revision <= i64::MAX as u64
}

fn pending_etag(id: &str, revision: u64) -> String {
    format!("raiun-pending-v1:{id}:{revision}")
}

fn pending_revision(etag: &str, id: &str) -> Result<u64, crate::BackendError> {
    let revision = etag
        .strip_prefix(&format!("raiun-pending-v1:{id}:"))
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(crate::BackendError::Unavailable)?;
    if valid_journal_id(id, revision) && pending_etag(id, revision) == etag {
        Ok(revision)
    } else {
        Err(crate::BackendError::Unavailable)
    }
}
