//! Explicit local journal receipts. No value in this module proves that a
//! remote mutation occurred or grants authority to replay one after restart.
use crate::{VaultChildCreateDescriptor, VaultFileDeleteDescriptor, VaultFileRenameDescriptor};
use raiun_core::backend::RemoteEntry;

#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum VaultCachedNamespaceOperation {
    CreateFile,
    CreateDirectory,
    RenameFile,
    DeleteFile,
    RetargetNeverAttemptedDirectory,
}

/// Full original native/account/root facts are retained separately from the
/// resulting journal alias. Online descriptor validators remain unchanged.
#[derive(Clone)]
pub enum VaultCachedNamespaceDescriptor {
    ChildCreate(VaultChildCreateDescriptor),
    FileRename(VaultFileRenameDescriptor),
    FileDelete(VaultFileDeleteDescriptor),
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
}
impl VaultCachedNamespaceQueued {
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
            || revision == 0
            || write_id.is_empty()
            || write_id.len() > 512
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
}
