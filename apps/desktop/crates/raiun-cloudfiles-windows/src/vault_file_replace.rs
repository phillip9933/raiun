//! Original live replacement metadata and protected-body bridge. Serialized
//! counters are history only; no type here restores route/unlock authority.
use crate::{BackendError, ConfiguredRootIdentity, LocalFileIdentity, ProviderScope};
use raiun_core::backend::RemoteEntry;
use raiun_vault::session::VaultSessionScope;
use std::{io::Read, sync::Arc};

pub const MAX_VAULT_FILE_REPLACE_BYTES: u64 = 1 << 30;
#[derive(Clone)]
pub struct VaultFileReplaceDescriptor {
    pub owner: ProviderScope,
    pub vault: VaultSessionScope,
    pub remote_root: String,
    pub root: ConfiguredRootIdentity,
    pub original_identity: [u8; 16],
    pub original: RemoteEntry,
    pub parent_identity: [u8; 16],
    pub parent: RemoteEntry,
    pub historical_unlock_epoch: u64,
    pub original_file: LocalFileIdentity,
    pub original_usn: i64,
    pub parent_file: LocalFileIdentity,
    pub parent_usn: i64,
    pub replacement_file: LocalFileIdentity,
    pub replacement_usn: i64,
    pub components: Vec<String>,
    pub plaintext_len: u64,
}
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultFileReplaceFacts {
    pub remote_root: String,
    pub root: LocalFileIdentity,
    pub original_identity: [u8; 16],
    pub original: RemoteEntry,
    pub parent_identity: [u8; 16],
    pub parent: RemoteEntry,
    pub historical_unlock_epoch: u64,
    pub original_file: LocalFileIdentity,
    pub original_usn: i64,
    pub parent_file: LocalFileIdentity,
    pub parent_usn: i64,
    pub replacement_file: LocalFileIdentity,
    pub replacement_usn: i64,
    pub components: Vec<String>,
    pub plaintext_len: u64,
}
impl VaultFileReplaceFacts {
    pub fn validate(&self, root: ConfiguredRootIdentity) -> Result<(), BackendError> {
        let bad = || BackendError::Unavailable;
        let strong = |s: &str| {
            let b = s.as_bytes();
            b.len() >= 2
                && b.len() <= 4096
                && b.first() == Some(&b'"')
                && b.last() == Some(&b'"')
                && b[1..b.len() - 1]
                    .iter()
                    .all(|b| *b == 0x21 || (0x23..=0x7e).contains(b))
        };
        let id = |s: &str| !s.is_empty() && s.len() <= 4096 && !s.chars().any(char::is_control);
        if self.root.volume_serial != root.volume_serial
            || self.root.file_index != root.file_index
            || self.historical_unlock_epoch == 0
            || self.root.volume_serial == 0
            || self.root.file_index == 0
            || self.original_identity == [0; 16]
            || self.parent_identity == [0; 16]
            || self.original_identity == self.parent_identity
            || self.original.directory
            || !self.parent.directory
            || !id(&self.original.id)
            || !id(&self.parent.id)
            || self.original.id == self.parent.id
            || !strong(&self.original.etag)
            || !strong(&self.parent.etag)
            || self.remote_root.len() > 32000
            || raiun_core::validate_remote_path(&self.remote_root).is_err()
            || self.original.path.len() > 32000
            || self.parent.path.len() > 32000
            || self.original.path == "/"
            || raiun_core::validate_remote_path(&self.original.path).is_err()
            || raiun_core::validate_remote_path(&self.parent.path).is_err()
            || self.components.len() < 2
            || self.components.len() > 256
            || self.components.iter().map(String::len).sum::<usize>() > 32000
            || self
                .components
                .iter()
                .any(|s| !crate::opencloud::valid_windows_component(s))
            || self.original.path
                != format!(
                    "{}/{}",
                    self.parent.path.trim_end_matches('/'),
                    self.components.last().ok_or_else(bad)?
                )
            || self.original_usn <= 0
            || self.parent_usn <= 0
            || self.replacement_usn <= 0
            || [self.original_file, self.parent_file, self.replacement_file]
                .iter()
                .any(|f| {
                    f.volume_serial != self.root.volume_serial
                        || f.file_index == 0
                        || f.file_index == self.root.file_index
                })
            || self.original_file == self.replacement_file
            || self.parent_file == self.replacement_file
            || self.original_file == self.parent_file
            || self.plaintext_len > MAX_VAULT_FILE_REPLACE_BYTES
        {
            return Err(bad());
        }
        Ok(())
    }
}
impl VaultFileReplaceDescriptor {
    pub fn facts(&self) -> VaultFileReplaceFacts {
        VaultFileReplaceFacts {
            remote_root: self.remote_root.clone(),
            root: LocalFileIdentity {
                volume_serial: self.root.volume_serial,
                file_index: self.root.file_index,
            },
            original_identity: self.original_identity,
            original: self.original.clone(),
            parent_identity: self.parent_identity,
            parent: self.parent.clone(),
            historical_unlock_epoch: self.historical_unlock_epoch,
            original_file: self.original_file,
            original_usn: self.original_usn,
            parent_file: self.parent_file,
            parent_usn: self.parent_usn,
            replacement_file: self.replacement_file,
            replacement_usn: self.replacement_usn,
            components: self.components.clone(),
            plaintext_len: self.plaintext_len,
        }
    }
    pub fn validate(&self) -> Result<(), BackendError> {
        self.facts().validate(self.root)?;
        if self.owner.profile_id() != self.vault.account_id()
            || self.owner.server_origin() != self.vault.server_origin()
            || self.owner.token_generation() == 0
            || self.original.id == self.vault.resource_id()
        {
            return Err(BackendError::Unavailable);
        }
        Ok(())
    }
}
/// Returned by exact original-scope custody admission BEFORE body staging.
/// Dropping any incomplete state retains unknown evidence; never delete/heal it.
pub trait VaultFileReplaceCapture {
    fn stage(
        self: Box<Self>,
        source: &mut dyn Read,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Box<dyn VaultFileReplaceStaged>, BackendError>;
}
pub trait VaultFileReplaceStaged {
    /// The same native owner has reached EOF and validated original postproof.
    /// Compare its digest to authenticated staged data before Ready CAS/readback.
    fn commit(
        self: Box<Self>,
        native_sha256: [u8; 32],
        verify_source: &mut dyn FnMut() -> Result<(), BackendError>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Arc<dyn VaultFileReplaceRecord>, BackendError>;
}
pub trait VaultFileReplaceRecord: Send + Sync {
    fn descriptor(&self) -> &VaultFileReplaceDescriptor;
    fn plaintext_sha256(&self) -> [u8; 32];
    fn open_reader(
        &self,
        cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<Box<dyn Read + Send>, BackendError>;
    fn claim_send(&self) -> Result<(), BackendError>;
    fn record_remote(&self, proof: &VaultFileReplaceRemoteProof) -> Result<(), BackendError>;
    fn record_native_completed(
        &self,
        proof: &VaultFileReplaceNativeProof,
    ) -> Result<(), BackendError>;
}
/// Minted only after original-resource conditional overwrite and authenticated
/// whole-file digest readback, never from an arbitrary stat/recovered record.
pub struct VaultFileReplaceRemoteProof {
    pub(crate) descriptor: VaultFileReplaceDescriptor,
    pub(crate) target: crate::ExistingVaultUploadTarget,
    pub(crate) verified: raiun_opencloud::vault_backend::VaultVerifiedOverwrite,
}
impl VaultFileReplaceRemoteProof {
    pub fn descriptor(&self) -> &VaultFileReplaceDescriptor {
        &self.descriptor
    }
    pub fn entry(&self) -> &RemoteEntry {
        self.verified.entry()
    }
    pub fn plaintext_sha256(&self) -> [u8; 32] {
        self.verified.plaintext_sha256()
    }
}
/// Minted only by original native replacement owner after same-handle convert,
/// exact opaque/FI/USN/body proof and local in-sync completion.
pub struct VaultFileReplaceNativeProof {
    pub(crate) descriptor: VaultFileReplaceDescriptor,
    pub(crate) completed_usn: i64,
    pub(crate) plaintext_sha256: [u8; 32],
}
impl VaultFileReplaceNativeProof {
    pub fn descriptor(&self) -> &VaultFileReplaceDescriptor {
        &self.descriptor
    }
    pub fn completed_usn(&self) -> i64 {
        self.completed_usn
    }
    pub fn plaintext_sha256(&self) -> [u8; 32] {
        self.plaintext_sha256
    }
}
