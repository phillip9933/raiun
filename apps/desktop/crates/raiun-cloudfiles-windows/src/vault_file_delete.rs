//! Factual clean FILE deletion through the original live native owner.
//! No persisted descriptor or local absence can reconstruct cloud authority.
use crate::{BackendError, ConfiguredRootIdentity, LocalFileIdentity, ProviderScope};
use raiun_core::backend::RemoteEntry;
use raiun_vault::session::VaultSessionScope;
#[derive(Clone)]
pub struct VaultFileDeleteDescriptor {
    pub owner: ProviderScope,
    pub vault: VaultSessionScope,
    pub remote_root: String,
    pub root: ConfiguredRootIdentity,
    pub original_identity: [u8; 16],
    pub original: RemoteEntry,
    pub empty_directory: bool,
    pub parent_identity: [u8; 16],
    pub parent: RemoteEntry,
    pub historical_unlock_epoch: u64,
    pub original_file: LocalFileIdentity,
    pub original_usn: i64,
    pub parent_file: LocalFileIdentity,
    pub parent_usn: i64,
    pub components: Vec<String>,
}
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultFileDeleteFacts {
    pub remote_root: String,
    pub root: LocalFileIdentity,
    pub original_identity: [u8; 16],
    pub original: RemoteEntry,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub empty_directory: bool,
    pub parent_identity: [u8; 16],
    pub parent: RemoteEntry,
    pub historical_unlock_epoch: u64,
    pub original_file: LocalFileIdentity,
    pub original_usn: i64,
    pub parent_file: LocalFileIdentity,
    pub parent_usn: i64,
    pub components: Vec<String>,
}
impl VaultFileDeleteFacts {
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
            || self.original.directory != self.empty_directory
            || (self.empty_directory && self.original.size != 0)
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
            || [self.original_file, self.parent_file].iter().any(|f| {
                f.volume_serial != self.root.volume_serial
                    || f.file_index == 0
                    || f.file_index == self.root.file_index
            })
            || self.original_file == self.parent_file
        {
            return Err(bad());
        }
        Ok(())
    }
}
impl VaultFileDeleteDescriptor {
    pub fn facts(&self) -> VaultFileDeleteFacts {
        VaultFileDeleteFacts {
            remote_root: self.remote_root.clone(),
            root: LocalFileIdentity {
                volume_serial: self.root.volume_serial,
                file_index: self.root.file_index,
            },
            original_identity: self.original_identity,
            original: self.original.clone(),
            empty_directory: self.empty_directory,
            parent_identity: self.parent_identity,
            parent: self.parent.clone(),
            historical_unlock_epoch: self.historical_unlock_epoch,
            original_file: self.original_file,
            original_usn: self.original_usn,
            parent_file: self.parent_file,
            parent_usn: self.parent_usn,
            components: self.components.clone(),
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
/// Returned only to the retained original native delete owner after exact
/// scope/index admission. No recovery constructor or automatic dispatch exists.
pub trait VaultFileDeleteRecord: Send + Sync {
    fn record_local_queued(
        &self,
        _receipt: &crate::VaultCachedNamespaceQueued,
    ) -> Result<(), BackendError> {
        Err(BackendError::Unavailable)
    }
    fn record_local_queued_native(
        &self,
        _receipt: &crate::VaultCachedNamespaceQueued,
        _identity: [u8; 16],
        _file: u64,
        _usn: i64,
    ) -> Result<(), BackendError> {
        Err(BackendError::Unavailable)
    }

    fn descriptor(&self) -> &VaultFileDeleteDescriptor;
    fn claim_send(&self) -> Result<(), BackendError>;
    fn record_remote(&self, proof: &VaultFileDeleteRemoteProof) -> Result<(), BackendError>;
    fn record_native_completed(
        &self,
        proof: &VaultFileDeleteNativeProof,
    ) -> Result<(), BackendError>;
}
/// Actual guarded SDK original-ID/strong-ETag DELETE and exact NotFound proof.
pub struct VaultFileDeleteRemoteProof {
    pub(crate) descriptor: VaultFileDeleteDescriptor,
    pub(crate) target: Option<crate::ExistingVaultUploadTarget>,
    pub(crate) directory_dispatch: Option<crate::FreshVaultCaptureDispatch>,
    pub(crate) verified: raiun_opencloud::vault_backend::VaultVerifiedFileDelete,
}
impl VaultFileDeleteRemoteProof {
    pub fn descriptor(&self) -> &VaultFileDeleteDescriptor {
        &self.descriptor
    }
    pub fn verified(&self) -> &raiun_opencloud::vault_backend::VaultVerifiedFileDelete {
        &self.verified
    }
    pub fn original(&self) -> &RemoteEntry {
        &self.descriptor.original
    }
}
/// Exact original ACK+DELETE_COMPLETION and fresh same-name absence while
/// original root/parent/route/admission pins remain owned. Not path-only input.
pub struct VaultFileDeleteNativeProof {
    pub(crate) descriptor: VaultFileDeleteDescriptor,
    pub(crate) parent_usn_after: i64,
}
impl VaultFileDeleteNativeProof {
    pub fn descriptor(&self) -> &VaultFileDeleteDescriptor {
        &self.descriptor
    }
    pub fn parent_usn_after(&self) -> i64 {
        self.parent_usn_after
    }
}
