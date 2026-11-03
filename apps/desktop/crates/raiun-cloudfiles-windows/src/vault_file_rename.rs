//! Vault-only rename evidence. Serialized values are history, never live authority.
use crate::{BackendError, ConfiguredRootIdentity, ProviderScope};
use raiun_core::backend::RemoteEntry;
use raiun_vault::session::VaultSessionScope;
use serde::{Deserialize, Serialize};
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultDirectoryRenameNode {
    pub identity: [u8; 16],
    pub file: u64,
    pub usn: i64,
    pub original: RemoteEntry,
    pub new_components: Vec<String>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultFileRenameDestination {
    pub identity: [u8; 16],
    pub parent: RemoteEntry,
    pub file: u64,
    pub usn: i64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultFileRenameFacts {
    pub volume: u32,
    pub file: u64,
    pub usn: i64,
    pub parent_file: u64,
    pub parent_usn: i64,
    pub identity: [u8; 16],
    pub parent_identity: [u8; 16],
    pub old_components: Vec<String>,
    pub new_components: Vec<String>,
    pub original: RemoteEntry,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub children: Option<Vec<VaultDirectoryRenameNode>>,
    pub parent: RemoteEntry,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_parent: Option<VaultFileRenameDestination>,
    pub destination: String,
    pub encoded_source: String,
    pub encoded_destination: String,
    pub integrity: String,
    pub historical_epoch: u64,
    pub token_generation: u64,
}
impl VaultFileRenameFacts {
    pub fn validate(&self, root: ConfiguredRootIdentity) -> Result<(), BackendError> {
        let valid = |p: &Vec<String>| {
            p.len() >= 2
                && p.len() <= 256
                && p.iter().map(String::len).sum::<usize>() <= 32000
                && p.iter()
                    .all(|s| crate::opencloud::valid_windows_component(s))
        };
        let bound = |s: &str| !s.is_empty() && s.len() <= 4096 && !s.chars().any(char::is_control);
        let parent = |p: &str| {
            p.rsplit_once('/')
                .map(|(p, _)| if p.is_empty() { "/" } else { p })
                .unwrap_or("/")
                .to_owned()
        };
        if root.volume_serial == 0
            || root.file_index == 0
            || self.volume != root.volume_serial
            || self.file == 0
            || self.file == root.file_index
            || self.parent_file == 0
            || self.file == self.parent_file
            || self.usn <= 0
            || self.parent_usn <= 0
            || self.identity == [0; 16]
            || self.parent_identity == [0; 16]
            || self.identity == self.parent_identity
            || !valid(&self.old_components)
            || !valid(&self.new_components)
            || self
                .old_components
                .iter()
                .map(|s| s.to_lowercase())
                .eq(self.new_components.iter().map(|s| s.to_lowercase()))
            || self.original.directory != self.children.is_some()
            || (self.original.directory && self.original.size != 0)
            || !self.parent.directory
            || !bound(&self.original.id)
            || !bound(&self.parent.id)
            || self.original.id == self.parent.id
            || self.original.path == "/"
        {
            return Err(BackendError::Unavailable);
        }
        let dp = self
            .destination_parent
            .as_ref()
            .map(|p| &p.parent)
            .unwrap_or(&self.parent);
        if let Some(p) = &self.destination_parent {
            if p.identity == [0; 16]
                || p.identity == self.identity
                || p.file == 0
                || p.file == self.file
                || p.usn <= 0
                || !p.parent.directory
                || !bound(&p.parent.id)
                || p.parent.id == self.original.id
                || !strong(&p.parent.etag)
                || raiun_core::validate_remote_path(&p.parent.path).is_err()
            {
                return Err(BackendError::Unavailable);
            }
        } else if self.old_components[..self.old_components.len() - 1]
            != self.new_components[..self.new_components.len() - 1]
        {
            return Err(BackendError::Unavailable);
        }
        if raiun_core::validate_remote_path(&self.original.path).is_err()
            || raiun_core::validate_remote_path(&self.destination).is_err()
            || parent(&self.original.path) != self.parent.path
            || parent(&self.destination) != dp.path
            || self.original.path
                != format!(
                    "{}/{}",
                    self.parent.path.trim_end_matches('/'),
                    self.old_components.last().unwrap()
                )
            || raiun_core::validate_remote_path(&self.parent.path).is_err()
            || self.destination
                != format!(
                    "{}/{}",
                    dp.path.trim_end_matches('/'),
                    self.new_components.last().unwrap()
                )
            || !crate::vault_file_rename::strong(&self.original.etag)
            || !strong(&self.parent.etag)
            || !bound(&self.encoded_source)
            || !bound(&self.encoded_destination)
            || !bound(&self.integrity)
            || self.encoded_source == self.encoded_destination
            || self.token_generation == 0
            || self.historical_epoch == 0
        {
            return Err(BackendError::Unavailable);
        }
        if let Some(children) = &self.children {
            if children.len() > 1023 {
                return Err(BackendError::Unavailable);
            }
            let mut ids = std::collections::BTreeSet::from([self.identity]);
            let mut files = std::collections::BTreeSet::from([self.file]);
            let mut remote = std::collections::BTreeSet::from([self.original.id.clone()]);
            let mut paths = std::collections::BTreeSet::from([self.original.path.to_lowercase()]);
            for n in children {
                let suffix = n
                    .original
                    .path
                    .strip_prefix(&format!("{}/", self.original.path))
                    .ok_or(BackendError::Unavailable)?;
                let parts = suffix.split('/').map(str::to_owned).collect::<Vec<_>>();
                let mut expected = self.new_components.clone();
                expected.extend(parts.iter().cloned());
                if n.identity == [0; 16]
                    || n.identity == self.parent_identity
                    || n.file == 0
                    || n.file == root.file_index
                    || n.file == self.parent_file
                    || n.usn <= 0
                    || !ids.insert(n.identity)
                    || !files.insert(n.file)
                    || !remote.insert(n.original.id.clone())
                    || !paths.insert(n.original.path.to_lowercase())
                    || !bound(&n.original.id)
                    || !strong(&n.original.etag)
                    || parts
                        .iter()
                        .any(|p| !crate::opencloud::valid_windows_component(p))
                    || n.new_components != expected
                    || !valid(&n.new_components)
                    || (n.original.directory && n.original.size != 0)
                {
                    return Err(BackendError::Unavailable);
                }
                let parent_path = parent(&n.original.path);
                if parent_path != self.original.path
                    && !children
                        .iter()
                        .any(|p| p.original.directory && p.original.path == parent_path)
                {
                    return Err(BackendError::Unavailable);
                }
            }
            if self
                .destination
                .starts_with(&format!("{}/", self.original.path))
            {
                return Err(BackendError::Unavailable);
            }
        }
        Ok(())
    }
}
fn strong(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 2
        && b.len() <= 4096
        && b[0] == b'"'
        && b[b.len() - 1] == b'"'
        && b[1..b.len() - 1]
            .iter()
            .all(|v| *v == 0x21 || (0x23..=0x7e).contains(v))
}
#[derive(Clone)]
pub struct VaultFileRenameDescriptor {
    pub owner: ProviderScope,
    pub vault: VaultSessionScope,
    pub remote_root: String,
    pub root: ConfiguredRootIdentity,
    pub facts: VaultFileRenameFacts,
}
impl VaultFileRenameDescriptor {
    pub fn validate(&self) -> Result<(), BackendError> {
        self.facts.validate(self.root)?;
        if self.owner.profile_id() != self.vault.account_id()
            || self.owner.server_origin() != self.vault.server_origin()
            || self.owner.token_generation() != self.facts.token_generation
            || self.facts.original.id == self.vault.resource_id()
            || self.facts.children.as_ref().is_some_and(|rows| {
                rows.iter()
                    .any(|n| n.original.id == self.vault.resource_id())
            })
            || raiun_core::validate_remote_path(&self.remote_root).is_err()
        {
            return Err(BackendError::Unavailable);
        }
        Ok(())
    }
}
pub trait VaultFileRenameRecord: Send + Sync {
    fn record_directory_remote(
        &self,
        _proof: &raiun_opencloud::vault_backend::VaultVerifiedDirectoryRename,
    ) -> Result<(), BackendError> {
        Err(BackendError::Unavailable)
    }
    fn record_directory_native(&self, _nodes: &[(u64, i64)]) -> Result<(), BackendError> {
        Err(BackendError::Unavailable)
    }
    fn claim_send(&self) -> Result<(), BackendError>;
    fn record_remote(
        &self,
        proof: &raiun_opencloud::vault_backend::VaultVerifiedFileRename,
    ) -> Result<(), BackendError>;
    fn record_native(&self, file: u64, usn: i64) -> Result<(), BackendError>;
}
