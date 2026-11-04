//! Explicit cached capture history. These facts never recreate a live route,
//! provider generation, unlock, original strong validator or upload capability.
use crate::{BackendError, ConfiguredRootIdentity, LocalFileIdentity};
use raiun_core::backend::RemoteEntry;

#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CachedVaultEditOperation {
    Overwrite,
    CreateFile,
}
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CachedVaultEditPending {
    pub write_id: String,
    pub revision: u64,
    pub operation: CachedVaultEditOperation,
}
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CachedVaultEditBaselineFacts {
    pub profile_id: String,
    pub account_id: String,
    pub server_origin: String,
    pub space_id: String,
    pub root_resource_id: String,
    pub remote_root: String,
    pub root: LocalFileIdentity,
    pub token_generation: u64,
    pub historical_unlock_epoch: u64,
    pub identity: [u8; 16],
    /// Exact current catalogue presentation, including a pending alias when present.
    pub current: RemoteEntry,
    /// Strong original remote baseline ONLY when it genuinely existed.
    pub original_base: Option<RemoteEntry>,
    pub pending: Option<CachedVaultEditPending>,
    pub file: LocalFileIdentity,
    pub usn: i64,
    pub components: Vec<String>,
    pub plaintext_len: u64,
    pub plaintext_sha256: [u8; 32],
}
impl CachedVaultEditBaselineFacts {
    pub fn validate(&self, root: ConfiguredRootIdentity) -> Result<(), BackendError> {
        let bounded = |s: &str, max: usize| {
            !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control)
        };
        let strong = |s: &str| {
            let b = s.as_bytes();
            b.len() >= 2
                && b.len() <= 4096
                && b[0] == b'"'
                && b[b.len() - 1] == b'"'
                && b[1..b.len() - 1]
                    .iter()
                    .all(|b| *b == 0x21 || (0x23..=0x7e).contains(b))
        };
        let scope = raiun_vault::session::VaultSessionScope::new(
            &self.profile_id,
            &self.server_origin,
            &self.space_id,
            &self.root_resource_id,
        )
        .map_err(|_| BackendError::Unavailable)?;
        if scope.account_id() != self.profile_id
            || scope.server_origin() != self.server_origin
            || !bounded(&self.account_id, 4096)
            || self.token_generation == 0
            || self.historical_unlock_epoch == 0
            || self.root.volume_serial != root.volume_serial
            || self.root.file_index != root.file_index
            || root.volume_serial == 0
            || root.file_index == 0
            || self.identity == [0; 16]
            || self.file.volume_serial != root.volume_serial
            || self.file.file_index == 0
            || self.file.file_index == root.file_index
            || self.usn <= 0
            || self.components.len() < 2
            || self.components.len() > 256
            || self.components.iter().map(String::len).sum::<usize>() > 32000
            || self
                .components
                .iter()
                .any(|p| !crate::opencloud::valid_windows_component(p))
            || self.plaintext_len > crate::vault_custody::MAX_STREAMED_VAULT_EDIT_BYTES
            || self.plaintext_sha256 == [0; 32]
            || self.current.directory
            || self.current.path == "/"
            || self.current.path.rsplit('/').next() != self.components.last().map(String::as_str)
            || !bounded(&self.current.id, 4096)
            || raiun_core::validate_remote_path(&self.current.path).is_err()
            || raiun_core::validate_remote_path(&self.remote_root).is_err()
        {
            return Err(BackendError::Unavailable);
        }
        match (&self.pending, &self.original_base) {
            (None, Some(base))
                if base.id == self.current.id
                    && base.path == self.current.path
                    && base.etag == self.current.etag
                    && base.size == self.current.size
                    && strong(&base.etag) =>
            {
                ()
            }
            (Some(p), base) => {
                if p.write_id.is_empty()
                    || p.write_id.len() > 512
                    || p.revision == 0
                    || self.current.etag
                        != format!("raiun-pending-v1:{}:{}", p.write_id, p.revision)
                {
                    return Err(BackendError::Unavailable);
                }
                match (p.operation, base) {
                    (CachedVaultEditOperation::Overwrite, Some(base))
                        if !base.directory
                            && base.id == self.current.id
                            && base.path == self.current.path
                            && strong(&base.etag) =>
                    {
                        ()
                    }
                    (CachedVaultEditOperation::CreateFile, None)
                        if self.current.id == format!("raiun-pending-create:{}", p.write_id) =>
                    {
                        ()
                    }
                    _ => return Err(BackendError::Unavailable),
                }
            }
            _ => return Err(BackendError::Unavailable),
        }
        Ok(())
    }
}

/// Borrowed inside the original lexical route/token/exact-unlock fences.
/// The final source facts carry actual native FI/USN/full-body digest; there is
/// no online baseline adapter and no serialized unlock restoration.
pub trait CachedVaultEditCapture {
    /// Metadata-only template. Native proof fields are populated only by
    /// baseline_facts after actual original-handle prehash/FI/USN inspection.
    fn catalogue_facts(&self) -> &CachedVaultEditBaselineFacts;
    fn stream_revocation(&self) -> std::sync::Arc<dyn Fn() -> bool + Send + Sync>;
    fn retain_streamed(
        &self,
        facts: CachedVaultEditBaselineFacts,
        source: &mut dyn std::io::Read,
        verify_source: &mut dyn FnMut() -> Result<(), BackendError>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Option<Box<dyn crate::DeferredVaultCaptureNotification>>, BackendError>;
    fn baseline_facts(
        &self,
        file: LocalFileIdentity,
        usn: i64,
        components: Vec<String>,
        length: u64,
        sha256: [u8; 32],
    ) -> Result<CachedVaultEditBaselineFacts, BackendError>;
}

pub enum VaultEditCaptureContext<'a> {
    Online(&'a dyn crate::ExistingVaultEditCapture),
    Cached(&'a dyn CachedVaultEditCapture),
}
pub struct VaultEditBaselineView<'a> {
    identity: [u8; 16],
    root: ConfiguredRootIdentity,
    metadata: &'a RemoteEntry,
    token_generation: u64,
    historical_unlock_epoch: u64,
}
impl VaultEditBaselineView<'_> {
    pub fn identity(&self) -> [u8; 16] {
        self.identity
    }
    pub fn root(&self) -> ConfiguredRootIdentity {
        self.root
    }
    pub fn metadata(&self) -> &RemoteEntry {
        self.metadata
    }
    pub fn token_generation(&self) -> u64 {
        self.token_generation
    }
    pub fn unlock_epoch(&self) -> u64 {
        self.historical_unlock_epoch
    }
}
impl VaultEditCaptureContext<'_> {
    pub fn baseline(&self) -> VaultEditBaselineView<'_> {
        match self {
            Self::Online(c) => {
                let b = c.baseline();
                VaultEditBaselineView {
                    identity: b.identity(),
                    root: b.root(),
                    metadata: b.metadata(),
                    token_generation: b.token_generation(),
                    historical_unlock_epoch: b.unlock_epoch(),
                }
            }
            Self::Cached(c) => {
                let b = c.catalogue_facts();
                VaultEditBaselineView {
                    identity: b.identity,
                    root: ConfiguredRootIdentity {
                        volume_serial: b.root.volume_serial,
                        file_index: b.root.file_index,
                    },
                    metadata: &b.current,
                    token_generation: b.token_generation,
                    historical_unlock_epoch: b.historical_unlock_epoch,
                }
            }
        }
    }
    pub fn stream_revocation(&self) -> Option<std::sync::Arc<dyn Fn() -> bool + Send + Sync>> {
        match self {
            Self::Online(c) => c.stream_revocation(),
            Self::Cached(c) => Some(c.stream_revocation()),
        }
    }
    pub fn retain_streamed_with_usn(
        &self,
        payload: crate::vault_custody::ExistingVaultStreamedEditPayload,
        usn: i64,
        source: &mut dyn std::io::Read,
        verify: &mut dyn FnMut() -> Result<(), BackendError>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Option<Box<dyn crate::DeferredVaultCaptureNotification>>, BackendError> {
        match self {
            Self::Online(c) => c.retain_streamed(payload, source, verify, cancelled),
            Self::Cached(c) => {
                let facts = c.baseline_facts(
                    payload.file,
                    usn,
                    payload.components,
                    payload.length,
                    payload.sha256,
                )?;
                if facts.root.volume_serial != payload.root.volume_serial
                    || facts.root.file_index != payload.root.file_index
                {
                    return Err(BackendError::Unavailable);
                }
                c.retain_streamed(facts, source, verify, cancelled)
            }
        }
    }
}
