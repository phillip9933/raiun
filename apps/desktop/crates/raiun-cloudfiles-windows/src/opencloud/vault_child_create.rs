//! Live vault child-create parent custody. Names select fresh catalog entries;
//! neither a pathname nor a durable record can reconstruct a live unlock.
use super::*;
use crate::namespace_intent::{CapturedAuthorization, NamespaceObjectKind};
use crate::vault_routes::VerifiedVaultRoute;
use raiun_core::backend::RemoteEntry;
use raiun_vault::session::VaultSessionScope;
use std::io::Read;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultChildCreateSource {
    pub kind: NamespaceObjectKind,
    pub volume: u32,
    pub file: u64,
    pub usn: i64,
    pub parent_file: u64,
    pub parent_usn: i64,
    pub components: Vec<String>,
    pub plaintext_len: u64,
    /// Present only for FILE. Directory carries native identity/USN facts, not file-content proof.
    pub plaintext_sha256: Option<[u8; 32]>,
}
impl VaultChildCreateSource {
    /// Structural history validation only; this never opens a native handle.
    pub fn validate(&self, root: crate::ConfiguredRootIdentity) -> Result<(), BackendError> {
        if root.volume_serial == 0
            || root.file_index == 0
            || self.volume != root.volume_serial
            || self.file == 0
            || self.file == root.file_index
            || self.file == self.parent_file
            || self.parent_file == 0
            || self.usn <= 0
            || self.parent_usn <= 0
            || self.components.len() < 2
            || self.components.len() > 256
            || self.components.iter().map(String::len).sum::<usize>() > 32000
            || self.components.iter().any(|p| !valid_windows_component(p))
            || self.plaintext_len > (1 << 30)
            || (self.kind == NamespaceObjectKind::File) != self.plaintext_sha256.is_some()
            || self.plaintext_sha256 == Some([0; 32])
            || (self.kind == NamespaceObjectKind::Directory && self.plaintext_len != 0)
        {
            return Err(BackendError::Unavailable);
        }
        Ok(())
    }
}
#[derive(Clone)]
pub struct VaultChildCreateDescriptor {
    pub owner: ProviderScope,
    pub vault: VaultSessionScope,
    pub remote_root: String,
    pub root: crate::ConfiguredRootIdentity,
    pub parent_identity: [u8; 16],
    pub parent: RemoteEntry,
    pub logical_path: String,
    pub encoded_target: String,
    pub integrity_token: String,
    pub historical_unlock_epoch: u64,
    pub source: VaultChildCreateSource,
}
impl VaultChildCreateDescriptor {
    pub fn validate(&self) -> Result<(), BackendError> {
        let s = &self.source;
        s.validate(self.root)?;
        if self.owner.profile_id() != self.vault.account_id()
            || self.owner.server_origin() != self.vault.server_origin()
            || self.owner.token_generation() == 0
            || self.historical_unlock_epoch == 0
            || self.root.volume_serial == 0
            || self.root.file_index == 0
            || s.volume != self.root.volume_serial
            || s.file == 0
            || s.file == self.root.file_index
            || s.parent_file == 0
            || s.usn <= 0
            || s.parent_usn <= 0
            || self.parent_identity == [0; 16]
            || !self.parent.directory
            || self.parent.id.is_empty()
            || !namespace::strong(&self.parent.etag)
            || self.logical_path == "/"
            || s.components.len() < 2
            || s.components.len() > 256
            || s.components.iter().any(|p| !valid_windows_component(p))
            || self.logical_path
                != format!(
                    "{}/{}",
                    self.parent.path.trim_end_matches('/'),
                    s.components.last().ok_or(BackendError::Unavailable)?
                )
            || self.encoded_target.is_empty()
            || self.integrity_token.is_empty()
            || s.plaintext_len > (1 << 30)
            || (s.kind == NamespaceObjectKind::File) != s.plaintext_sha256.is_some()
            || (s.kind == NamespaceObjectKind::Directory && s.plaintext_len != 0)
        {
            return Err(BackendError::Unavailable);
        }
        Ok(())
    }
}
/// One original fresh capture's durable record. Discovery never creates this
/// capability. It owns no native, account, route or unlock authority.
pub trait VaultChildCreateRecord: Send + Sync {
    fn descriptor(&self) -> &VaultChildCreateDescriptor;
    fn open_reader(
        &self,
        cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<Box<dyn Read + Send>, BackendError>;
    fn record_local_queued(
        &self,
        _receipt: &super::VaultCachedNamespaceQueued,
    ) -> Result<(), BackendError> {
        Err(BackendError::Unavailable)
    }
    fn record_local_queued_native(
        &self,
        _receipt: &super::VaultCachedNamespaceQueued,
        _identity: [u8; 16],
        _file: u64,
        _usn: i64,
    ) -> Result<(), BackendError> {
        Err(BackendError::Unavailable)
    }
    fn claim_send(&self) -> Result<(), BackendError>;
    fn record_remote(&self, proof: &VaultChildCreateRemoteProof) -> Result<(), BackendError>;
    fn record_native_completed(&self, identity: [u8; 16]) -> Result<(), BackendError>;
}
/// Separate local-only custody for a child of a queued directory. This trait
/// cannot provide a remote send or online completion method.
pub trait VaultCachedChildCreateRecord: Send + Sync {
    fn descriptor(&self) -> &super::VaultCachedChildCreateDescriptor;
    fn open_reader(
        &self,
        cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<Box<dyn Read + Send>, BackendError>;
    fn record_local_queued(
        &self,
        receipt: &super::VaultCachedNamespaceQueued,
    ) -> Result<(), BackendError>;
    fn record_local_queued_native(
        &self,
        receipt: &super::VaultCachedNamespaceQueued,
        identity: [u8; 16],
        file: u64,
        usn: i64,
    ) -> Result<(), BackendError>;
}
pub struct VaultChildCreateRemoteProof {
    descriptor: VaultChildCreateDescriptor,
    entry: RemoteEntry,
}
impl VaultChildCreateRemoteProof {
    pub fn descriptor(&self) -> &VaultChildCreateDescriptor {
        &self.descriptor
    }
    pub fn entry(&self) -> &RemoteEntry {
        &self.entry
    }
    pub(crate) fn new(
        descriptor: &VaultChildCreateDescriptor,
        entry: &RemoteEntry,
    ) -> Result<Self, BackendError> {
        descriptor.validate()?;
        if entry.id.is_empty()
            || entry.id == descriptor.parent.id
            || entry.id == descriptor.vault.resource_id()
            || !namespace::strong(&entry.etag)
            || entry.path != descriptor.logical_path
            || entry.directory != (descriptor.source.kind == NamespaceObjectKind::Directory)
            || entry.size != descriptor.source.plaintext_len
        {
            return Err(BackendError::Unavailable);
        }
        Ok(Self {
            descriptor: descriptor.clone(),
            entry: entry.clone(),
        })
    }
}
/// Nonconstructible original live parent. The epoch stays inside the retained
/// read binding and SDK targets; numeric historical labels never admit work.
pub(crate) struct VaultChildCreateParent {
    backend: Arc<OpenCloudPlaceholderBackend>,
    route: Arc<VerifiedVaultRoute>,
    root: crate::ConfiguredRootIdentity,
    components: Vec<String>,
    path_route: Vec<crate::PlaceholderChild>,
    identity: OpaqueIdentity,
    metadata: RemoteEntry,
    authorization: CapturedAuthorization,
    job: crate::StreamedRecoveryJob,
    current: file_create::Current,
    generation: Arc<AtomicU64>,
}
impl VaultChildCreateParent {
    pub(crate) fn components(&self) -> &[String] {
        &self.components
    }
    pub(crate) fn route(&self) -> &[crate::PlaceholderChild] {
        &self.path_route
    }
    pub(crate) fn opaque(&self) -> OpaqueIdentity {
        self.identity
    }
    pub(crate) fn metadata(&self) -> &RemoteEntry {
        &self.metadata
    }
    pub(crate) fn root(&self) -> crate::ConfiguredRootIdentity {
        self.root
    }

    pub(crate) fn job(&self) -> &crate::StreamedRecoveryJob {
        &self.job
    }
    pub(crate) fn vault(&self) -> &Arc<VerifiedVaultRoute> {
        &self.route
    }
    pub(crate) fn is_stopped(&self) -> bool {
        self.job.is_stopped()
            || !(self.current)(self.authorization)
            || self.backend.is_revoked()
            || self.route.backend().binding().is_revoked()
            || self.generation.load(Ordering::Acquire) != self.authorization.agent_generation
    }
    pub(crate) fn generation(&self) -> Arc<AtomicU64> {
        self.generation.clone()
    }
    pub(crate) fn authorization(&self) -> CapturedAuthorization {
        self.authorization
    }
    pub(crate) fn check(&self) -> Result<(), BackendError> {
        self.job.check()?;
        if self.is_stopped() {
            return Err(BackendError::Unavailable);
        }
        if !(self.current)(self.authorization)
            || self.backend.is_revoked()
            || self.backend.local_root_identity != Some(self.root)
        {
            return Err(BackendError::Unavailable);
        }
        self.route.backend().check_child_create_parent(
            self.identity.as_bytes(),
            &self.metadata,
            self.root,
        )
    }
    pub(crate) fn descriptor(
        &self,
        source: VaultChildCreateSource,
        encoded: &str,
        integrity: &str,
    ) -> Result<VaultChildCreateDescriptor, BackendError> {
        self.check()?;
        self.route.backend().binding().child_create_descriptor(
            self.root,
            self.identity.as_bytes(),
            &self.metadata,
            source,
            encoded,
            integrity,
        )
    }
    pub(crate) fn cached_descriptor(
        &self,
        source: VaultChildCreateSource,
        encoded: &str,
        integrity: &str,
    ) -> Result<super::VaultCachedChildCreateDescriptor, BackendError> {
        self.check()?;
        self.route
            .backend()
            .binding()
            .cached_child_create_descriptor(
                self.root,
                self.identity.as_bytes(),
                &self.metadata,
                source,
                encoded,
                integrity,
            )
    }
    pub(crate) fn prepare_cached_record(
        &self,
        descriptor: &super::VaultCachedChildCreateDescriptor,
        source: Option<&mut dyn Read>,
        verify: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<Arc<dyn VaultCachedChildCreateRecord>, BackendError> {
        self.check()?;
        self.route
            .backend()
            .prepare_cached_child_create_record(descriptor, source, verify, &|| {
                self.job.is_stopped()
            })
    }
    pub(crate) fn prepare_record(
        &self,
        descriptor: &VaultChildCreateDescriptor,
        source: Option<&mut dyn Read>,
        verify: &mut dyn FnMut() -> Result<(), BackendError>,
    ) -> Result<Arc<dyn VaultChildCreateRecord>, BackendError> {
        self.check()?;
        self.route
            .backend()
            .prepare_child_create_record(descriptor, source, verify, &|| self.job.is_stopped())
    }
}
impl OpenCloudPlaceholderBackend {
    /// Fresh composite traversal; None is proven ordinary parent only. Locked,
    /// unknown or historically encrypted paths refuse rather than fall through.
    pub(crate) fn capture_vault_child_create_parent(
        self: &Arc<Self>,
        components: &[String],
        root: crate::ConfiguredRootIdentity,
        authorization: CapturedAuthorization,
        job: &crate::StreamedRecoveryJob,
        current: file_create::Current,
        generation: Arc<AtomicU64>,
    ) -> Result<Option<Arc<VaultChildCreateParent>>, BackendError> {
        let _lease = self
            .lease_gate
            .read()
            .map_err(|_| BackendError::Unavailable)?;
        self.ensure_active()?;
        job.check()?;
        if components.is_empty()
            || components.len() > 255
            || components.iter().any(|p| !valid_windows_component(p))
            || authorization.token_generation != self.token_generation
            || !(current)(authorization)
            || self
                .catalog_scope_snapshot()?
                .is_none_or(|c| c.local_root() != root)
        {
            return Err(BackendError::Unavailable);
        }
        // Local dispatch preference only: the ordinary factory still performs
        // its unchanged fresh encryption/root/parent checks before mutation.
        let Some(routes) = self.vault_routes.as_ref() else {
            return Ok(None);
        };
        if !routes.has_active_routes()? {
            return Ok(None);
        }
        let catalog = self
            .catalog_scope_snapshot()?
            .ok_or(BackendError::Unavailable)?;
        let location = {
            let state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
            let candidates = match components.first().map(String::as_str) {
                Some("Personal") => vec![(
                    catalog.personal_space_id().to_owned(),
                    catalog.personal_root_resource_id().to_owned(),
                    1,
                )],
                Some("Spaces") if components.len() >= 2 => state
                    .location_labels
                    .iter()
                    .filter(|(_, label)| **label == format!("Spaces / {}", components[1]))
                    .map(|((space, root), _)| (space.clone(), root.clone(), 2))
                    .collect(),
                _ => Vec::new(),
            };
            if candidates.len() == 1 {
                let (space, root, prefix) = &candidates[0];
                let path = if components.len() == *prefix {
                    "/".to_owned()
                } else {
                    format!("/{}", components[*prefix..].join("/"))
                };
                let mut matches = state.directories.values().filter(|d| {
                    d.space_id == *space && d.root_resource_id == *root && d.path == path
                });
                let value = matches.next().map(|d| (d.space_id.clone(), d.path.clone()));
                if matches.next().is_some() {
                    None
                } else {
                    value
                }
            } else {
                None
            }
        };
        if let Some((space, path)) = location
            && !routes.covers_path(&space, &path)?
        {
            return Ok(None);
        }
        let metadata_budget = job.cancellation().bounded_request();
        let mut identity = {
            let state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
            let mut roots=state.namespace_directories.iter().filter_map(|(id,kind)|matches!(kind,NamespaceDirectory::Root{account_id,..} if account_id==self.scope.account_id()).then_some(*id));
            let id = roots.next().ok_or(BackendError::Unavailable)?;
            if roots.next().is_some() {
                return Err(BackendError::Unavailable);
            }
            id
        };
        let mut path_route = Vec::new();
        for component in components {
            job.check()?;
            let mut matches = self
                .enumerate_scoped(identity.as_bytes(), &metadata_budget)?
                .into_iter()
                .filter(|c| c.name == *component && c.metadata.is_directory);
            let child = matches.next().ok_or(BackendError::NotFound)?;
            if matches.next().is_some() {
                return Err(BackendError::Unavailable);
            }
            identity = OpaqueIdentity(
                child
                    .identity
                    .as_slice()
                    .try_into()
                    .map_err(|_| BackendError::Unavailable)?,
            );
            path_route.push(child);
        }
        let Some(route) = self.vault_for_identity(identity.as_bytes())? else {
            return Ok(None);
        };
        let metadata = route
            .backend()
            .child_create_parent_metadata(identity.as_bytes(), &metadata_budget)?;
        job.check()?;
        if !(current)(authorization)
            || metadata_budget.is_expired()
            || metadata_budget.is_cancelled()
        {
            return Err(BackendError::Unavailable);
        }
        let result = Arc::new(VaultChildCreateParent {
            backend: self.clone(),
            route,
            root,
            components: components.to_vec(),
            path_route,
            identity,
            metadata,
            authorization,
            job: job.clone(),
            current,
            generation,
        });
        result.check()?;
        Ok(Some(result))
    }
}
