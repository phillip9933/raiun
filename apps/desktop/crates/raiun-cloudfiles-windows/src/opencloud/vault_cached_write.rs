//! Local-only encrypted journal admission. These receipts are NOT remote or
//! native-completion proofs and cannot be used by the online completion APIs.
use super::*;
use raiun_core::backend::{CloudError, RemoteEntry};

pub struct VaultCachedQueuedEdit {
    original: RemoteEntry,
    entry: RemoteEntry,
    write_id: String,
    revision: u64,
    source_sha256: [u8; 32],
    plaintext_len: u64,
    // Retain the exact original route, never resolve a replacement from history.
    _route: Arc<crate::vault_routes::VerifiedVaultRoute>,
}
impl VaultCachedQueuedEdit {
    pub fn write_id(&self) -> &str {
        &self.write_id
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn original(&self) -> &RemoteEntry {
        &self.original
    }
    pub fn entry(&self) -> &RemoteEntry {
        &self.entry
    }
    pub fn source_sha256(&self) -> [u8; 32] {
        self.source_sha256
    }
    pub fn plaintext_len(&self) -> u64 {
        self.plaintext_len
    }
}

impl OpenCloudPlaceholderBackend {
    /// The source must be the authenticated protected capture belonging to this
    /// fresh original dispatch. No source/path is read from ordinary FileCache.
    pub fn queue_cached_vault_existing_capture<R: std::io::Read>(
        &self,
        target: &crate::ExistingVaultUploadTarget,
        source: &mut R,
        edited_len: u64,
        expected_sha: [u8; 32],
        provider_generation: Arc<AtomicU64>,
        expected_provider_generation: u64,
        cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<VaultCachedQueuedEdit, CloudError> {
        let refused = || CloudError::new(ErrorKind::Forbidden, "cached vault edit route changed");
        let route = {
            let _lease = self.lease_gate.read().map_err(|_| refused())?;
            self.ensure_active().map_err(|_| refused())?;
            if !self.client.is_offline()
                || target.dispatch().is_none()
                || target.owner() != &self.scope
                || self.local_root_identity != Some(target.root())
                || expected_provider_generation == 0
                || provider_generation.load(Ordering::Acquire) != expected_provider_generation
                || cancelled()
                || edited_len > crate::vault_custody::MAX_STREAMED_VAULT_EDIT_BYTES
            {
                return Err(refused());
            }
            let route = self
                .vault_for_identity(target.identity())
                .map_err(|_| refused())?
                .ok_or_else(refused)?;
            if route.local_root() != target.root()
                || route.space_id() != target.vault().space_id()
                || route.root_resource_id() != target.vault().resource_id()
                || route.root_path() != target.remote_root()
            {
                return Err(refused());
            }
            route.backend().validate_capture_dispatch_target(target)?;
            route
        };
        // Called by local crypto while the coordinator owns its exact epoch.
        // This predicate is deliberately atomics-only: no token/route/session lock.
        let stop = || {
            self.is_revoked()
                || route.backend().binding().is_revoked()
                || provider_generation.load(Ordering::Acquire) != expected_provider_generation
                || cancelled()
        };
        let result = route.backend().binding().queue_cached_existing_capture(
            target,
            source,
            edited_len,
            expected_sha,
            &stop,
        )?;
        if stop() {
            return Err(refused());
        }
        route.backend().validate_capture_dispatch_target(target)?;
        let raiun_opencloud::vault_backend::VaultUploadOutcome::Queued {
            entry,
            write_id,
            revision,
            uncertain: false,
        } = result
        else {
            return Err(refused());
        };
        if revision == 0
            || write_id.is_empty()
            || write_id.len() > 512
            || entry.directory
            || entry.id != target.original().id
            || entry.path != target.original().path
            || entry.size != edited_len
        {
            return Err(refused());
        }
        Ok(VaultCachedQueuedEdit {
            original: target.original().clone(),
            entry,
            write_id,
            revision,
            source_sha256: expected_sha,
            plaintext_len: edited_len,
            _route: route,
        })
    }
}

pub struct VaultCachedQueuedCapture {
    facts: crate::vault_cached_edit::CachedVaultEditBaselineFacts,
    entry: RemoteEntry,
    write_id: String,
    revision: u64,
    _route: Arc<crate::vault_routes::VerifiedVaultRoute>,
}
impl VaultCachedQueuedCapture {
    pub fn facts(&self) -> &crate::vault_cached_edit::CachedVaultEditBaselineFacts {
        &self.facts
    }
    pub fn entry(&self) -> &RemoteEntry {
        &self.entry
    }
    pub fn write_id(&self) -> &str {
        &self.write_id
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn plaintext_len(&self) -> u64 {
        self.facts.plaintext_len
    }
    pub fn source_sha256(&self) -> [u8; 32] {
        self.facts.plaintext_sha256
    }
}
impl OpenCloudPlaceholderBackend {
    fn cached_capture_route(
        &self,
        facts: &crate::vault_cached_edit::CachedVaultEditBaselineFacts,
        dispatch: &crate::FreshVaultCaptureDispatch,
    ) -> Result<Arc<crate::vault_routes::VerifiedVaultRoute>, CloudError> {
        let no = || CloudError::new(ErrorKind::Forbidden, "cached vault capture changed");
        self.ensure_active().map_err(|_| no())?;
        let root = self.local_root_identity.ok_or_else(no)?;
        facts.validate(root).map_err(|_| no())?;
        if !self.client.is_offline()
            || facts.profile_id != self.scope.profile_id()
            || facts.account_id != self.scope.account_id()
            || facts.server_origin != self.scope.server_origin()
            || facts.token_generation != self.scope.token_generation()
            || facts.root.volume_serial != root.volume_serial
            || facts.root.file_index != root.file_index
        {
            return Err(no());
        }
        let route = self
            .vault_for_identity(&facts.identity)
            .map_err(|_| no())?
            .ok_or_else(no)?;
        if route.local_root() != root
            || route.space_id() != facts.space_id
            || route.root_resource_id() != facts.root_resource_id
            || route.root_path() != facts.remote_root
        {
            return Err(no());
        }
        route
            .backend()
            .binding()
            .validate_cached_capture(facts, dispatch)?;
        Ok(route)
    }
    pub fn validate_fresh_cached_vault_capture(
        &self,
        facts: &crate::vault_cached_edit::CachedVaultEditBaselineFacts,
        dispatch: &crate::FreshVaultCaptureDispatch,
    ) -> Result<(), CloudError> {
        let _lease = self
            .lease_gate
            .read()
            .map_err(|_| CloudError::new(ErrorKind::Forbidden, "cached vault capture changed"))?;
        self.cached_capture_route(facts, dispatch).map(|_| ())
    }
    pub fn queue_cached_vault_capture<R: std::io::Read>(
        &self,
        facts: &crate::vault_cached_edit::CachedVaultEditBaselineFacts,
        dispatch: crate::FreshVaultCaptureDispatch,
        source: &mut R,
        provider_generation: Arc<AtomicU64>,
        expected: u64,
        cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<VaultCachedQueuedCapture, CloudError> {
        let no = || CloudError::new(ErrorKind::Forbidden, "cached vault capture changed");
        let route = {
            let _lease = self.lease_gate.read().map_err(|_| no())?;
            if expected == 0
                || provider_generation.load(Ordering::Acquire) != expected
                || cancelled()
            {
                return Err(no());
            }
            self.cached_capture_route(facts, &dispatch)?
        };
        let stop = || {
            self.is_revoked()
                || route.backend().binding().is_revoked()
                || provider_generation.load(Ordering::Acquire) != expected
                || cancelled()
        };
        let result = route
            .backend()
            .binding()
            .queue_cached_capture(facts, &dispatch, source, &stop)?;
        if stop() {
            return Err(no());
        }
        let raiun_opencloud::vault_backend::VaultUploadOutcome::Queued {
            entry,
            write_id,
            revision,
            uncertain: false,
        } = result
        else {
            return Err(no());
        };
        if entry.directory
            || entry.path != facts.current.path
            || entry.id != facts.current.id
            || entry.size != facts.plaintext_len
            || write_id.is_empty()
            || write_id.len() > 512
            || revision == 0
            || facts.pending.as_ref().is_some_and(|p| {
                p.write_id != write_id || p.revision.checked_add(1) != Some(revision)
            })
        {
            return Err(no());
        }
        Ok(VaultCachedQueuedCapture {
            facts: facts.clone(),
            entry,
            write_id,
            revision,
            _route: route,
        })
    }
}
