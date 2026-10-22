//! Existing-identity publication under the live initial-save session lease.

use super::*;
use crate::VerifiedEditReadback;

/// A publication capability for one current backend, catalog entry and proof.
/// Publishing updates only the verified cloud baseline. Native in-sync marking
/// separately requires an exact held local-file verification.
pub struct VerifiedEditPublication<'session, 'backend> {
    session: &'session InitialEditSession<'backend>,
    proof: &'session VerifiedEditReadback,
    identity: OpaqueIdentity,
    prior: FileBinding,
    catalog: ProviderIdentityCatalogScope,
}

impl<'backend> InitialEditSession<'backend> {
    pub fn prepare_verified_edit<'session>(
        &'session self,
        identity: &[u8],
        proof: &'session VerifiedEditReadback,
    ) -> Result<VerifiedEditPublication<'session, 'backend>, BackendError> {
        let backend = self.remote.backend;
        self.remote
            .authorize(&self.scope)
            .map_err(|_| BackendError::Unavailable)?;
        let metadata = proof.metadata();
        if metadata.scope != self.scope || metadata.generation != backend.token_generation {
            return Err(BackendError::Unavailable);
        }
        let identity = OpaqueIdentity(identity.try_into().map_err(|_| BackendError::NotFound)?);
        let catalog = backend
            .catalog_scope_snapshot()?
            .ok_or(BackendError::Unavailable)?;
        let prior = backend
            .state
            .lock()
            .map_err(|_| BackendError::Unavailable)?
            .files
            .get(&identity)
            .cloned()
            .ok_or(BackendError::NotFound)?;
        let baseline = metadata.remote.as_ref().ok_or(BackendError::Unavailable)?;
        let version = proof.remote_version();
        if prior.space_id != self.scope.space_id
            || prior.root_resource_id != self.scope.root_resource_id
            || prior.path.strip_prefix('/') != Some(metadata.relative_path.as_str())
            || prior.remote_id != baseline.resource_id
            || prior.remote_id != version.resource_id
            || !((prior.etag == baseline.etag && prior.size == baseline.byte_len)
                || (prior.etag == version.etag && prior.size == version.size))
            || catalog.root_volume_serial != self.scope.root_volume_serial
            || catalog.root_file_index != self.scope.root_file_index
        {
            return Err(BackendError::Unavailable);
        }
        Ok(VerifiedEditPublication {
            session: self,
            proof,
            identity,
            prior,
            catalog,
        })
    }
}

impl VerifiedEditPublication<'_, '_> {
    pub fn proof(&self) -> &VerifiedEditReadback {
        self.proof
    }

    pub fn identity(&self) -> &[u8; 16] {
        self.identity.as_bytes()
    }

    pub fn provider_scope(&self) -> &ProviderScope {
        &self.session.remote.backend.scope
    }

    /// Persist the freshly verified cloud baseline without marking local data
    /// clean. A later OS failure leaves this verified cloud baseline and the
    /// journal intact; post-OS validation failure may follow an accepted in-sync
    /// state. It must never roll back to an older validator.
    pub fn publish_and_complete<T>(
        &self,
        complete: impl FnOnce() -> Result<T, crate::Error>,
    ) -> Result<T, crate::Error> {
        let unavailable = || crate::Error::EditRecoveryUnavailable;
        let backend = self.session.remote.backend;
        let cancellation = CancellationToken::new();
        // Existing publication/token fence also blocks revoke() setting its
        // flag. Keep it through the OS completion, not merely catalog writes.
        let _permit = backend
            .begin_scoped_publish(&cancellation)
            .map_err(|_| unavailable())?;
        self.session
            .remote
            .authorize(&self.session.scope)
            .map_err(|_| unavailable())?;
        // Never wait for state while holding a token read permit: existing
        // registration paths take state before token. A busy state fails closed
        // instead of introducing an inverse-order lock wait.
        let mut state = backend.state.try_lock().map_err(|_| unavailable())?;
        if state.files.get(&self.identity) != Some(&self.prior) {
            return Err(unavailable());
        }
        let version = self.proof.remote_version();
        backend
            .upsert_identity_binding(
                &self.catalog,
                &ProviderIdentityBinding::File {
                    identity: *self.identity.as_bytes(),
                    space_id: self.prior.space_id.clone(),
                    root_resource_id: self.prior.root_resource_id.clone(),
                    path: self.prior.path.clone(),
                    remote_id: self.prior.remote_id.clone(),
                    etag: version.etag.clone(),
                    size: version.size,
                },
            )
            .map_err(|_| unavailable())?;
        let mut updated = self.prior.clone();
        updated.etag = version.etag.clone();
        updated.size = version.size;
        state.files.insert(self.identity, updated);
        complete()
    }
}
