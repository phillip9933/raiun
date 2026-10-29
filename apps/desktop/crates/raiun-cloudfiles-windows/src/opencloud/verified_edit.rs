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
    /// Resolve exactly one already-admitted opaque identity. Remote paths are
    /// compared as cloud identifiers only, never turned into local components.
    pub fn prepare_recovered_edit<'session>(
        &'session self,
        proof: &'session VerifiedEditReadback,
    ) -> Result<VerifiedEditPublication<'session, 'backend>, BackendError> {
        self.remote
            .authorize(&self.scope)
            .map_err(|_| BackendError::Unavailable)?;
        if proof.metadata().scope != self.scope {
            return Err(BackendError::Unavailable);
        }
        let identity = {
            let state = self
                .remote
                .backend
                .state
                .lock()
                .map_err(|_| BackendError::Unavailable)?;
            unique_recovered_identity(&state.files, proof.metadata(), proof.remote_version())?
        };
        self.prepare_verified_edit(identity.as_bytes(), proof)
    }

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

fn matches_recovered_binding(
    binding: &FileBinding,
    metadata: &crate::LocalEditMetadata,
    version: &crate::RecoveryRemoteVersion,
) -> bool {
    let Some(baseline) = metadata.remote.as_ref() else {
        return false;
    };
    binding.space_id == metadata.scope.space_id
        && binding.root_resource_id == metadata.scope.root_resource_id
        && binding.path.strip_prefix('/') == Some(metadata.relative_path.as_str())
        && binding.remote_id == baseline.resource_id
        && binding.remote_id == version.resource_id
        && ((binding.etag == baseline.etag && binding.size == baseline.byte_len)
            || (binding.etag == version.etag && binding.size == version.size))
}

fn unique_recovered_identity(
    files: &HashMap<OpaqueIdentity, FileBinding>,
    metadata: &crate::LocalEditMetadata,
    version: &crate::RecoveryRemoteVersion,
) -> Result<OpaqueIdentity, BackendError> {
    if files.len() > MAX_IDENTITY_CATALOG_ENTRIES {
        return Err(BackendError::Unavailable);
    }
    let mut selected = files
        .iter()
        .filter(|(_, binding)| matches_recovered_binding(binding, metadata, version));
    let identity = *selected.next().ok_or(BackendError::NotFound)?.0;
    if selected.next().is_some() {
        return Err(BackendError::Unavailable);
    }
    Ok(identity)
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
        let cancellation = self
            .proof
            .recovery_job()
            .map_or_else(CancellationToken::new, |job| job.cancellation().clone());
        if cancellation.is_cancelled() || cancellation.is_expired() {
            return Err(unavailable());
        }
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
        if cancellation.is_cancelled() || cancellation.is_expired() {
            return Err(unavailable());
        }
        let result = complete()?;
        if cancellation.is_cancelled() || cancellation.is_expired() {
            return Err(unavailable());
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovered_reverse_lookup_requires_one_exact_cloud_binding_and_version() {
        let metadata = crate::LocalEditMetadata {
            record_id: "0123456789abcdef".into(),
            generation: 1,
            scope: crate::EditJournalScope {
                profile_id: "default".into(),
                server_origin: "https://example.test".into(),
                account_subject: "synthetic".into(),
                space_id: "project".into(),
                root_resource_id: "root".into(),
                root_volume_serial: 1,
                root_file_index: 2,
            },
            local_file: crate::LocalFileIdentity {
                volume_serial: 1,
                file_index: 3,
            },
            relative_path: "docs/file".into(),
            remote: Some(crate::RemoteEditBaseline {
                resource_id: "file-id".into(),
                etag: "\"v1\"".into(),
                byte_len: 4,
            }),
            content_len: 5,
            content_sha256: "unused-test-hash".into(),
            state: crate::LocalEditState::Dirty,
        };
        let version = crate::RecoveryRemoteVersion {
            resource_id: "file-id".into(),
            etag: "\"v2\"".into(),
            size: 5,
            is_directory: false,
            encrypted: false,
            writable: true,
        };
        let binding = FileBinding {
            space_id: "project".into(),
            root_resource_id: "root".into(),
            path: "/docs/file".into(),
            remote_id: "file-id".into(),
            etag: "\"v1\"".into(),
            size: 4,
        };
        let identity = OpaqueIdentity([1; 16]);
        let mut files = HashMap::new();
        files.insert(identity, binding.clone());
        assert_eq!(
            unique_recovered_identity(&files, &metadata, &version).unwrap(),
            identity
        );
        files.insert(OpaqueIdentity([2; 16]), binding.clone());
        assert!(unique_recovered_identity(&files, &metadata, &version).is_err());
        files.remove(&OpaqueIdentity([2; 16]));
        for invalid in [
            FileBinding {
                path: "/elsewhere".into(),
                ..binding.clone()
            },
            FileBinding {
                space_id: "other".into(),
                ..binding.clone()
            },
            FileBinding {
                root_resource_id: "replaced".into(),
                ..binding.clone()
            },
            FileBinding {
                remote_id: "other".into(),
                ..binding.clone()
            },
            FileBinding {
                etag: "\"v3\"".into(),
                ..binding.clone()
            },
        ] {
            files.insert(identity, invalid);
            assert!(unique_recovered_identity(&files, &metadata, &version).is_err());
        }
        files.insert(
            identity,
            FileBinding {
                etag: version.etag.clone(),
                size: version.size,
                ..binding
            },
        );
        assert_eq!(
            unique_recovered_identity(&files, &metadata, &version).unwrap(),
            identity
        );
    }
}
