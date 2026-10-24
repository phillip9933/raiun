//! Verified read binding and local publication fences. Constructing this object
//! does not register a native route or expose vault capability in the agent.
use crate::{
    BackendError, CancellationToken, MAX_DIRECTORY_CHILDREN, MAX_RANGE_BYTES, ProviderScope,
    PublishPermit,
};
use raiun_core::{
    backend::{CloudBackend, CloudError, ErrorKind, RemoteEntry},
    validate_remote_path,
};
use raiun_opencloud::TokenGenerationLease;
use raiun_opencloud::{OpenCloudClient, vault::VaultMetadataClient, vault_backend::VaultBackend};
use raiun_vault::session::{
    VaultSessionCoordinator, VaultSessionEpoch, VaultSessionEpochLease, VaultSessionScope,
};
use std::{
    io::{Read, Seek, SeekFrom},
    sync::{
        Arc, RwLock, RwLockReadGuard,
        atomic::{AtomicBool, Ordering},
    },
};
use zeroize::Zeroizing;

pub struct WindowsVaultReadBinding {
    trusted: ProviderScope,
    client: Arc<OpenCloudClient>,
    sessions: Arc<VaultSessionCoordinator>,
    scope: VaultSessionScope,
    backend: VaultBackend,
    root_path: String,
    epoch: VaultSessionEpoch,
    identity: Arc<()>,
    revoked: AtomicBool,
    publication_gate: RwLock<()>,
}
struct VaultPublishPermit<'a> {
    _route: RwLockReadGuard<'a, ()>,
    _token: TokenGenerationLease<'a>,
    _session: VaultSessionEpochLease<'a>,
}

fn refused() -> CloudError {
    CloudError::new(
        ErrorKind::Forbidden,
        "Vault read binding is no longer current",
    )
}
fn check_context(
    trusted: &ProviderScope,
    client: &OpenCloudClient,
    scope: &VaultSessionScope,
) -> Result<(), CloudError> {
    if trusted.profile_id() != scope.account_id()
        || trusted.server_origin() != scope.server_origin()
        || client.server_origin().as_deref() != Some(trusted.server_origin())
        || client.token_generation() != trusted.token_generation()
    {
        return Err(refused());
    }
    Ok(())
}
fn normalized_inspected_path(path: &str) -> &str {
    if path == "/" {
        "/"
    } else {
        path.trim_end_matches('/')
    }
}
/// Private staging only: NOT a native route, revocation-safe reader, or
/// evidence that an unlocked route has been published.
#[cfg(windows)]
pub struct UnpublishedVaultStage {
    reader: raiun_control_windows::OwnedPrivateStagedReader,
    metadata: RemoteEntry,
    binding_identity: Arc<()>,
}
impl UnpublishedVaultStage {
    pub fn metadata(&self) -> &RemoteEntry {
        &self.metadata
    }
}
impl WindowsVaultReadBinding {
    /// Inputs are trusted runtime bindings, never credentials selected by UI.
    /// Provider account subject and local vault profile ID are intentionally
    /// distinct; the agent remains responsible for authenticating that subject.
    pub fn new_online(
        trusted: ProviderScope,
        client: Arc<OpenCloudClient>,
        sessions: Arc<VaultSessionCoordinator>,
        scope: VaultSessionScope,
        root_path: String,
    ) -> Result<Self, CloudError> {
        check_context(&trusted, &client, &scope)?;
        if root_path.len() > 4096 || validate_remote_path(&root_path).is_err() {
            return Err(refused());
        }
        let root_path = normalized_inspected_path(&root_path).to_owned();
        let epoch = sessions
            .capture_session_epoch(&scope)
            .map_err(|_| refused())?;
        let listing =
            VaultMetadataClient::new(&client).inspect_vault(scope.space_id(), &root_path)?;
        check_context(&trusted, &client, &scope)?;
        if listing.space_id != scope.space_id()
            || !listing.root.directory
            || listing.root.id != scope.resource_id()
            || normalized_inspected_path(&listing.root_path) != root_path
            || normalized_inspected_path(&listing.root.path) != root_path
        {
            return Err(refused());
        }
        // This constructor is always cache-free/online. Backend construction
        // independently revalidates root ID, token and exact unlocked session;
        // metadata presence alone never creates an unlocked session.
        let backend = VaultBackend::new(
            (*client).clone(),
            sessions.clone(),
            scope.clone(),
            root_path.clone(),
        )?;
        let binding = Self {
            trusted,
            client,
            sessions,
            scope,
            backend,
            root_path,
            epoch,
            identity: Arc::new(()),
            revoked: AtomicBool::new(false),
            publication_gate: RwLock::new(()),
        };
        binding.check_current()?;
        Ok(binding)
    }
    /// Complete a verified online read into an admitted private immutable file.
    /// The result stays opaque/unpublished until parent integration obtains the
    /// required provider/root/session publication lease and lock lifecycle.
    #[cfg(windows)]
    pub fn open_private(
        &self,
        path: &str,
        expected: &RemoteEntry,
        private_dir: Arc<raiun_control_windows::PrivateDirectory>,
        unique_name: &std::ffi::OsStr,
        maximum_bytes: u64,
    ) -> Result<UnpublishedVaultStage, CloudError> {
        self.check_current()?;
        if expected.directory
            || expected.size > maximum_bytes
            || expected.path != path
            || expected.id.is_empty()
            || expected.etag.is_empty()
            || path.len() > 4096
            || validate_remote_path(path).is_err()
        {
            return Err(refused());
        }
        let mut original_error = None;
        let staged = private_dir.stage_immutable_file(unique_name, maximum_bytes, |writer| {
            let downloaded = self.backend.download_online_to_private_writer(
                self.scope.space_id(),
                path,
                &expected.etag,
                private_dir.path(),
                writer,
            );
            match downloaded {
                Ok(actual)
                    if !actual.directory
                        && actual.id == expected.id
                        && actual.etag == expected.etag
                        && actual.path == expected.path
                        && actual.size == expected.size =>
                {
                    Ok(actual)
                }
                result => {
                    original_error = Some(match result {
                        Err(error) => error,
                        Ok(_) => CloudError::new(
                            ErrorKind::Conflict,
                            "Vault read metadata changed before stage admission",
                        ),
                    });
                    // Do not format an underlying path, token or secret into
                    // the filesystem callback error channel.
                    Err(std::io::Error::other("Vault private stage fill refused"))
                }
            }
        });
        let (reader, mut metadata) = staged.map_err(|_| {
            original_error.unwrap_or_else(|| {
                CloudError::new(
                    ErrorKind::InvalidResponse,
                    "Could not admit private vault stage",
                )
            })
        })?;
        self.check_current()?; // failure drops the exact owned stage here
        metadata.writable = false;
        Ok(UnpublishedVaultStage {
            reader,
            metadata,
            binding_identity: Arc::clone(&self.identity),
        })
    }

    /// Caller holds this binding's existing publication permit. No locks are
    /// reacquired here; the custody implementation must not reenter the binding.
    pub(crate) fn verify_custody_context(
        &self,
        custody: &dyn crate::vault_custody::VaultPublicationCustody,
    ) -> Result<(), BackendError> {
        custody.verify_context(&self.trusted, &self.scope, &self.root_path)
    }

    pub(crate) fn route_location(
        &self,
        owner: &ProviderScope,
    ) -> Result<(String, String, String), CloudError> {
        if owner != &self.trusted {
            return Err(refused());
        }
        self.with_publication(|| {
            Ok((
                self.scope.space_id().to_owned(),
                self.scope.resource_id().to_owned(),
                self.root_path.clone(),
            ))
        })
    }

    fn check_current(&self) -> Result<(), CloudError> {
        if self.revoked.load(Ordering::Acquire) {
            return Err(refused());
        }
        check_context(&self.trusted, &self.client, &self.scope)?;
        self.sessions
            .with_session_epoch(&self.scope, &self.epoch, || ())
            .map_err(|_| refused())
    }

    /// Prevent later publication and wait for any already admitted short local
    /// publication to finish. The owner must revoke routes before key removal.
    pub fn revoke(&self) -> Result<(), CloudError> {
        self.revoked.store(true, Ordering::Release);
        let _exclusive = self.publication_gate.write().map_err(|_| refused())?;
        Ok(())
    }

    /// Hold route, auth generation, and exact verified unlock through a short
    /// local native publication. No network, auth-lock acquisition or coordinator
    /// re-entry is permitted in the callback. Lock order is route→token→session.
    pub fn with_publication<T>(
        &self,
        publish: impl FnOnce() -> Result<T, CloudError>,
    ) -> Result<T, CloudError> {
        let _route = self.publication_gate.read().map_err(|_| refused())?;
        self.check_current()?;
        self.client
            .with_token_generation(self.trusted.token_generation(), || {
                self.sessions
                    .with_session_epoch(&self.scope, &self.epoch, || {
                        if self.revoked.load(Ordering::Acquire) {
                            Err(refused())
                        } else {
                            publish()
                        }
                    })
                    .map_err(|_| refused())?
            })?
    }

    /// Admit one native publication without blocking on route/auth/session
    /// locks. The returned opaque permit retains all three leases until dropped.
    pub fn try_begin_publish<'a>(
        &'a self,
        cancellation: &CancellationToken,
    ) -> Result<Box<dyn PublishPermit + 'a>, BackendError> {
        if cancellation.is_cancelled() {
            return Err(BackendError::Cancelled);
        }
        if cancellation.is_expired() {
            return Err(BackendError::Unavailable);
        }
        let route = self
            .publication_gate
            .try_read()
            .map_err(|_| BackendError::Unavailable)?;
        if self.revoked.load(Ordering::Acquire) {
            return Err(BackendError::Unavailable);
        }
        let token = self
            .client
            .try_lock_token_generation(self.trusted.token_generation())
            .map_err(|_| BackendError::Unavailable)?
            .ok_or(BackendError::Unavailable)?;
        let session = self
            .sessions
            .try_lock_session_epoch(&self.scope, &self.epoch)
            .map_err(|_| BackendError::Unavailable)?
            .ok_or(BackendError::Unavailable)?;
        if self.revoked.load(Ordering::Acquire) || cancellation.is_expired() {
            return Err(BackendError::Unavailable);
        }
        if cancellation.is_cancelled() {
            return Err(BackendError::Cancelled);
        }
        Ok(Box::new(VaultPublishPermit {
            _route: route,
            _token: token,
            _session: session,
        }))
    }

    /// Read and publish one bounded range from this binding's immutable stage.
    /// An owned copy must remain unpublished and zeroized until a fresh native
    /// publication permit is held. The callback must not re-enter auth/session
    /// operations or perform network I/O.
    pub fn publish_stage_range<T>(
        &self,
        stage: &mut UnpublishedVaultStage,
        offset: u64,
        length: usize,
        publish: impl FnOnce(&[u8]) -> Result<T, CloudError>,
    ) -> Result<T, CloudError> {
        if !Arc::ptr_eq(&self.identity, &stage.binding_identity)
            || length == 0
            || length > MAX_RANGE_BYTES
            || offset
                .checked_add(length as u64)
                .is_none_or(|end| end > stage.metadata.size)
        {
            return Err(refused());
        }
        self.with_publication(|| {
            let mut bytes = Zeroizing::new(vec![0u8; length]);
            stage
                .reader
                .seek(SeekFrom::Start(offset))
                .map_err(|_| refused())?;
            stage.reader.read_exact(&mut bytes).map_err(|_| refused())?;
            stage.reader.verify().map_err(|_| refused())?;
            publish(&bytes)
        })
    }

    pub fn stat(&self, path: &str) -> Result<RemoteEntry, CloudError> {
        self.check_current()?;
        let mut entry = self.backend.stat(self.scope.space_id(), path)?;
        self.check_current()?;
        entry.writable = false;
        Ok(entry)
    }
    /// Collect before returning; no external visitor sees a partial listing
    /// before the final generation and exact-session recheck.
    pub fn list(&self, path: &str) -> Result<Vec<RemoteEntry>, CloudError> {
        self.check_current()?;
        let mut entries = Vec::new();
        self.backend
            .list(self.scope.space_id(), path, &mut |mut entry| {
                if entries.len() >= MAX_DIRECTORY_CHILDREN {
                    return Err(CloudError::new(
                        ErrorKind::Unsupported,
                        "Vault directory exceeds the provider limit",
                    ));
                }
                entry.writable = false;
                entries.push(entry);
                Ok(())
            })?;
        self.check_current()?;
        Ok(entries)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn trusted_profile_origin_and_client_generation_are_distinct_from_subject() {
        let client =
            OpenCloudClient::new("https://synthetic.invalid", "synthetic-token".into()).unwrap();
        let profile = format!("profile-{}", "a".repeat(32));
        let trusted = ProviderScope::new(
            &client,
            profile.clone(),
            "actual-subject".into(),
            "https://synthetic.invalid".into(),
        )
        .unwrap();
        let own =
            VaultSessionScope::new(&profile, "https://synthetic.invalid", "space", "root").unwrap();
        assert!(check_context(&trusted, &client, &own).is_ok());
        let subject_as_profile = VaultSessionScope::new(
            "actual-subject",
            "https://synthetic.invalid",
            "space",
            "root",
        )
        .unwrap();
        assert!(check_context(&trusted, &client, &subject_as_profile).is_err());
        let foreign_origin =
            VaultSessionScope::new(&profile, "https://other.invalid", "space", "root").unwrap();
        assert!(check_context(&trusted, &client, &foreign_origin).is_err());
        client
            .set_bearer_token("rotated-synthetic-token".into())
            .unwrap();
        assert!(check_context(&trusted, &client, &own).is_err());
    }
}
