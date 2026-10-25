//! Single verified vault read adapter. No registered root, composite namespace,
//! edit support or durable identity catalogue is installed by this module.
use crate::opencloud::{direct_child_name, valid_windows_component};
use crate::{BackendError, MAX_DIRECTORY_CHILDREN, PlaceholderChild, PlaceholderMetadata};
use raiun_core::backend::RemoteEntry;
use std::collections::{HashMap, HashSet};

const MAX_CATALOGUE: usize = 100_000;
#[derive(Clone, Eq, PartialEq, Hash)]
enum VersionKey {
    Directory(String, String),
    File(String, String, String, u64),
}
fn key(entry: &RemoteEntry) -> VersionKey {
    if entry.directory {
        VersionKey::Directory(entry.path.clone(), entry.id.clone())
    } else {
        VersionKey::File(
            entry.path.clone(),
            entry.id.clone(),
            entry.etag.clone(),
            entry.size,
        )
    }
}
fn metadata(entry: &RemoteEntry) -> PlaceholderMetadata {
    PlaceholderMetadata {
        is_directory: entry.directory,
        length: if entry.directory { 0 } else { entry.size },
    }
}
#[derive(Clone, Default)]
struct Catalogue {
    entries: HashMap<[u8; 16], RemoteEntry>,
    versions: HashMap<VersionKey, [u8; 16]>,
}
impl Catalogue {
    fn insert(&mut self, entry: RemoteEntry) -> Result<[u8; 16], BackendError> {
        if entry.id.is_empty() || (!entry.directory && entry.etag.is_empty()) {
            return Err(BackendError::Unavailable);
        }
        let version = key(&entry);
        if let Some(id) = self.versions.get(&version) {
            return Ok(*id);
        }
        if self.entries.len() >= MAX_CATALOGUE {
            return Err(BackendError::Unavailable);
        }
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|_| BackendError::Unavailable)?;
        if self.entries.contains_key(&id) {
            return Err(BackendError::Unavailable);
        }
        self.entries.insert(id, entry);
        self.versions.insert(version, id);
        Ok(id)
    }
    #[cfg(windows)]
    fn restore(
        entries: Vec<crate::vault_custody::VaultCatalogueEntry>,
    ) -> Result<Self, BackendError> {
        if entries.len() > MAX_CATALOGUE {
            return Err(BackendError::Unavailable);
        }
        let mut catalogue = Self::default();
        for row in entries {
            let entry = row.metadata;
            if row.identity == [0; 16]
                || entry.id.is_empty()
                || (!entry.directory && entry.etag.is_empty())
                || (entry.directory && entry.size != 0)
                || raiun_core::validate_remote_path(&entry.path).is_err()
                || (entry.path != "/" && !entry.path[1..].split('/').all(valid_windows_component))
                || catalogue.entries.contains_key(&row.identity)
                || catalogue.versions.contains_key(&key(&entry))
            {
                return Err(BackendError::Unavailable);
            }
            catalogue.versions.insert(key(&entry), row.identity);
            catalogue.entries.insert(row.identity, entry);
        }
        Ok(catalogue)
    }
    fn get(&self, identity: &[u8]) -> Option<RemoteEntry> {
        let id: [u8; 16] = identity.try_into().ok()?;
        self.entries.get(&id).cloned()
    }
    // Plan against a clone: errors never install a partial listing or mapping.
    fn stage_listing(
        &self,
        parent: &RemoteEntry,
        entries: Vec<RemoteEntry>,
    ) -> Result<(Self, Vec<PlaceholderChild>), BackendError> {
        if !parent.directory || entries.len() > MAX_DIRECTORY_CHILDREN {
            return Err(BackendError::Unavailable);
        }
        let mut next = self.clone();
        let mut names = HashSet::new();
        let mut children = Vec::with_capacity(entries.len());
        for entry in entries {
            let name = direct_child_name(&parent.path, &entry.path)
                .filter(|name| valid_windows_component(name))
                .ok_or(BackendError::Unavailable)?
                .to_owned();
            if !names.insert(name.to_lowercase()) {
                return Err(BackendError::Unavailable);
            }
            let child_metadata = metadata(&entry);
            let identity = next.insert(entry)?;
            children.push(PlaceholderChild {
                name,
                identity: identity.to_vec(),
                metadata: child_metadata,
                last_write_time: 0,
            });
        }
        Ok((next, children))
    }
}

#[cfg(windows)]
mod runtime {
    use super::*;
    use crate::vault_read::{UnpublishedVaultStage, WindowsVaultReadBinding};
    use crate::{
        CancellationToken, FetchRange, MAX_RANGE_BYTES, MAX_REQUEST_BYTES, PlaceholderBackend,
        PreparedEnumeration, PreparedFetch, PreparedFetchSession, PublishPermit,
    };
    use raiun_control_windows::PrivateDirectory;
    use raiun_core::backend::{CloudError, ErrorKind};
    use std::{
        ffi::OsStr,
        sync::{Arc, Mutex},
    };
    use zeroize::Zeroizing;

    fn check(cancellation: &CancellationToken) -> Result<(), BackendError> {
        if cancellation.is_cancelled() {
            Err(BackendError::Cancelled)
        } else if cancellation.is_expired() {
            Err(BackendError::Unavailable)
        } else {
            Ok(())
        }
    }
    fn refused() -> CloudError {
        CloudError::new(
            ErrorKind::Forbidden,
            "Vault placeholder publication refused",
        )
    }
    pub struct WindowsVaultPlaceholderBackend {
        binding: Arc<WindowsVaultReadBinding>,
        private: Arc<PrivateDirectory>,
        maximum_stage_bytes: u64,
        catalogue: Mutex<Catalogue>,
        root: [u8; 16],
        custody: Arc<dyn crate::vault_custody::VaultPublicationCustody>,
    }
    impl WindowsVaultPlaceholderBackend {
        pub fn new(
            binding: Arc<WindowsVaultReadBinding>,
            private: Arc<PrivateDirectory>,
            maximum_stage_bytes: u64,
            custody: Arc<dyn crate::vault_custody::VaultPublicationCustody>,
        ) -> Result<Self, BackendError> {
            let root = binding.stat("/").map_err(|_| BackendError::Unavailable)?;
            if !root.directory || root.path != "/" {
                return Err(BackendError::Unavailable);
            }
            private
                .verify_path()
                .map_err(|_| BackendError::Unavailable)?;
            let (catalogue, identity) = binding
                .with_publication(|| {
                    binding
                        .verify_custody_context(custody.as_ref())
                        .map_err(|_| refused())?;
                    let mut catalogue =
                        Catalogue::restore(custody.catalogue_snapshot().map_err(|_| refused())?)
                            .map_err(|_| refused())?;
                    if catalogue
                        .entries
                        .values()
                        .any(|entry| entry.path == "/" && (!entry.directory || entry.id != root.id))
                    {
                        return Err(refused());
                    }
                    let identity = catalogue.insert(root).map_err(|_| refused())?;
                    persist_catalogue(custody.as_ref(), &catalogue).map_err(|_| refused())?;
                    Ok((catalogue, identity))
                })
                .map_err(|_| BackendError::Unavailable)?;
            Ok(Self {
                binding,
                private,
                maximum_stage_bytes,
                catalogue: Mutex::new(catalogue),
                root: identity,
                custody,
            })
        }
        /// Early local freshness check only. No body, HTTP or live permit
        /// escapes; the upload path still performs full custody validation.
        pub(crate) fn validate_capture_dispatch_target(
            &self,
            target: &crate::ExistingVaultUploadTarget,
        ) -> Result<(), CloudError> {
            let saved = self.saved(target.identity()).map_err(|_| refused())?;
            self.binding.with_publication(|| {
                self.binding.validate_upload_target(target)?;
                if key(&saved) != key(target.original()) || !target.matches_original(&saved) {
                    return Err(refused());
                }
                Ok(())
            })
        }

        pub(crate) fn upload_existing_capture<R: std::io::Read + std::io::Seek>(
            &self,
            target: &crate::ExistingVaultUploadTarget,
            source: &mut R,
            edited_len: u64,
            cancellation: &crate::vault_custody::VaultUploadCancellation<'_>,
        ) -> Result<raiun_opencloud::vault_backend::VaultExistingOverwriteOutcome, CloudError>
        {
            use raiun_opencloud::vault_backend::VaultExistingOverwriteOutcome;
            if cancellation.is_cancelled()
                || edited_len > crate::MAX_VAULT_EDIT_CAPTURE_BYTES as u64
            {
                return Err(refused());
            }
            let saved = self.saved(target.identity()).map_err(|_| refused())?;
            self.binding.with_publication(|| {
                // Local protected validation only; no source body reads, HTTP,
                // auth/coordinator reentry or authority escaping this callback.
                self.binding.validate_upload_target(target)?;
                self.binding
                    .verify_custody_context(self.custody.as_ref())
                    .map_err(|_| refused())?;
                if self.custody.root_identity() != target.root() || !target.matches_original(&saved)
                {
                    return Err(refused());
                }
                let catalogue = self.custody.catalogue_snapshot().map_err(|_| refused())?;
                let mut matching = catalogue
                    .iter()
                    .filter(|row| &row.identity == target.identity());
                let original = matching.next().ok_or_else(refused)?;
                if matching.next().is_some() || !target.matches_original(&original.metadata) {
                    return Err(refused());
                }
                Ok(())
            })?; // Every route/token/epoch/custody/catalogue guard is dropped.
            self.private.verify_path().map_err(|_| refused())?;
            let result = self.binding.upload_existing_capture(
                target,
                source,
                edited_len,
                &self.private,
                cancellation,
            );
            match result {
                Ok(VaultExistingOverwriteOutcome::Verified(_))
                    if self.private.verify_path().is_err() || cancellation.is_cancelled() =>
                {
                    Ok(VaultExistingOverwriteOutcome::NeedsReconciliation {
                        reason: raiun_core::backend::ErrorKind::Forbidden,
                    })
                }
                other => other,
            }
        }

        /// Caller retains this route's exclusive publication/auth/epoch fence.
        /// Stable opaque identity is promoted explicitly; no name insertion or
        /// remote rebasing and no additional storage write occurs here.
        pub(crate) fn promote_completed_catalogue(
            &self,
            upload: &crate::FreshVaultUpload,
        ) -> Result<(), BackendError> {
            // Established order: exclusive route WRITE -> token -> epoch ->
            // catalogue. All other catalogue readers clone before native/I/O;
            // there is no catalogue -> route/auth acquisition. Waiting for a
            // brief Explorer lookup must not fail an already durable Prepared.
            let mut catalogue = self
                .catalogue
                .lock()
                .map_err(|_| BackendError::Unavailable)?;
            let id = upload.identity();
            let old = catalogue.entries.get(&id).ok_or(BackendError::NotFound)?;
            if !upload.target.matches_original(old)
                || upload.verified.entry().id != old.id
                || upload.verified.entry().path != old.path
            {
                return Err(BackendError::Unavailable);
            }
            let old_key = key(old);
            let mut next = old.clone();
            next.etag = upload.verified.entry().etag.clone();
            next.size = upload.verified.entry().size;
            let new_key = key(&next);
            if catalogue
                .versions
                .get(&new_key)
                .is_some_and(|other| *other != id)
            {
                return Err(BackendError::Unavailable);
            }
            catalogue.versions.remove(&old_key);
            catalogue.versions.insert(new_key, id);
            catalogue.entries.insert(id, next);
            Ok(())
        }

        pub(crate) fn custody_root_identity(&self) -> crate::ConfiguredRootIdentity {
            self.custody.root_identity()
        }
        pub(crate) fn binding(&self) -> &Arc<WindowsVaultReadBinding> {
            &self.binding
        }
        pub(crate) fn cleanup_identities(
            &self,
        ) -> Result<std::collections::BTreeSet<[u8; 16]>, BackendError> {
            Ok(self
                .catalogue
                .lock()
                .map_err(|_| BackendError::Unavailable)?
                .entries
                .keys()
                .copied()
                .collect())
        }
        pub(crate) fn owns_identity(&self, identity: &[u8]) -> Result<bool, BackendError> {
            Ok(self
                .catalogue
                .lock()
                .map_err(|_| BackendError::Unavailable)?
                .get(identity)
                .is_some())
        }
        pub fn prepare_enumeration_owned(
            &self,
            identity: &[u8],
            cancellation: &CancellationToken,
        ) -> Result<Box<dyn PreparedEnumeration + 'static>, BackendError> {
            check(cancellation)?;
            let revision = self.binding.publication_revision();
            let parent = self.saved(identity)?;
            if !parent.directory {
                return Err(BackendError::NotFound);
            }
            let before = self
                .binding
                .stat(&parent.path)
                .map_err(|_| BackendError::Unavailable)?;
            if !before.directory || before.path != parent.path || before.id != parent.id {
                return Err(BackendError::NotFound);
            }
            let entries = self
                .binding
                .list(&parent.path)
                .map_err(|_| BackendError::Unavailable)?;
            let after = self
                .binding
                .stat(&parent.path)
                .map_err(|_| BackendError::Unavailable)?;
            if !after.directory || after.path != parent.path || after.id != parent.id {
                return Err(BackendError::NotFound);
            }
            check(cancellation)?;
            // Publication/route -> token -> session -> catalogue is the only
            // catalogue commit order; no catalogue guard survives network I/O.
            let children = self
                .binding
                .with_publication_revision(revision, || {
                    check(cancellation).map_err(|_| refused())?;
                    let mut catalogue = self.catalogue.lock().map_err(|_| refused())?;
                    let (next, children) = catalogue
                        .stage_listing(&parent, entries)
                        .map_err(|_| refused())?;
                    persist_catalogue(self.custody.as_ref(), &next).map_err(|_| refused())?;
                    *catalogue = next;
                    Ok(children)
                })
                .map_err(|_| BackendError::Unavailable)?;
            check(cancellation)?;
            Ok(Box::new(VaultEnumeration {
                binding: self.binding.clone(),
                revision,
                children,
            }))
        }

        pub fn prepare_fetch_session_owned(
            &self,
            identity: &[u8],
            cancellation: &CancellationToken,
        ) -> Result<Box<dyn PreparedFetchSession + 'static>, BackendError> {
            Ok(Box::new(self.session(identity, cancellation)?))
        }

        pub fn prepare_fetch_owned(
            &self,
            identity: &[u8],
            range: FetchRange,
            cancellation: &CancellationToken,
        ) -> Result<Box<dyn PreparedFetch + 'static>, BackendError> {
            check(cancellation)?;
            if range.end < range.offset || range.len() > MAX_REQUEST_BYTES {
                return Err(BackendError::InvalidRange);
            }
            Ok(Box::new(
                self.session(identity, cancellation)?
                    .window(range, cancellation)?,
            ))
        }
        pub fn root_identity(&self) -> [u8; 16] {
            self.root
        }
        fn saved(&self, identity: &[u8]) -> Result<RemoteEntry, BackendError> {
            self.catalogue
                .lock()
                .map_err(|_| BackendError::Unavailable)?
                .get(identity)
                .ok_or(BackendError::NotFound)
        }
        fn session(
            &self,
            identity: &[u8],
            cancellation: &CancellationToken,
        ) -> Result<VaultFetchSession, BackendError> {
            check(cancellation)?;
            let revision = self.binding.publication_revision();
            let expected = self.saved(identity)?; // release catalogue before I/O/publication
            if expected.directory || expected.size > self.maximum_stage_bytes {
                return Err(BackendError::Unavailable);
            }
            let mut nonce = [0; 16];
            getrandom::fill(&mut nonce).map_err(|_| BackendError::Unavailable)?;
            let name = format!(
                "vault-stage-{}",
                nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()
            );
            let stage = self
                .binding
                .open_private(
                    &expected.path,
                    &expected,
                    self.private.clone(),
                    OsStr::new(&name),
                    self.maximum_stage_bytes,
                )
                .map_err(|_| BackendError::Unavailable)?;
            check(cancellation)?;
            self.binding
                .with_publication_revision(revision, || Ok(()))
                .map_err(|_| BackendError::Unavailable)?;
            Ok(VaultFetchSession {
                binding: self.binding.clone(),
                revision,
                custody: self.custody.clone(),
                identity: identity.try_into().map_err(|_| BackendError::Unavailable)?,
                metadata: metadata(&expected),
                stage: Mutex::new(stage),
            })
        }
    }
    fn persist_catalogue(
        custody: &dyn crate::vault_custody::VaultPublicationCustody,
        catalogue: &Catalogue,
    ) -> Result<(), BackendError> {
        let mut entries = catalogue
            .entries
            .iter()
            .map(
                |(identity, metadata)| crate::vault_custody::VaultCatalogueEntry {
                    identity: *identity,
                    metadata: metadata.clone(),
                },
            )
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.identity);
        custody.persist_catalogue(&entries)
    }

    struct VaultEnumeration {
        binding: Arc<WindowsVaultReadBinding>,
        revision: u64,
        children: Vec<PlaceholderChild>,
    }
    impl PreparedEnumeration for VaultEnumeration {
        fn read_only(&self) -> bool {
            true
        }
        fn children(&self) -> &[PlaceholderChild] {
            &self.children
        }
        fn begin_publish<'a>(
            &'a self,
            cancellation: &CancellationToken,
        ) -> Result<Box<dyn PublishPermit + 'a>, BackendError> {
            self.binding
                .try_begin_publish_revision(self.revision, cancellation)
        }
    }
    struct VaultFetch {
        binding: Arc<WindowsVaultReadBinding>,
        revision: u64,
        custody: Arc<dyn crate::vault_custody::VaultPublicationCustody>,
        identity: [u8; 16],
        metadata: PlaceholderMetadata,
        bytes: Zeroizing<Vec<u8>>,
    }
    impl PreparedFetch for VaultFetch {
        fn persist_vault_hydration(
            &self,
            intent: &crate::vault_custody::VaultHydrationIntent,
        ) -> Result<(), BackendError> {
            if intent.identity != self.identity
                || intent.length != self.metadata.length
                || self.metadata.is_directory
                || intent.root != self.custody.root_identity()
            {
                return Err(BackendError::Unavailable);
            }
            self.custody.persist_hydration(intent)
        }
        fn metadata(&self) -> PlaceholderMetadata {
            self.metadata
        }
        fn bytes(&self) -> &[u8] {
            &self.bytes
        }
        fn begin_publish<'a>(
            &'a self,
            cancellation: &CancellationToken,
        ) -> Result<Box<dyn PublishPermit + 'a>, BackendError> {
            self.binding
                .try_begin_publish_revision(self.revision, cancellation)
        }
    }
    struct VaultFetchSession {
        binding: Arc<WindowsVaultReadBinding>,
        revision: u64,
        custody: Arc<dyn crate::vault_custody::VaultPublicationCustody>,
        identity: [u8; 16],
        metadata: PlaceholderMetadata,
        stage: Mutex<UnpublishedVaultStage>,
    }
    impl VaultFetchSession {
        fn window(
            &self,
            range: FetchRange,
            cancellation: &CancellationToken,
        ) -> Result<VaultFetch, BackendError> {
            check(cancellation)?;
            if range.end < range.offset
                || range.end > self.metadata.length
                || range.len() > MAX_REQUEST_BYTES
            {
                return Err(BackendError::InvalidRange);
            }
            let length = usize::try_from(range.len()).map_err(|_| BackendError::InvalidRange)?;
            let mut bytes = Zeroizing::new(vec![0u8; length]);
            let mut stage = self.stage.lock().map_err(|_| BackendError::Unavailable)?;
            let mut copied = 0;
            while copied < length {
                check(cancellation)?;
                let count = (length - copied).min(MAX_RANGE_BYTES);
                self.binding
                    .publish_stage_range_at_revision(
                        self.revision,
                        &mut stage,
                        range.offset + copied as u64,
                        count,
                        |part| {
                            bytes[copied..copied + count].copy_from_slice(part);
                            Ok(())
                        },
                    )
                    .map_err(|_| BackendError::Unavailable)?;
                check(cancellation)?;
                copied += count;
            }
            check(cancellation)?;
            Ok(VaultFetch {
                binding: self.binding.clone(),
                revision: self.revision,
                custody: self.custody.clone(),
                identity: self.identity,
                metadata: self.metadata,
                bytes,
            })
        }
    }
    impl PreparedFetchSession for VaultFetchSession {
        fn metadata(&self) -> PlaceholderMetadata {
            self.metadata
        }
        fn prepare_window<'a>(
            &'a self,
            range: FetchRange,
            cancellation: &CancellationToken,
        ) -> Result<Box<dyn PreparedFetch + 'a>, BackendError> {
            Ok(Box::new(self.window(range, cancellation)?))
        }
    }
    struct LocalExistingCapture<'a> {
        baseline: crate::vault_custody::ExistingVaultEditBaseline,
        binding: &'a WindowsVaultReadBinding,
        custody: &'a dyn crate::vault_custody::VaultPublicationCustody,
        acknowledgement: crate::backend::ExistingCaptureAcknowledgement,
    }
    impl crate::ExistingVaultEditCapture for LocalExistingCapture<'_> {
        fn baseline(&self) -> &crate::vault_custody::ExistingVaultEditBaseline {
            &self.baseline
        }
        fn retain(
            &self,
            payload: crate::vault_custody::ExistingVaultEditPayload,
        ) -> Result<Option<Box<dyn crate::DeferredVaultCaptureNotification>>, BackendError>
        {
            self.acknowledgement.begin_attempt()?;
            if payload.bytes.len() > crate::MAX_VAULT_EDIT_CAPTURE_BYTES
                || payload.root != self.baseline.root()
                || payload.file.volume_serial != payload.root.volume_serial
                || payload.file.file_index == 0
                || payload.components.is_empty()
                || payload.components.len() > 256
                || payload.components.iter().map(String::len).sum::<usize>() > 32000
            {
                return Err(BackendError::Unavailable);
            }
            let notification = self.custody.retain_existing_edit(
                &self.baseline,
                payload,
                self.binding.capture_dispatch_stamp(),
            )?;
            self.acknowledgement.acknowledge_retained();
            Ok(notification)
        }
    }
    impl PlaceholderBackend for WindowsVaultPlaceholderBackend {
        fn with_vault_edit_capture(
            &self,
            identity: &[u8],
            callback: &mut dyn FnMut(
                &dyn crate::ExistingVaultEditCapture,
            ) -> Result<(), BackendError>,
        ) -> Result<(), BackendError> {
            // Resolve immutable original metadata locally before acquiring the
            // lexical fences. Opaque identities are never rebound to fresh DAV
            // metadata. Broker custody independently verifies this exact entry.
            let saved = self.saved(identity)?;
            let identity: [u8; 16] = identity.try_into().map_err(|_| BackendError::Unavailable)?;
            self.binding
                .with_publication(|| {
                    self.binding
                        .verify_custody_context(self.custody.as_ref())
                        .map_err(|_| refused())?;
                    // This is a local protected catalogue snapshot, not fresh
                    // remote metadata or coordinator reentry. Require the exact
                    // original opaque entry before native body reading begins.
                    let catalogue = self.custody.catalogue_snapshot().map_err(|_| refused())?;
                    let mut matching = catalogue.iter().filter(|row| row.identity == identity);
                    let original = matching.next().ok_or_else(refused)?;
                    if matching.next().is_some() || key(&original.metadata) != key(&saved) {
                        return Err(refused());
                    }
                    let baseline = self
                        .binding
                        .existing_edit_baseline(identity, saved, self.custody.root_identity())
                        .map_err(|_| refused())?;
                    let context = LocalExistingCapture {
                        baseline,
                        binding: &self.binding,
                        custody: self.custody.as_ref(),
                        acknowledgement: crate::backend::ExistingCaptureAcknowledgement::default(),
                    };
                    // No guard borrowed from this Arc escapes. Native body reads
                    // and local protected index/body readback run inside this call.
                    let result = callback(&context);
                    Ok(context.acknowledgement.finish(result))
                })
                .map_err(|_| BackendError::Unavailable)?
        }

        fn requires_hydration_inventory(&self, identity: &[u8]) -> Result<bool, BackendError> {
            if !self.owns_identity(identity)? {
                return Err(BackendError::NotFound);
            }
            Ok(true)
        }

        fn lookup(&self, identity: &[u8]) -> Result<Option<PlaceholderMetadata>, BackendError> {
            let saved = match self.saved(identity) {
                Ok(entry) => entry,
                Err(BackendError::NotFound) => return Ok(None),
                Err(e) => return Err(e),
            };
            self.binding
                .with_publication(|| Ok(Some(metadata(&saved))))
                .map_err(|_| BackendError::Unavailable)
        }
        fn enumerate(
            &self,
            identity: &[u8],
            cancellation: &CancellationToken,
        ) -> Result<Vec<PlaceholderChild>, BackendError> {
            Ok(self
                .prepare_enumeration(identity, cancellation)?
                .children()
                .to_vec())
        }
        fn prepare_enumeration<'a>(
            &'a self,
            identity: &[u8],
            cancellation: &CancellationToken,
        ) -> Result<Box<dyn PreparedEnumeration + 'a>, BackendError> {
            self.prepare_enumeration_owned(identity, cancellation)
        }
        fn prepare_fetch_session<'a>(
            &'a self,
            identity: &[u8],
            cancellation: &CancellationToken,
        ) -> Result<Box<dyn PreparedFetchSession + 'a>, BackendError> {
            self.prepare_fetch_session_owned(identity, cancellation)
        }
        fn prepare_fetch<'a>(
            &'a self,
            identity: &[u8],
            range: FetchRange,
            cancellation: &CancellationToken,
        ) -> Result<Box<dyn PreparedFetch + 'a>, BackendError> {
            self.prepare_fetch_owned(identity, range, cancellation)
        }
        fn read_range(
            &self,
            identity: &[u8],
            offset: u64,
            output: &mut [u8],
            cancellation: &CancellationToken,
        ) -> Result<usize, BackendError> {
            if output.len() > MAX_RANGE_BYTES {
                return Err(BackendError::InvalidRange);
            }
            let end = offset
                .checked_add(output.len() as u64)
                .ok_or(BackendError::InvalidRange)?;
            let fetched = self.prepare_fetch(identity, FetchRange { offset, end }, cancellation)?;
            let _permit = fetched.begin_publish(cancellation)?;
            check(cancellation)?;
            output.copy_from_slice(fetched.bytes());
            check(cancellation)?;
            Ok(output.len())
        }
    }
    #[cfg(test)]
    mod native_tests {
        #[cfg(feature = "synthetic-agent-integration")]
        use raiun_core::backend::CloudBackend;

        // Test-only in-memory evidence, never a protected durable service or
        // restart/cleanup authority. Production constructors still require the
        // broker-supplied protected implementation; there is no fallback.
        struct FixtureCustody {
            owner: ProviderScope,
            vault: raiun_vault::session::VaultSessionScope,
            remote_root: String,
            root: crate::ConfiguredRootIdentity,
            state: Mutex<FixtureCustodyState>,
        }
        #[derive(Clone, Default)]
        struct FixtureCustodyState {
            catalogue: std::collections::BTreeMap<[u8; 16], RemoteEntry>,
            hydrations: std::collections::BTreeMap<u64, FixtureHydration>,
        }
        #[derive(Clone, PartialEq, Eq)]
        struct FixtureHydration {
            identity: [u8; 16],
            length: u64,
            components: Vec<String>,
        }
        impl FixtureCustody {
            fn new(
                owner: ProviderScope,
                vault: raiun_vault::session::VaultSessionScope,
                remote_root: &str,
                root: crate::ConfiguredRootIdentity,
            ) -> Self {
                assert_eq!(owner.profile_id(), vault.account_id());
                assert_eq!(owner.server_origin(), vault.server_origin());
                assert!(root.volume_serial != 0 && root.file_index != 0);
                Self {
                    owner,
                    vault,
                    remote_root: remote_root.into(),
                    root,
                    state: Mutex::new(FixtureCustodyState::default()),
                }
            }
        }
        impl crate::vault_custody::VaultPublicationCustody for FixtureCustody {
            fn root_identity(&self) -> crate::ConfiguredRootIdentity {
                self.root
            }
            fn verify_context(
                &self,
                owner: &ProviderScope,
                vault: &raiun_vault::session::VaultSessionScope,
                remote_root: &str,
            ) -> Result<(), BackendError> {
                if owner != &self.owner || vault != &self.vault || remote_root != self.remote_root {
                    return Err(BackendError::Unavailable);
                }
                Ok(())
            }
            fn catalogue_snapshot(
                &self,
            ) -> Result<Vec<crate::vault_custody::VaultCatalogueEntry>, BackendError> {
                let state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
                Ok(state
                    .catalogue
                    .iter()
                    .map(
                        |(identity, metadata)| crate::vault_custody::VaultCatalogueEntry {
                            identity: *identity,
                            metadata: metadata.clone(),
                        },
                    )
                    .collect())
            }
            fn persist_catalogue(
                &self,
                entries: &[crate::vault_custody::VaultCatalogueEntry],
            ) -> Result<(), BackendError> {
                let mut state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
                let mut next = state.catalogue.clone();
                let mut seen = std::collections::BTreeSet::new();
                for entry in entries {
                    let m = &entry.metadata;
                    if entry.identity == [0; 16]
                        || !seen.insert(entry.identity)
                        || m.id.is_empty()
                        || !m.path.starts_with('/')
                        || m.writable
                        || (m.path == "/" && (!m.directory || m.id != self.vault.resource_id()))
                        || next.get(&entry.identity).is_some_and(|old| old != m)
                    {
                        return Err(BackendError::Unavailable);
                    }
                    next.insert(entry.identity, m.clone());
                }
                if next.len() > 1024 {
                    return Err(BackendError::Unavailable);
                }
                state.catalogue = next;
                Ok(())
            }
            fn persist_hydration(
                &self,
                intent: &crate::vault_custody::VaultHydrationIntent,
            ) -> Result<(), BackendError> {
                let mut state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
                let entry = state
                    .catalogue
                    .get(&intent.identity)
                    .ok_or(BackendError::Unavailable)?;
                if intent.root != self.root
                    || intent.file_index == 0
                    || entry.directory
                    || intent.length != entry.size
                    || intent.components.is_empty()
                    || intent.components.len() > 256
                    || intent.components.iter().map(String::len).sum::<usize>() > 32000
                    || intent
                        .components
                        .iter()
                        .any(|name| !crate::opencloud::valid_windows_component(name))
                {
                    return Err(BackendError::Unavailable);
                }
                let row = FixtureHydration {
                    identity: intent.identity,
                    length: intent.length,
                    components: intent.components.clone(),
                };
                if state.hydrations.iter().any(|(file, old)| {
                    (*file == intent.file_index || old.identity == intent.identity)
                        && (*file != intent.file_index || old != &row)
                }) {
                    return Err(BackendError::Unavailable);
                }
                if state.hydrations.len() >= 4096
                    && !state.hydrations.contains_key(&intent.file_index)
                {
                    return Err(BackendError::Unavailable);
                }
                state.hydrations.insert(intent.file_index, row);
                Ok(())
            }
        }
        use super::*;
        use crate::ProviderScope;
        use crate::opencloud::{
            OpaqueIdentity, OpenCloudPlaceholderBackend, ProviderIdentityBinding,
            ProviderIdentityCatalog, ProviderIdentityCatalogScope,
        };
        struct MemoryCatalogue;
        impl ProviderIdentityCatalog for MemoryCatalogue {
            fn load(
                &self,
                _: &ProviderIdentityCatalogScope,
            ) -> Result<Vec<ProviderIdentityBinding>, BackendError> {
                Ok(Vec::new())
            }
            fn upsert(
                &self,
                _: &ProviderIdentityCatalogScope,
                _: &ProviderIdentityBinding,
            ) -> Result<(), BackendError> {
                Ok(())
            }
            fn remove(
                &self,
                _: &ProviderIdentityCatalogScope,
                _: OpaqueIdentity,
            ) -> Result<(), BackendError> {
                Ok(())
            }
        }
        use raiun_control_windows::PinnedDirectory;
        use raiun_opencloud::OpenCloudClient;
        use raiun_vault::session::{VaultSessionCoordinator, VaultSessionScope};
        use std::{
            collections::BTreeMap,
            io::{Read, Write},
            net::{TcpListener, TcpStream},
            sync::atomic::{AtomicBool, AtomicUsize, Ordering},
            thread::{self, JoinHandle},
            time::{Duration, SystemTime, UNIX_EPOCH},
        };
        const SPACE: &str = "personal-drive";
        const ROOT_ID: &str = "vault-root-id";
        const ROOT_PATH: &str = "/Travel.vault";
        // Public web fixture's encrypted name for plaintext component "1".
        const NAME: &str = "9cmn80lns8obm4t3koceogil20";
        const CIPHERTEXT: &[u8] = include_bytes!("../../raiun-vault/tests/fixtures/web-65537.bin");
        const TOKEN: &str =
            include_str!("../../raiun-vault/tests/fixtures/web-integrity-token.b64");

        // Required GET/PROPFIND response fields and Windows blocking accepted
        // sockets are reused from opencloud/tests/vault_backend.rs. No writes,
        // nested namespace, offline cache or general server dispatcher exists.
        struct Fixture {
            origin: String,
            stop: Arc<AtomicBool>,
            gets: Arc<AtomicUsize>,
            mutations: Arc<AtomicUsize>,
            #[cfg(feature = "synthetic-agent-integration")]
            requests: Arc<Mutex<BTreeMap<&'static str, usize>>>,
            worker: Option<JoinHandle<()>>,
        }
        impl Fixture {
            fn start() -> Self {
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                listener.set_nonblocking(true).unwrap();
                let authority = listener.local_addr().unwrap().to_string();
                let stop = Arc::new(AtomicBool::new(false));
                let gets = Arc::new(AtomicUsize::new(0));
                let mutations = Arc::new(AtomicUsize::new(0));
                let (end, content, writes) = (stop.clone(), gets.clone(), mutations.clone());
                let requests_seen = Arc::new(Mutex::new(BTreeMap::new()));
                let requests_worker = requests_seen.clone();
                let server_authority = authority.clone();
                let worker = thread::spawn(move || {
                    let mut requests = 0;
                    while !end.load(Ordering::Acquire) {
                        match listener.accept() {
                            Ok((stream, _)) => {
                                requests += 1;
                                assert!(requests <= 256, "bounded synthetic read requests");
                                serve(
                                    stream,
                                    &server_authority,
                                    &content,
                                    &writes,
                                    &requests_worker,
                                );
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                thread::sleep(Duration::from_millis(2))
                            }
                            Err(_) => panic!("synthetic listener failed"),
                        }
                    }
                });
                Self {
                    origin: format!("http://{authority}"),
                    stop,
                    gets,
                    mutations,
                    #[cfg(feature = "synthetic-agent-integration")]
                    requests: requests_seen,
                    worker: Some(worker),
                }
            }
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                self.stop.store(true, Ordering::Release);
                if let Some(worker) = self.worker.take() {
                    let joined = worker.join();
                    if !thread::panicking() {
                        joined.expect("synthetic read server");
                    }
                }
            }
        }
        fn respond(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) {
            let _ = write!(
                stream,
                "HTTP/1.1 {status} Response\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(body);
        }
        fn listing(authority: &str, file_only: bool, include_child: bool) -> String {
            let prefix = format!("http://{authority}/dav/personal/Travel.vault/");
            let file = format!(
                r#"<d:response><d:href>{prefix}{NAME}</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>{}</d:getcontentlength><d:getetag>"child-rev-1"</d:getetag><oc:fileid>child-resource-id</oc:fileid><oc:name>{NAME}</oc:name><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"#,
                CIPHERTEXT.len()
            );
            let root = format!(
                r#"<d:response><d:href>{prefix}</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>"root-rev-2"</d:getetag><d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype><oc:fileid>{ROOT_ID}</oc:fileid><oc:name>Travel.vault</oc:name><oc:size>0</oc:size><oc:permissions>RDNVW</oc:permissions><ocrclone:integrity-id>{}</ocrclone:integrity-id></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"#,
                TOKEN.trim()
            );
            let rows = if file_only {
                file
            } else if include_child {
                root + &file
            } else {
                root
            };
            format!(
                r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:ocrclone="ocrclone">{rows}</d:multistatus>"#
            )
        }
        fn personal_parent_listing(authority: &str, include_child: bool) -> String {
            let parent = format!(
                r#"<d:response><d:href>http://{authority}/dav/personal/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength><d:getetag>"space-rev-1"</d:getetag><oc:fileid>space-root-id</oc:fileid><oc:name>Personal</oc:name><oc:permissions>RDNVW</oc:permissions></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"#
            );
            let child_xml = listing(authority, false, false);
            let child = if include_child {
                &child_xml[child_xml.find("<d:response>").unwrap()
                    ..child_xml.rfind("</d:multistatus>").unwrap()]
            } else {
                ""
            };
            format!(
                r#"<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:ocrclone="ocrclone">{parent}{child}</d:multistatus>"#
            )
        }
        fn serve(
            mut stream: TcpStream,
            authority: &str,
            gets: &AtomicUsize,
            mutations: &AtomicUsize,
            requests: &Mutex<BTreeMap<&'static str, usize>>,
        ) {
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut raw = Vec::new();
            let mut byte = [0];
            while !raw.ends_with(b"\r\n\r\n") {
                if stream.read_exact(&mut byte).is_err() {
                    return;
                }
                raw.push(byte[0]);
                assert!(raw.len() <= 64 * 1024);
            }
            let text = String::from_utf8(raw).unwrap();
            let mut lines = text.lines();
            let mut first = lines.next().unwrap().split_ascii_whitespace();
            let method = first.next().unwrap();
            let target = first.next().unwrap();
            let headers: BTreeMap<_, _> = lines
                .filter_map(|line| {
                    let (k, v) = line.split_once(':')?;
                    Some((k.to_ascii_lowercase(), v.trim().to_owned()))
                })
                .collect();
            let length = headers
                .get("content-length")
                .map(|v| v.parse::<usize>().unwrap())
                .unwrap_or(0);
            assert!(length <= 64 * 1024);
            let mut body = vec![0; length];
            if stream.read_exact(&mut body).is_err() {
                return;
            }
            if headers.get("authorization").map(String::as_str) != Some("Bearer synthetic-token") {
                respond(&mut stream, 401, "text/plain", b"unauthorized");
                return;
            }
            let child = format!("/dav/personal/Travel.vault/{NAME}");
            let route_label = match (method, target) {
                ("GET", "/graph/v1.0/me/drives") => "GET_GRAPH",
                ("PROPFIND", "/dav/personal/")
                    if headers.get("depth").map(String::as_str) == Some("0") =>
                {
                    "PROPFIND_PARENT_DEPTH0"
                }
                ("PROPFIND", "/dav/personal/") => "PROPFIND_PARENT_DEPTH1",
                ("PROPFIND", "/dav/personal") => "PROPFIND_PARENT_NO_TRAILING_SLASH",
                ("PROPFIND", "/dav/personal/Travel.vault") => "PROPFIND_VAULT_NO_TRAILING_SLASH",
                ("PROPFIND", "/dav/personal/Travel.vault/") => "PROPFIND_VAULT",
                ("PROPFIND", path) if path == child => "PROPFIND_FILE",
                ("GET", path) if path == child => "GET_CIPHERTEXT",
                _ => "OTHER",
            };
            *requests.lock().unwrap().entry(route_label).or_insert(0) += 1;

            match (method, target) {
                ("GET", "/graph/v1.0/me/drives") => {
                    let graph = format!(
                        r#"{{"value":[{{"id":"{SPACE}","name":"Personal","driveType":"personal","root":{{"id":"space-root-id","webDavUrl":"http://{authority}/dav/personal/","permissions":"RDNVW"}}}}]}}"#
                    );
                    respond(&mut stream, 200, "application/json", graph.as_bytes());
                }
                ("PROPFIND", "/dav/personal/") => respond(
                    &mut stream,
                    207,
                    "application/xml",
                    personal_parent_listing(
                        authority,
                        headers.get("depth").map(String::as_str) != Some("0"),
                    )
                    .as_bytes(),
                ),
                ("PROPFIND", "/dav/personal/Travel.vault/") => respond(
                    &mut stream,
                    207,
                    "application/xml",
                    listing(
                        authority,
                        false,
                        headers.get("depth").map(String::as_str) != Some("0"),
                    )
                    .as_bytes(),
                ),
                ("PROPFIND", path) if path == child => respond(
                    &mut stream,
                    207,
                    "application/xml",
                    listing(authority, true, false).as_bytes(),
                ),
                ("GET", path)
                    if path == child
                        && headers.get("if-match").map(String::as_str)
                            == Some("\"child-rev-1\"") =>
                {
                    gets.fetch_add(1, Ordering::AcqRel);
                    respond(&mut stream, 200, "application/octet-stream", CIPHERTEXT);
                }
                _ => {
                    if !matches!(method, "GET" | "PROPFIND") {
                        mutations.fetch_add(1, Ordering::AcqRel);
                    }
                    respond(
                        &mut stream,
                        404,
                        "text/plain",
                        b"unsupported synthetic route",
                    );
                }
            }
        }

        #[cfg(feature = "synthetic-agent-integration")]
        #[test]
        #[ignore = "requires isolated ordinary-user Windows VM with Cloud Files; preserves owned registered namespace"]
        fn native_registered_vault_refresh_reads_and_retires_owned_route() {
            registered_vault_refresh_and_retirement(false);
        }

        #[cfg(feature = "synthetic-agent-integration")]
        #[test]
        #[ignore = "requires isolated ordinary-user Windows VM with Cloud Files; preserves owned dirty file and registered namespace"]
        fn native_registered_vault_dirty_file_refuses_cleanup_and_preserves_bytes() {
            registered_vault_refresh_and_retirement(true);
        }

        #[cfg(feature = "synthetic-agent-integration")]
        fn write_owned_dirty_fixture_in_child(path: &std::path::Path) -> bool {
            use std::process::{Command, Stdio};
            assert!(path.is_absolute());
            assert_eq!(path.file_name(), Some(std::ffi::OsStr::new("1")));
            // External ordinary client, matching real editor I/O. Provider-process
            // fixture writes did not produce a Cloud Files close notification.
            // Only this freshly-created guest fixture path is supplied, through
            // a child-local environment entry; payload bytes are public constants.
            let Ok(mut child) = Command::new("powershell.exe")
                .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
                    "$ErrorActionPreference='Stop'; try { $b=New-Object byte[] 65537; for($i=0;$i -lt $b.Length;$i++){ $b[$i]=[byte](((($i*31+7) -band 255) -bxor 90)) }; $f=[System.IO.File]::Open($env:RAIUN_SYNTHETIC_DIRTY_FILE,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Write,[System.IO.FileShare]::Read); try { if($f.Length -ne $b.Length){exit 35}; $f.Write($b,0,$b.Length); $f.Flush($true) } finally { $f.Dispose() }; [Console]::WriteLine('SYNTHETIC_DIRTY_WRITE_COMPLETE=true') } catch { exit 24 }"])
                .env("RAIUN_SYNTHETIC_DIRTY_FILE", path)
                .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null())
                .spawn() else { return false; };
            let deadline = std::time::Instant::now() + Duration::from_secs(15);
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        let Ok(output) = child.wait_with_output() else {
                            return false;
                        };
                        return status.success()
                            && output.stdout == b"SYNTHETIC_DIRTY_WRITE_COMPLETE=true\r\n";
                    }
                    Ok(None) if std::time::Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(20))
                    }
                    _ => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return false;
                    }
                }
            }
        }

        #[cfg(feature = "synthetic-agent-integration")]
        fn registered_vault_refresh_and_retirement(dirty: bool) {
            assert!(
                std::env::var("USERNAME")
                    .unwrap_or_default()
                    .eq_ignore_ascii_case("RaiunLabUser")
            );
            let fixture_root = std::env::temp_dir().join(format!(
                "raiun-vault-native-refresh-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&fixture_root).unwrap();
            println!("VAULT_NATIVE_REFRESH_FIXTURE={}", fixture_root.display());
            let native_path = fixture_root.join("native-root");
            std::fs::create_dir(&native_path).unwrap();
            let lease = crate::pin_configured_root(&native_path).unwrap();
            let local_root = lease.identity();
            println!(
                "VAULT_NATIVE_REFRESH_ROOT_ID={}:{}",
                local_root.volume_serial, local_root.file_index
            );
            let fixture_parent = PinnedDirectory::open(&fixture_root).unwrap();
            let private = Arc::new(
                PrivateDirectory::create_or_open_under(
                    &fixture_parent,
                    OsStr::new("private-stage"),
                )
                .unwrap(),
            );
            let fixture = Fixture::start();
            let client =
                Arc::new(OpenCloudClient::new(&fixture.origin, "synthetic-token".into()).unwrap());
            let origin = client.server_origin().unwrap();
            let account =
                format!("{origin}\0{SPACE}")
                    .bytes()
                    .fold(String::new(), |mut result, byte| {
                        use std::fmt::Write as _;
                        write!(result, "{byte:02x}").unwrap();
                        result
                    });
            let trusted = ProviderScope::new(&client, "default".into(), account, origin).unwrap();
            let recovery = Arc::new(
                crate::DurableEditRecoveryProvider::current_user(trusted.clone(), local_root)
                    .unwrap(),
            );
            let ordinary = Arc::new(
                OpenCloudPlaceholderBackend::new_with_identity_catalog(
                    client.clone(),
                    trusted.clone(),
                    local_root,
                    recovery.identity_catalog(),
                )
                .unwrap(),
            );
            let composite = ordinary
                .register_composite_root_for(SPACE, "space-root-id")
                .unwrap();
            let runtime = crate::prepare_configured_root_runtime(
                lease,
                ordinary.clone(),
                composite,
                recovery.clone(),
            )
            .unwrap();
            let mut connection = crate::connect_configured_root(runtime).unwrap();
            let sessions = Arc::new(VaultSessionCoordinator::new());
            let scope = VaultSessionScope::new("default", &fixture.origin, SPACE, ROOT_ID).unwrap();
            let mut password = b"potato".to_vec();
            sessions
                .unlock(&scope, &mut password, TOKEN.trim())
                .unwrap();
            assert!(password.iter().all(|byte| *byte == 0));
            let custody = Arc::new(FixtureCustody::new(
                trusted.clone(),
                scope.clone(),
                ROOT_PATH,
                local_root,
            ));
            let binding = Arc::new(
                WindowsVaultReadBinding::new_online(
                    trusted,
                    client,
                    sessions.clone(),
                    scope.clone(),
                    ROOT_PATH.into(),
                )
                .unwrap(),
            );
            let vault = Arc::new(
                WindowsVaultPlaceholderBackend::new(
                    binding.clone(),
                    private.clone(),
                    131072,
                    custody.clone(),
                )
                .unwrap(),
            );
            ordinary
                .install_vault_route(vault.clone(), local_root)
                .unwrap();
            // Prove the exact ordinary provider parent listing independently
            // before asking the OS; drop all prepared leases before native work.
            let parent_id = ordinary
                .register_directory(SPACE, "space-root-id", "/")
                .unwrap();
            let cancellation = CancellationToken::new();
            let provider_listing = ordinary
                .prepare_enumeration(parent_id.as_bytes(), &cancellation)
                .unwrap_or_else(|error| {
                    println!(
                        "VAULT_REFRESH_REQUEST_COUNTS={:?}",
                        fixture.requests.lock().unwrap()
                    );
                    panic!("provider parent listing refused: {error:?}");
                });
            let provider_names = provider_listing
                .children()
                .iter()
                .map(|child| child.name.clone())
                .collect::<Vec<_>>();
            println!(
                "VAULT_REFRESH_PROVIDER_NAMES={:?}",
                &provider_names[..provider_names.len().min(16)]
            );
            assert!(provider_names.iter().any(|name| name == "Travel.vault"));
            drop(provider_listing);
            println!(
                "VAULT_REFRESH_BEFORE={:?}",
                connection.directory_observation()
            );
            ordinary
                .refresh_vault_parent_population(&connection, local_root, SPACE, ROOT_ID, ROOT_PATH)
                .unwrap();
            println!(
                "VAULT_REFRESH_AFTER={:?}",
                connection.directory_observation()
            );
            let personal = native_path.join("Personal");
            let external_parent = crate::tests::query_owned_fixture_directory_in_child(&personal);
            println!(
                "VAULT_REFRESH_AFTER_EXTERNAL_PARENT={:?}",
                connection.directory_observation()
            );
            println!(
                "VAULT_REFRESH_REQUEST_COUNTS={:?}",
                fixture.requests.lock().unwrap()
            );
            assert!(
                external_parent,
                "external Personal enumeration did not return its one fixture child"
            );
            let names = std::fs::read_dir(&personal)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>();
            println!("VAULT_REFRESH_OS_NAMES={:?}", &names[..names.len().min(16)]);
            println!(
                "VAULT_REFRESH_AFTER_QUERY={:?}",
                connection.directory_observation()
            );
            println!(
                "VAULT_REFRESH_REQUEST_COUNTS={:?}",
                fixture.requests.lock().unwrap()
            );
            assert!(names.iter().any(|name| name == "Travel.vault"));
            let vault_path = personal.join("Travel.vault");
            let external_vault = crate::tests::query_owned_fixture_directory_in_child(&vault_path);
            println!(
                "VAULT_REFRESH_AFTER_EXTERNAL_VAULT={:?}",
                connection.directory_observation()
            );
            assert!(
                external_vault,
                "external vault enumeration did not return its one fixture child"
            );
            let names = std::fs::read_dir(&vault_path)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>();
            assert_eq!(names, vec![std::ffi::OsString::from("1")]);
            let expected: Vec<u8> = (0..65537).map(|index| (index * 31 + 7) as u8).collect();
            use sha2::{Digest, Sha256};
            let expected_sha = format!("{:x}", Sha256::digest(&expected));
            let external_read = crate::tests::query_owned_fixture_file_in_child(
                &vault_path.join("1"),
                expected.len(),
                &expected_sha,
            );
            println!(
                "VAULT_REFRESH_AFTER_EXTERNAL_READ={:?}",
                connection.fetch_observation()
            );
            println!(
                "VAULT_REFRESH_FETCH_VALIDATION_STAGE={}",
                connection.fetch_validation_stage()
            );
            println!(
                "VAULT_REFRESH_REQUEST_COUNTS={:?}",
                fixture.requests.lock().unwrap()
            );
            assert!(
                external_read,
                "external decrypted read length/hash mismatch"
            );
            let bytes = std::fs::read(vault_path.join("1")).unwrap();
            assert_eq!(bytes, expected);
            assert!(
                (1..=16).contains(&fixture.gets.load(Ordering::Acquire)),
                "OS hydration must make bounded verified reads"
            );
            let dirty_bytes = if dirty {
                // Fixture-only adversarial local edit of this freshly created
                // synthetic file. Production never clears READONLY to clean it.
                let path = vault_path.join("1");
                let before = connection.close_observation_for_integration();
                let replacement = expected.iter().map(|byte| byte ^ 0x5a).collect::<Vec<_>>();
                assert_eq!(replacement.len(), expected.len());
                assert!(replacement != expected);
                let mut permissions = std::fs::metadata(&path).unwrap().permissions();
                assert!(permissions.readonly());
                // This Windows-only fixture deliberately clears the Windows
                // READONLY attribute; no Unix permission bits are involved.
                #[allow(clippy::permissions_set_readonly_false)]
                permissions.set_readonly(false);
                std::fs::set_permissions(&path, permissions).unwrap();
                let external_write = write_owned_dirty_fixture_in_child(&path);
                let mut permissions = std::fs::metadata(&path).unwrap().permissions();
                permissions.set_readonly(true);
                std::fs::set_permissions(&path, permissions).unwrap();
                assert!(
                    external_write,
                    "bounded external synthetic edit did not finish"
                );
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                loop {
                    let observed = connection.close_observation_for_integration();
                    // Stage 4 is reached only after native MODIFIED ranges are
                    // nonempty, before this vault's edit binding is refused.
                    if observed.0 > before.0 && observed.1 > before.1 && observed.4 == 4 {
                        println!("VAULT_DIRTY_NATIVE_CLOSE={observed:?}");
                        break;
                    }
                    assert!(
                        std::time::Instant::now() < deadline,
                        "real dirty close was not observed: {observed:?}"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
                Some(replacement)
            } else {
                None
            };
            println!(
                "VAULT_REFRESH_PRE_RETIRE_CLOSE={:?}",
                connection.close_observation_for_integration()
            );
            let retired = ordinary
                .retire_vault_route(SPACE, ROOT_ID, ROOT_PATH)
                .unwrap()
                .unwrap();
            println!(
                "VAULT_REFRESH_PRE_CLEANUP_CLOSE={:?}",
                connection.close_observation_for_integration()
            );
            let cleanup = connection.cleanup_retired_vault_route(&retired);
            if let Some(expected_dirty) = dirty_bytes.as_ref() {
                assert!(matches!(
                    cleanup,
                    Err(crate::Error::UnresolvedPlaceholderEdits)
                ));
                assert!(
                    std::fs::read(vault_path.join("1")).unwrap() == *expected_dirty,
                    "dirty bytes must remain intact"
                );
            } else {
                cleanup.unwrap();
            }
            assert!(
                std::fs::metadata(vault_path.join("1"))
                    .unwrap()
                    .permissions()
                    .readonly(),
                "cleanup must preserve the vault file read-only attribute"
            );
            assert!(
                binding
                    .try_begin_publish(&CancellationToken::new())
                    .is_err()
            );
            assert_eq!(fixture.mutations.load(Ordering::Acquire), 0);
            sessions.lock(&scope).unwrap();
            ordinary.revoke();
            connection.disconnect_in_place().unwrap();
            if let Some(expected_dirty) = dirty_bytes.as_ref() {
                assert!(
                    std::fs::read(vault_path.join("1")).unwrap() == *expected_dirty,
                    "dirty bytes must remain intact"
                );
                assert!(
                    std::fs::metadata(vault_path.join("1"))
                        .unwrap()
                        .permissions()
                        .readonly()
                );
                assert_eq!(fixture.mutations.load(Ordering::Acquire), 0);
                println!("VAULT_DIRTY_CLEANUP_REFUSED_BYTES_PRESERVED=true");
            }
            drop(connection);
            drop(retired);
            drop(vault);
            drop(binding);
            drop(ordinary);
            drop(recovery);
            drop(sessions);
            assert_eq!(std::fs::read_dir(private.path()).unwrap().count(), 0);
            drop(private);
            drop(fixture_parent);
            drop(fixture);
            // Intentionally retain the exact registration and populated namespace,
            // plus fixture-local recovery evidence, on success and failure.
            println!("VAULT_NATIVE_REFRESH_PRESERVED=true");
        }

        #[test]
        #[ignore = "requires isolated ordinary-user Windows private storage and loopback; no Cloud Files registration, credentials or GUI"]
        fn native_verified_vault_read_path_rejects_old_epoch_after_reunlock() {
            assert!(
                std::env::var("USERNAME")
                    .unwrap_or_default()
                    .eq_ignore_ascii_case("RaiunLabUser")
            );
            let root = std::env::temp_dir().join(format!(
                "raiun-vault-adapter-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&root).unwrap();
            println!("VAULT_ADAPTER_FIXTURE={}", root.display());
            let parent = PinnedDirectory::open(&root).unwrap();
            let private = Arc::new(
                PrivateDirectory::create_or_open_under(&parent, OsStr::new("private-stage"))
                    .unwrap(),
            );
            let fixture = Fixture::start();
            let client =
                Arc::new(OpenCloudClient::new(&fixture.origin, "synthetic-token".into()).unwrap());
            let sessions = Arc::new(VaultSessionCoordinator::new());
            let scope = VaultSessionScope::new("default", &fixture.origin, SPACE, ROOT_ID).unwrap();
            let mut password = b"potato".to_vec();
            sessions
                .unlock(&scope, &mut password, TOKEN.trim())
                .unwrap();
            assert!(password.iter().all(|b| *b == 0));
            let trusted = ProviderScope::new(
                &client,
                "default".into(),
                "synthetic-subject".into(),
                fixture.origin.clone(),
            )
            .unwrap();
            let binding = Arc::new(
                WindowsVaultReadBinding::new_online(
                    trusted.clone(),
                    client.clone(),
                    sessions.clone(),
                    scope.clone(),
                    ROOT_PATH.into(),
                )
                .unwrap(),
            );
            let pinned = parent.identity();
            let local_root = crate::ConfiguredRootIdentity {
                volume_serial: pinned.volume_serial,
                file_index: pinned.file_index,
            };
            let custody = Arc::new(FixtureCustody::new(
                trusted.clone(),
                scope.clone(),
                ROOT_PATH,
                local_root,
            ));
            let backend = Arc::new(
                WindowsVaultPlaceholderBackend::new(
                    binding.clone(),
                    private.clone(),
                    131072,
                    custody.clone(),
                )
                .unwrap(),
            );
            let ordinary = OpenCloudPlaceholderBackend::new_with_identity_catalog(
                client.clone(),
                trusted,
                local_root,
                Arc::new(MemoryCatalogue),
            )
            .unwrap();
            let mut wrong_root = local_root;
            wrong_root.file_index ^= 1;
            assert!(
                ordinary
                    .install_vault_route(backend.clone(), wrong_root)
                    .is_err()
            );
            let route = ordinary
                .install_vault_route(backend.clone(), local_root)
                .unwrap();
            assert_eq!(route.space_id(), SPACE);
            assert_eq!(route.root_resource_id(), ROOT_ID);
            assert_eq!(route.root_path(), ROOT_PATH);
            let cancellation = CancellationToken::new();
            let root_id = backend.root_identity();
            let mut unknown = root_id;
            unknown[0] ^= 1;
            assert!(backend.lookup(&unknown).unwrap().is_none());
            assert!(
                backend
                    .prepare_fetch_session(&unknown, &cancellation)
                    .is_err()
            );
            assert!(ordinary.lookup(&root_id).unwrap().unwrap().is_directory);
            let listing = ordinary
                .prepare_enumeration(&root_id, &cancellation)
                .unwrap();
            assert_eq!(listing.children().len(), 1);
            let child = listing.children()[0].clone();
            assert_eq!(child.name, "1");
            assert!(!child.metadata.is_directory);
            assert_eq!(child.metadata.length, 65537);
            let permit = listing.begin_publish(&cancellation).unwrap();
            drop(permit);
            drop(listing);
            let session = ordinary
                .prepare_fetch_session(&child.identity, &cancellation)
                .unwrap();
            let fetched = session
                .prepare_window(
                    FetchRange {
                        offset: 0,
                        end: 65537,
                    },
                    &cancellation,
                )
                .unwrap();
            let expected: Vec<u8> = (0..65537).map(|index| (index * 31 + 7) as u8).collect();
            let permit = fetched.begin_publish(&cancellation).unwrap();
            assert_eq!(fetched.bytes(), expected.as_slice());
            drop(permit);
            drop(fetched);
            assert_eq!(fixture.gets.load(Ordering::Acquire), 1);
            assert!(ordinary.remove_vault_route(SPACE, ROOT_ID).unwrap());
            assert!(!ordinary.remove_vault_route(SPACE, ROOT_ID).unwrap());
            assert!(
                route
                    .backend()
                    .binding()
                    .try_begin_publish(&cancellation)
                    .is_err()
            );
            assert!(ordinary.lookup(&root_id).unwrap().is_none());
            assert!(
                ordinary
                    .prepare_fetch_session(&child.identity, &cancellation)
                    .is_err()
            );
            ordinary.revoke();
            assert!(ordinary.lookup(&root_id).is_err());
            sessions.lock(&scope).unwrap();
            let mut password = b"potato".to_vec();
            sessions
                .unlock(&scope, &mut password, TOKEN.trim())
                .unwrap();
            assert!(password.iter().all(|b| *b == 0));
            assert!(binding.try_begin_publish(&cancellation).is_err());
            assert!(
                session
                    .prepare_window(FetchRange { offset: 0, end: 1 }, &cancellation)
                    .is_err()
            );
            assert!(backend.lookup(&root_id).is_err());
            assert_eq!(fixture.gets.load(Ordering::Acquire), 1);
            assert_eq!(fixture.mutations.load(Ordering::Acquire), 0);
            drop(session);
            drop(route);
            drop(ordinary);
            drop(backend);
            drop(binding);
            drop(sessions);
            assert_eq!(std::fs::read_dir(private.path()).unwrap().count(), 0);
            drop(fixture);
            drop(private);
            drop(parent);
            // Preserve this exclusively owned synthetic root on every earlier panic.
            std::fs::remove_dir_all(root).unwrap();
        }
    }
}
#[cfg(windows)]
pub use runtime::WindowsVaultPlaceholderBackend;

#[cfg(test)]
mod tests {
    use super::*;
    fn entry(path: &str, id: &str, directory: bool, etag: &str, size: u64) -> RemoteEntry {
        RemoteEntry {
            id: id.into(),
            path: path.into(),
            directory,
            size,
            etag: etag.into(),
            modified_unix: 0,
            writable: false,
            encrypted: false,
        }
    }
    #[test]
    fn catalogue_opaque_ids_preserve_exact_file_version_and_directory_identity() {
        let mut catalogue = Catalogue::default();
        let original = entry("/a", "file", false, "v1", 5);
        let id = catalogue.insert(original.clone()).unwrap();
        assert_eq!(catalogue.insert(original).unwrap(), id);
        let next = catalogue
            .insert(entry("/a", "file", false, "v2", 5))
            .unwrap();
        assert_ne!(id, next);
        assert_eq!(catalogue.get(&id).unwrap().etag, "v1");
        assert!(catalogue.get(&[1; 15]).is_none());
        assert!(catalogue.get(&[0; 16]).is_none());
        let dir = catalogue
            .insert(entry("/dir", "directory", true, "v1", 0))
            .unwrap();
        assert_eq!(
            catalogue
                .insert(entry("/dir", "directory", true, "v2", 9))
                .unwrap(),
            dir
        );
    }
    #[test]
    fn whole_listing_refuses_unsafe_duplicate_or_nonchild_without_partial_mapping() {
        let mut catalogue = Catalogue::default();
        let root = entry("/", "root", true, "", 0);
        catalogue.insert(root.clone()).unwrap();
        for rows in [
            vec![
                entry("/ok", "one", false, "v", 1),
                entry("/CON", "two", false, "v", 1),
            ],
            vec![
                entry("/Name", "one", false, "v", 1),
                entry("/name", "two", false, "v", 1),
            ],
            vec![entry("/nested/child", "one", false, "v", 1)],
        ] {
            assert!(catalogue.stage_listing(&root, rows).is_err());
            assert_eq!(catalogue.entries.len(), 1);
        }
        let (next, children) = catalogue
            .stage_listing(&root, vec![entry("/safe.txt", "file", false, "v", 1)])
            .unwrap();
        assert_eq!(next.entries.len(), 2);
        assert_eq!(children[0].name, "safe.txt");
        assert_eq!(children[0].metadata.length, 1);
        assert!(
            catalogue
                .stage_listing(
                    &root,
                    vec![entry("/x", "file", false, "v", 1); MAX_DIRECTORY_CHILDREN + 1]
                )
                .is_err()
        );
    }
}
