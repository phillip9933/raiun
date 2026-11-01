//! One explicit create attempt; remote facts never authorize native completion.
use super::*;
use crate::namespace_intent::{
    CapturedAuthorization, NamespaceDestinationReport, NamespaceIntent, NamespaceOperation,
};
use crate::streamed_store::namespace_file_store::VerifiedFileJoin;

pub(crate) type Current = Arc<dyn Fn(CapturedAuthorization) -> bool + Send + Sync>;
pub(crate) struct Admission {
    pub(crate) parent: namespace::CapturedDirectoryParent,
    catalog: Arc<dyn ProviderIdentityCatalog>,
    catalog_scope: ProviderIdentityCatalogScope,
    auth: CapturedAuthorization,
    job: crate::StreamedRecoveryJob,
    current: Current,
    attempted: bool,
    backend: std::sync::Weak<OpenCloudPlaceholderBackend>,
}
impl Admission {
    pub(crate) fn capture_job(&self) -> crate::StreamedRecoveryJob {
        self.job.clone()
    }
    pub(crate) fn persist(
        &self,
        backend: &Arc<OpenCloudPlaceholderBackend>,
        lease: &mut crate::streamed_store::namespace_file_store::FileCreateLease,
        proof: &VerifiedCreateReadback,
    ) -> Result<(), BackendError> {
        self.check(backend)?;
        lease
            .record_remote_verified(proof)
            .map_err(|_| BackendError::Unavailable)?;
        self.check(backend)
    }
    /// Exact FILE publication; no discovery, HTTP or journal I/O under this fence.
    pub(crate) fn publish_and_complete<T>(
        &self,
        backend: &Arc<OpenCloudPlaceholderBackend>,
        proof: &VerifiedCreateReadback,
        complete: impl FnOnce(&[u8; 16]) -> Result<T, crate::Error>,
    ) -> Result<T, crate::Error> {
        let unavailable = || crate::Error::EditRecoveryUnavailable;
        self.check(backend).map_err(|_| unavailable())?;
        let report = proof.report_for(&proof.intent).map_err(|_| unavailable())?;
        if report.destination.parent.scope != self.parent.scope
            || report.destination.parent.authorization != self.auth
            || report.destination.parent.remote != self.parent.remote
        {
            return Err(unavailable());
        }
        let scope = &self.parent.scope;
        let path = format!("/{}", report.destination.name);
        // Refresh the exact historical readback tuple before entering the local
        // publication fence. This is bounded metadata observation, not remote CAS.
        let context = RangeReadContext {
            deadline: self.job.deadline(),
            token_generation: self.auth.token_generation,
        };
        let root = backend
            .client
            .stat_with_context(&scope.space_id, "/", context)
            .map_err(|_| unavailable())?;
        self.check(backend).map_err(|_| unavailable())?;
        if !root.directory || root.encrypted || !root.writable || root.id != scope.root_resource_id
        {
            return Err(unavailable());
        }
        let observed = backend
            .client
            .stat_with_context(&scope.space_id, &path, context)
            .map_err(|_| unavailable())?;
        self.check(backend).map_err(|_| unavailable())?;
        if observed.path != path
            || observed.directory
            || observed.encrypted
            || !observed.writable
            || observed.id != report.remote.resource_id
            || observed.etag != report.remote.etag
            || !namespace::strong(&observed.etag)
            || observed.size != report.remote.byte_len
        {
            return Err(unavailable());
        }
        let identity = binding_identity(
            &self.catalog_scope,
            "file",
            &[
                &scope.space_id,
                &scope.root_resource_id,
                &path,
                &report.remote.resource_id,
            ],
        );
        let binding = FileBinding {
            space_id: scope.space_id.clone(),
            root_resource_id: scope.root_resource_id.clone(),
            path,
            remote_id: report.remote.resource_id.clone(),
            etag: report.remote.etag.clone(),
            size: report.remote.byte_len,
        };
        let _permit = backend
            .begin_scoped_publish(self.job.cancellation())
            .map_err(|_| unavailable())?;
        self.check(backend).map_err(|_| unavailable())?;
        let mut state = backend.state.try_lock().map_err(|_| unavailable())?;
        // Inspect the original tuples under this already-held state guard;
        // never recurse through owns_composite_root_identity/state.lock here.
        let composite =
            composite_root_identity(&backend.scope, &scope.space_id, &scope.root_resource_id);
        let root_current = matches!(state.namespace_directories.get(&composite),
            Some(NamespaceDirectory::Root { account_id, personal_space_id, personal_root_id })
                if account_id == backend.scope.account_id()
                && personal_space_id == &scope.space_id && personal_root_id == &scope.root_resource_id);
        let parent_current = state
            .directories
            .get(&self.parent.identity)
            .is_some_and(|parent| {
                parent.space_id == scope.space_id
                    && parent.root_resource_id == scope.root_resource_id
                    && parent.path == self.parent.path
                    && parent.remote_id == self.parent.remote.resource_id
            });
        if !root_current || !parent_current {
            return Err(unavailable());
        }
        if binding_count(&state) >= MAX_IDENTITY_CATALOG_ENTRIES
            || state.directories.contains_key(&identity)
            || state.namespace_directories.contains_key(&identity)
            || state.files.iter().any(|(key, prior)| {
                (*key == identity && prior != &binding)
                    || (prior.space_id == binding.space_id
                        && prior.root_resource_id == binding.root_resource_id
                        && prior.path == binding.path
                        && prior != &binding)
            })
        {
            return Err(unavailable());
        }
        backend
            .upsert_identity_binding(
                &self.catalog_scope,
                &ProviderIdentityBinding::File {
                    identity: *identity.as_bytes(),
                    space_id: binding.space_id.clone(),
                    root_resource_id: binding.root_resource_id.clone(),
                    path: binding.path.clone(),
                    remote_id: binding.remote_id.clone(),
                    etag: binding.etag.clone(),
                    size: binding.size,
                },
            )
            .map_err(|_| unavailable())?;
        state.files.insert(identity, binding);
        self.check(backend).map_err(|_| unavailable())?;
        let result = complete(identity.as_bytes())?;
        self.check(backend).map_err(|_| unavailable())?;
        Ok(result)
    }
    pub(crate) fn check(
        &self,
        backend: &Arc<OpenCloudPlaceholderBackend>,
    ) -> Result<(), BackendError> {
        self.job.check()?;
        if self
            .backend
            .upgrade()
            .is_none_or(|b| !Arc::ptr_eq(&b, backend))
            || !(self.current)(self.auth)
            || self.auth.token_generation != backend.token_generation
            || backend
                .identity_catalog
                .as_ref()
                .is_none_or(|c| !Arc::ptr_eq(c, &self.catalog))
            || self.catalog_scope.local_root().volume_serial != self.parent.scope.root_volume_serial
            || self.catalog_scope.local_root().file_index != self.parent.scope.root_file_index
        {
            return Err(BackendError::Unavailable);
        }
        backend.ensure_active()
    }
    pub(crate) fn send(
        &mut self,
        backend: &Arc<OpenCloudPlaceholderBackend>,
        joined: VerifiedFileJoin,
        before_sdk: impl FnOnce() -> Result<(), BackendError>,
    ) -> Result<VerifiedCreateReadback, BackendError> {
        self.check(backend)?;
        if self.attempted {
            return Err(BackendError::Unavailable);
        }
        self.attempted = true;
        let intent = joined.record().intent().clone();
        let NamespaceOperation::CreateFile {
            destination,
            content,
        } = &intent.operation
        else {
            return Err(BackendError::Unavailable);
        };
        if destination.parent.scope != self.parent.scope
            || destination.parent.authorization != self.auth
            || destination.parent.local_components != ["Personal"]
            || destination.parent.remote != self.parent.remote
            || joined.manifest().binding().remote.is_some()
            || joined.manifest().binding().generation != intent.record_generation
            || joined.manifest().binding().local_file != destination.local_file
            || joined.manifest().binding().content_len != content.byte_len
            || joined.manifest().binding().scope != self.parent.scope
            || joined
                .manifest()
                .content_sha256()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
                != content.sha256
        {
            return Err(BackendError::Unavailable);
        }
        let digest = *joined.manifest().content_sha256();
        let job = self.job.clone();
        let current = self.current.clone();
        let auth = self.auth;
        let original = self.backend.clone();
        let cancelled: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new(move || {
            job.is_stopped()
                || !current(auth)
                || original.upgrade().is_none_or(|b| {
                    b.revoked.load(Ordering::Acquire)
                        || b.client.token_generation() != auth.token_generation
                })
        });
        let reader = joined
            .into_reader(cancelled.clone())
            .map_err(|_| BackendError::Unavailable)?;
        // No backend lease, account guard or parent callback spans SDK recursion.
        before_sdk()?;
        let proof = backend
            .client
            .recovery_create_blocking_reader_cancellable_with_context(
                &self.parent.scope.space_id,
                "/",
                &self.parent.scope.root_resource_id,
                &destination.name,
                reader,
                content.byte_len,
                digest,
                RangeReadContext {
                    deadline: self.job.deadline(),
                    token_generation: self.auth.token_generation,
                },
                cancelled,
            )
            .map_err(|_| BackendError::Unavailable)?;
        self.check(backend)?;
        let observed = proof.observed;
        if observed.entry.path != format!("/{}", destination.name)
            || observed.entry.directory
            || observed.entry.encrypted
            || !observed.entry.writable
            || !valid_remote_id(&observed.entry.id)
            || !namespace::strong(&observed.entry.etag)
            || observed.entry.size != content.byte_len
            || observed.bytes != content.byte_len
            || observed.sha256 != digest
        {
            return Err(BackendError::Unavailable);
        }
        let report = NamespaceDestinationReport {
            destination: destination.clone(),
            remote: crate::RemoteEditBaseline {
                resource_id: observed.entry.id,
                etag: observed.entry.etag,
                byte_len: observed.bytes,
            },
            content: Some(content.clone()),
        };
        Ok(VerifiedCreateReadback { intent, report })
    }
}
/// Constructor is private: only this original live SDK call can mint this fact.
pub(crate) struct VerifiedCreateReadback {
    intent: NamespaceIntent,
    report: NamespaceDestinationReport,
}
impl VerifiedCreateReadback {
    pub(crate) fn report_for(
        &self,
        intent: &NamespaceIntent,
    ) -> Result<NamespaceDestinationReport, BackendError> {
        if &self.intent != intent {
            return Err(BackendError::Unavailable);
        }
        Ok(self.report.clone())
    }
}
impl OpenCloudPlaceholderBackend {
    pub(crate) fn admit_file_create(
        self: &Arc<Self>,
        root: crate::ConfiguredRootIdentity,
        auth: CapturedAuthorization,
        job: &crate::StreamedRecoveryJob,
        current: Current,
    ) -> Result<Admission, BackendError> {
        job.check()?;
        if !current(auth) {
            return Err(BackendError::Unavailable);
        }
        let catalog = self
            .identity_catalog
            .clone()
            .ok_or(BackendError::Unavailable)?;
        let catalog_scope = self
            .catalog_scope_snapshot()?
            .ok_or(BackendError::Unavailable)?;
        let original = Arc::downgrade(self);
        let owner = current.clone();
        let job = job.with_revocation_check(Arc::new(move || {
            !owner(auth)
                || original.upgrade().is_none_or(|b| {
                    b.revoked.load(Ordering::Acquire)
                        || b.client.token_generation() != auth.token_generation
                })
        }));
        // Keep the ORIGINAL deadline/epoch; no backend lease escapes discovery.
        let parent = {
            let _lease = self
                .lease_gate
                .read()
                .map_err(|_| BackendError::Unavailable)?;
            self.capture_namespace_parent_under_lease(
                &["Personal"],
                root,
                auth,
                job.cancellation(),
            )?
        };
        if catalog_scope.local_root() != root
            || parent.path != "/"
            || parent.scope.space_id != catalog_scope.personal_space_id
            || parent.scope.root_resource_id != catalog_scope.personal_root_resource_id
        {
            return Err(BackendError::Unavailable);
        }
        let result = Admission {
            parent,
            catalog,
            catalog_scope,
            auth,
            job,
            current,
            attempted: false,
            backend: Arc::downgrade(self),
        };
        result.check(self)?;
        Ok(result)
    }
}
