//! One explicit create attempt; remote facts never authorize native completion.
use super::namespace::preparation_stage;
use super::*;
use crate::creation_preparation::{Stage as PreparationStage, Trace as PreparationTrace};
use crate::namespace_intent::{
    CapturedAuthorization, NamespaceDestinationReport, NamespaceIntent, NamespaceOperation,
};
use crate::streamed_store::namespace_file_store::VerifiedFileJoin;

#[path = "file_create_continuation.rs"]
pub(crate) mod continuation;

pub(crate) type Current = Arc<dyn Fn(CapturedAuthorization) -> bool + Send + Sync>;
pub(crate) struct Admission {
    pub(crate) parent: namespace::CapturedDirectoryParent,
    parent_components: Vec<String>,
    catalog: Arc<dyn ProviderIdentityCatalog>,
    catalog_scope: ProviderIdentityCatalogScope,
    auth: CapturedAuthorization,
    job: crate::StreamedRecoveryJob,
    current: Current,
    attempted: bool,
    backend: std::sync::Weak<OpenCloudPlaceholderBackend>,
}
impl Admission {
    /// This token describes only the exact freshly verified parent used by
    /// this admission. It is never selected from an event or caller scope.
    #[allow(dead_code)] // Scope-only callers retain the conservative health policy.
    pub(crate) fn fresh_create_space(
        &self,
        backend: &Arc<OpenCloudPlaceholderBackend>,
    ) -> Result<crate::FreshCreateSpace, BackendError> {
        self.check(backend)?;
        let space = crate::FreshCreateSpace::from_verified_scope(self.parent.scope.clone());
        self.check(backend)?;
        Ok(space)
    }
    pub(crate) fn fresh_create_space_for_child(
        &self,
        backend: &Arc<OpenCloudPlaceholderBackend>,
        name: &str,
    ) -> Result<crate::FreshCreateSpace, BackendError> {
        self.check(backend)?;
        if !valid_windows_component(name) {
            return Err(BackendError::Unavailable);
        }
        let target = crate::fresh_create_target::FreshCreateTarget::from_verified_parent(
            &self.parent.path,
            &self.parent.remote.resource_id,
            name,
            crate::fresh_create_target::FreshCreateTargetKind::File,
        )
        .ok_or(BackendError::Unavailable)?;
        let space =
            crate::FreshCreateSpace::from_verified_target(self.parent.scope.clone(), target);
        self.check(backend)?;
        Ok(space)
    }
    fn child_path(&self, leaf: &str) -> Result<String, BackendError> {
        let components: Vec<_> = self.parent_components.iter().map(String::as_str).collect();
        let relative =
            crate::personal_create_relative(&components, leaf).ok_or(BackendError::Unavailable)?;
        Ok(format!("/{relative}"))
    }
    // HTTP only in worker metadata phases, never under native/catalog publication.
    fn qualify_target(
        &self,
        backend: &Arc<OpenCloudPlaceholderBackend>,
    ) -> Result<(), BackendError> {
        self.qualify_target_with_trace(backend, None)
    }
    fn qualify_target_with_trace(
        &self,
        backend: &Arc<OpenCloudPlaceholderBackend>,
        trace: Option<&PreparationTrace>,
    ) -> Result<(), BackendError> {
        preparation_stage(trace, PreparationStage::Current);
        self.check(backend)?;
        let metadata = self.job.cancellation().bounded_request();
        namespace::qualify_create_target_with_trace(
            backend,
            &self.parent.scope,
            &self.parent_components,
            RangeReadContext {
                deadline: metadata.deadline(),
                token_generation: self.auth.token_generation,
            },
            trace,
        )
        .map_err(|error| backend.reject_cached_cloud_error(error))?;
        preparation_stage(trace, PreparationStage::Current);
        self.check(backend)
    }
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
    pub(crate) fn refresh(
        &self,
        backend: &Arc<OpenCloudPlaceholderBackend>,
        proof: VerifiedCreateReadback,
    ) -> Result<RefreshedCreateReadback, BackendError> {
        let unavailable = || BackendError::Unavailable;
        self.check(backend).map_err(|_| BackendError::Unavailable)?;
        let report = proof
            .report_for(&proof.intent)
            .map_err(|_| BackendError::Unavailable)?;
        if report.destination.parent.scope != self.parent.scope
            || report.destination.parent.authorization != self.auth
            || report.destination.parent.remote != self.parent.remote
        {
            return Err(unavailable());
        }
        let scope = &self.parent.scope;
        let path = self.child_path(&report.destination.name)?;
        // Refresh the exact historical readback tuple before entering the local
        // publication fence. This is bounded metadata observation, not remote CAS.
        let metadata = self.job.cancellation().bounded_request();
        let context = RangeReadContext {
            deadline: metadata.deadline(),
            token_generation: self.auth.token_generation,
        };
        let root =
            namespace::qualify_create_target(backend, scope, &self.parent_components, context)
                .map_err(|error| backend.reject_cached_cloud_error(error))?;
        self.check(backend).map_err(|_| BackendError::Unavailable)?;
        if !root.directory || root.encrypted || !root.writable || root.id != scope.root_resource_id
        {
            return Err(unavailable());
        }
        if self.parent.path != "/" {
            let parent = backend
                .client
                .stat_with_context(&scope.space_id, &self.parent.path, context)
                .map_err(|_| BackendError::Unavailable)?;
            self.check(backend)?;
            if parent.path != self.parent.path
                || parent.id != self.parent.remote.resource_id
                || !parent.directory
                || parent.encrypted
                || !parent.writable
                || !namespace::strong(&parent.etag)
            {
                return Err(unavailable());
            }
        }
        let observed = backend
            .client
            .stat_with_context(&scope.space_id, &path, context)
            .map_err(|_| BackendError::Unavailable)?;
        self.check(backend).map_err(|_| BackendError::Unavailable)?;
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
        self.qualify_target(backend)?;
        Ok(RefreshedCreateReadback { proof })
    }
    /// Local publication only; all HTTP finished in the consumed refresh task.
    pub(crate) fn publish_and_complete<T>(
        &self,
        backend: &Arc<OpenCloudPlaceholderBackend>,
        refreshed: &RefreshedCreateReadback,
        complete: impl FnOnce(&[u8; 16]) -> Result<T, crate::Error>,
    ) -> Result<T, crate::Error> {
        let unavailable = || crate::Error::EditRecoveryUnavailable;
        self.check(backend).map_err(|_| unavailable())?;
        let proof = &refreshed.proof;
        let report = proof.report_for(&proof.intent).map_err(|_| unavailable())?;
        if report.destination.parent.scope != self.parent.scope
            || report.destination.parent.authorization != self.auth
            || report.destination.parent.remote != self.parent.remote
        {
            return Err(unavailable());
        }
        let scope = &self.parent.scope;
        let path = self
            .child_path(&report.destination.name)
            .map_err(|_| unavailable())?;
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
        let composite = composite_root_identity(
            &backend.scope,
            self.catalog_scope.personal_space_id(),
            self.catalog_scope.personal_root_resource_id(),
        );
        let root_current = matches!(state.namespace_directories.get(&composite),
            Some(NamespaceDirectory::Root { account_id, personal_space_id, personal_root_id })
                if account_id == backend.scope.account_id()
                && personal_space_id == self.catalog_scope.personal_space_id() && personal_root_id == self.catalog_scope.personal_root_resource_id());
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
        self.qualify_target(backend)?;
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
            || destination.parent.local_components != self.parent_components
            || destination.parent.remote != self.parent.remote
            || joined.manifest().binding().remote.is_some()
            || joined.manifest().binding().generation != intent.record_generation
            || joined.manifest().binding().local_file != destination.local_file
            || joined.manifest().binding().content_len != content.byte_len
            || joined.manifest().binding().relative_path
                != self.child_path(&destination.name)?.trim_start_matches('/')
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
                        || !b
                            .client
                            .provider_generation_is_current(auth.token_generation)
                })
        });
        let reader = joined
            .into_reader(cancelled.clone())
            .map_err(|_| BackendError::Unavailable)?;
        // No backend lease, account guard or parent callback spans SDK recursion.
        before_sdk()?;
        let path = self.child_path(&destination.name)?;
        let relative = path.trim_start_matches('/');
        let context = RangeReadContext {
            deadline: self.job.deadline(),
            token_generation: self.auth.token_generation,
        };
        let proof = if self.parent.path == "/" {
            // Preserve the established explicit root wrapper's SDK behavior.
            backend
                .client
                .recovery_create_blocking_reader_cancellable_with_context(
                    &self.parent.scope.space_id,
                    "/",
                    &self.parent.scope.root_resource_id,
                    relative,
                    reader,
                    content.byte_len,
                    digest,
                    context,
                    cancelled,
                )
        } else {
            let parent = raiun_opencloud::RecoveryCreateParent {
                path: &self.parent.path,
                resource_id: &self.parent.remote.resource_id,
                etag: &self.parent.remote.etag,
            };
            backend
                .client
                .recovery_create_blocking_reader_with_parent_cancellable_with_context(
                    &self.parent.scope.space_id,
                    "/",
                    &self.parent.scope.root_resource_id,
                    relative,
                    &parent,
                    reader,
                    content.byte_len,
                    digest,
                    context,
                    cancelled,
                )
        }
        .map_err(|_| BackendError::Unavailable)?;
        self.qualify_target(backend)?;
        let observed = proof.observed;
        if observed.entry.path != path
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
/// Move-only evidence that exact original metadata was refreshed off-owner.
pub(crate) struct RefreshedCreateReadback {
    proof: VerifiedCreateReadback,
}
impl RefreshedCreateReadback {
    pub(crate) fn report_for(
        &self,
        intent: &NamespaceIntent,
    ) -> Result<NamespaceDestinationReport, BackendError> {
        self.proof.report_for(intent)
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
        components: &[&str],
        root: crate::ConfiguredRootIdentity,
        auth: CapturedAuthorization,
        job: &crate::StreamedRecoveryJob,
        current: Current,
    ) -> Result<Admission, BackendError> {
        self.admit_file_create_with_trace(components, root, auth, job, current, None)
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit_file_create_traced(
        self: &Arc<Self>,
        components: &[&str],
        root: crate::ConfiguredRootIdentity,
        auth: CapturedAuthorization,
        job: &crate::StreamedRecoveryJob,
        current: Current,
        trace: &PreparationTrace,
    ) -> Result<Admission, BackendError> {
        self.admit_file_create_with_trace(components, root, auth, job, current, Some(trace))
    }
    #[allow(clippy::too_many_arguments)]
    fn admit_file_create_with_trace(
        self: &Arc<Self>,
        components: &[&str],
        root: crate::ConfiguredRootIdentity,
        auth: CapturedAuthorization,
        job: &crate::StreamedRecoveryJob,
        current: Current,
        trace: Option<&PreparationTrace>,
    ) -> Result<Admission, BackendError> {
        preparation_stage(trace, PreparationStage::Job);
        job.check()?;
        preparation_stage(trace, PreparationStage::Current);
        if !current(auth) {
            return Err(BackendError::Unavailable);
        }
        preparation_stage(trace, PreparationStage::ParentRoute);
        if crate::personal_create_relative(components, "probe").is_none() {
            return Err(BackendError::Unavailable);
        }
        preparation_stage(trace, PreparationStage::Catalog);
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
                        || !b
                            .client
                            .provider_generation_is_current(auth.token_generation)
                })
        }));
        // Bound this complete metadata phase while keeping the ORIGINAL job
        // deadline/epoch for admission/body. No backend lease escapes discovery.
        let metadata = job.cancellation().bounded_request();
        preparation_stage(trace, PreparationStage::ParentRoute);
        let parent = {
            let _lease = self
                .lease_gate
                .read()
                .map_err(|_| BackendError::Unavailable)?;
            match trace {
                Some(trace) => self.capture_namespace_parent_under_lease_traced(
                    components, root, auth, &metadata, trace,
                ),
                None => {
                    self.capture_namespace_parent_under_lease(components, root, auth, &metadata)
                }
            }?
        };
        let prefix = if components.first().copied() == Some("Personal") {
            1
        } else {
            2
        };
        preparation_stage(trace, PreparationStage::Catalog);
        if catalog_scope.local_root() != root {
            return Err(BackendError::Unavailable);
        }
        preparation_stage(trace, PreparationStage::ParentRoute);
        if parent.path != format!("/{}", components[prefix..].join("/")) {
            return Err(BackendError::Unavailable);
        }
        let result = Admission {
            parent,
            parent_components: components.iter().map(|part| (*part).to_owned()).collect(),
            catalog,
            catalog_scope,
            auth,
            job,
            current,
            attempted: false,
            backend: Arc::downgrade(self),
        };
        result.qualify_target_with_trace(self, trace)?;
        Ok(result)
    }
}
