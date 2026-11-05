//! Directory-only live route. Bare201 plus observed path IDs is deliberately
//! not represented as an atomic created-ID or arbitrary-parent-CAS receipt.
use super::*;
use crate::RemoteEditBaseline;
use crate::namespace_intent::{
    CapturedAuthorization, NamespaceDestinationReport, NamespaceIntent, NamespaceOperation,
};
use crate::namespace_reconcile::{
    DirectoryCompletionError, DirectoryCreateDispatch, DirectoryCreateReadback,
    DirectoryCreateRemote,
};
use raiun_core::backend::{CloudError, RemoteEntry};
use raiun_opencloud::DirectoryCreateResponse;
use std::{
    cell::{Cell, RefCell},
    time::{Duration, Instant},
};

/// Shared create metadata qualification, outside publication/catalog locks.
/// Personal identifies the account; the captured target Space is independent.
pub(super) fn qualify_create_target(
    backend: &OpenCloudPlaceholderBackend,
    scope: &crate::EditJournalScope,
    components: &[String],
    context: RangeReadContext,
) -> Result<RemoteEntry, CloudError> {
    backend
        .ensure_active()
        .map_err(|_| refusal(ErrorKind::Unauthorized))?;
    let refs = components.iter().map(String::as_str).collect::<Vec<_>>();
    if crate::personal_create_relative(&refs, "probe").is_none()
        || context.token_generation != backend.token_generation
    {
        return Err(refusal(ErrorKind::Conflict));
    }
    let catalog = backend
        .catalog_scope_snapshot()
        .map_err(|_| refusal(ErrorKind::Conflict))?
        .ok_or_else(|| refusal(ErrorKind::Conflict))?;
    if catalog.local_root().volume_serial != scope.root_volume_serial
        || catalog.local_root().file_index != scope.root_file_index
        || catalog.profile_id != scope.profile_id
        || catalog.account_id != scope.account_subject
        || catalog.server_origin != scope.server_origin
    {
        return Err(refusal(ErrorKind::Conflict));
    }
    let spaces = backend
        .validate_namespace_scope(
            backend.scope.account_id(),
            catalog.personal_space_id(),
            catalog.personal_root_resource_id(),
            context.deadline,
        )
        .map_err(|_| refusal(ErrorKind::Conflict))?;
    let mut targets = spaces.iter().filter(|space| space.id == scope.space_id);
    let target = targets.next().ok_or_else(|| refusal(ErrorKind::Conflict))?;
    if targets.next().is_some()
        || !target.writable
        || target.encrypted
        || match components.first().map(String::as_str) {
            Some("Personal") => !target.personal || target.id != catalog.personal_space_id,
            Some("Spaces") => target.personal || target.id == catalog.personal_space_id,
            _ => true,
        }
    {
        return Err(refusal(ErrorKind::Conflict));
    }
    let root = backend
        .client
        .stat_discovered_space_root_with_context(target, context)?;
    if !root.directory
        || root.encrypted
        || !root.writable
        || root.id != scope.root_resource_id
        || !valid_remote_path(&scope.space_id, &scope.root_resource_id, &root.path, true)
    {
        return Err(refusal(ErrorKind::Conflict));
    }
    backend
        .ensure_active()
        .map_err(|_| refusal(ErrorKind::Unauthorized))?;
    Ok(root)
}

impl OpenCloudPlaceholderBackend {
    /// Retain the backend lease through the entire closure. The owner guard must
    /// freshly compare the supplied captured agent generation on every call.
    /// Parent identity comes from current pinned provider metadata, never names.
    pub fn with_directory_create_session<T>(
        &self,
        intent: &NamespaceIntent,
        parent_identity: OpaqueIdentity,
        owner_current: &dyn Fn(CapturedAuthorization) -> bool,
        run: impl FnOnce(&dyn DirectoryCreateRemote) -> T,
    ) -> Result<T, BackendError> {
        self.with_directory_publication_session(intent, parent_identity, owner_current, |session| {
            run(session.remote())
        })
    }

    /// One lease spans dispatch, readback and native publication. A nested
    /// backend read acquisition would deadlock behind a waiting revoke writer.
    pub fn with_directory_publication_session<T>(
        &self,
        intent: &NamespaceIntent,
        parent_identity: OpaqueIdentity,
        owner_current: &dyn Fn(CapturedAuthorization) -> bool,
        run: impl FnOnce(&DirectoryCreateSession<'_>) -> T,
    ) -> Result<T, BackendError> {
        intent.validate().map_err(|_| BackendError::Unavailable)?;
        let NamespaceOperation::CreateDirectory { destination } = &intent.operation else {
            return Err(BackendError::Unavailable);
        };
        let scope = &destination.parent.scope;
        // The owner carries the ORIGINAL connection cancellation epoch. Refuse
        // before waiting behind a revoke writer, then check again under lease.
        if !owner_current(destination.parent.authorization) {
            return Err(BackendError::Unavailable);
        }
        let _lease = self
            .lease_gate
            .read()
            .map_err(|_| BackendError::Unavailable)?;
        self.ensure_active()?;
        let catalog = self
            .catalog_scope_snapshot()?
            .ok_or(BackendError::Unavailable)?;
        if scope.profile_id != self.scope.profile_id()
            || scope.account_subject != self.scope.account_id()
            || scope.server_origin != self.scope.server_origin()
            || scope.root_volume_serial != catalog.local_root().volume_serial
            || scope.root_file_index != catalog.local_root().file_index
            || destination.parent.authorization.token_generation != self.token_generation
            || !owner_current(destination.parent.authorization)
        {
            return Err(BackendError::Unavailable);
        }
        let parent = self
            .state
            .lock()
            .map_err(|_| BackendError::Unavailable)?
            .directories
            .get(&parent_identity)
            .cloned()
            .ok_or(BackendError::NotFound)?;
        if parent.space_id != scope.space_id
            || parent.root_resource_id != scope.root_resource_id
            || parent.remote_id != destination.parent.remote.resource_id
        {
            return Err(BackendError::Unavailable);
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        let context = RangeReadContext {
            deadline,
            token_generation: self.token_generation,
        };
        let root =
            qualify_create_target(self, scope, &destination.parent.local_components, context)
                .map_err(|error| self.reject_cached_cloud_error(error))?;
        let path = format!("{}/{}", parent.path.trim_end_matches('/'), destination.name);
        if !valid_remote_path(&scope.space_id, &scope.root_resource_id, &path, false) {
            return Err(BackendError::Unavailable);
        }
        let transfer_cancellation = self.client.transfer_budget().cancellation();
        let remote = LiveDirectoryCreate {
            backend: self,
            intent: intent.clone(),
            parent,
            path,
            root_path: root.path,
            context,
            owner_current,
            attempted: Cell::new(false),
            created: Cell::new(false),
            observed: RefCell::new(None),
            cancelled: Arc::new(move || transfer_cancellation.is_cancelled()),
        };
        remote
            .ensure_authorized(intent)
            .map_err(|_| BackendError::Unavailable)?;
        Ok(run(&DirectoryCreateSession { remote }))
    }
}
struct LiveDirectoryCreate<'a> {
    backend: &'a OpenCloudPlaceholderBackend,
    intent: NamespaceIntent,
    parent: DirectoryBinding,
    path: String,
    root_path: String,
    context: RangeReadContext,
    owner_current: &'a dyn Fn(CapturedAuthorization) -> bool,
    attempted: Cell<bool>,
    created: Cell<bool>,
    observed: RefCell<Option<NamespaceDestinationReport>>,
    cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
}
fn refusal(kind: ErrorKind) -> CloudError {
    CloudError::new(kind, "directory create evidence unavailable")
}
pub(super) fn strong(etag: &str) -> bool {
    etag.len() >= 2
        && etag.len() <= 4096
        && etag.starts_with('"')
        && etag.ends_with('"')
        && !etag[1..etag.len() - 1]
            .bytes()
            .any(|b| b < 0x21 || b == b'"' || b == 0x7f)
}
impl LiveDirectoryCreate<'_> {
    fn destination(&self) -> &crate::namespace_intent::LocalNamespaceEntry {
        match &self.intent.operation {
            NamespaceOperation::CreateDirectory { destination } => destination,
            _ => unreachable!("constructor admits directory only"),
        }
    }
    fn relative_path(&self) -> Result<&str, CloudError> {
        let root = self.root_path.trim_end_matches('/');
        let relative = self
            .path
            .strip_prefix(root)
            .filter(|s| s.starts_with('/'))
            .ok_or_else(|| refusal(ErrorKind::Conflict))?;
        Ok(relative.trim_start_matches('/'))
    }
    fn check_parent(&self, captured_etag: bool) -> Result<(), CloudError> {
        let scope = &self.destination().parent.scope;
        let root = qualify_create_target(
            self.backend,
            scope,
            &self.destination().parent.local_components,
            self.context,
        )?;
        if root.path.trim_end_matches('/') != self.root_path.trim_end_matches('/') {
            return Err(refusal(ErrorKind::Conflict));
        }
        let parent = self.backend.client.stat_with_context(
            &scope.space_id,
            &self.parent.path,
            self.context,
        )?;
        if !parent.directory
            || parent.encrypted
            || !parent.writable
            || parent.id != self.parent.remote_id
            || !strong(&parent.etag)
            || (captured_etag && parent.etag != self.destination().parent.remote.etag)
        {
            return Err(refusal(ErrorKind::Conflict));
        }
        Ok(())
    }
    fn child(&self) -> Result<RemoteEntry, CloudError> {
        let scope = &self.destination().parent.scope;
        let entry = self.backend.client.recovery_stat_with_context(
            &scope.space_id,
            &self.root_path,
            &scope.root_resource_id,
            self.relative_path()?,
            self.context,
        )?;
        if entry.path.trim_end_matches('/') != self.path
            || !entry.directory
            || entry.encrypted
            || !entry.writable
            || !valid_remote_id(&entry.id)
            || !strong(&entry.etag)
            || entry.id == self.parent.remote_id
            || entry.id == scope.root_resource_id
        {
            return Err(refusal(ErrorKind::Conflict));
        }
        Ok(entry)
    }
}
impl DirectoryCreateRemote for LiveDirectoryCreate<'_> {
    fn ensure_authorized(&self, intent: &NamespaceIntent) -> Result<(), CloudError> {
        self.backend
            .ensure_active()
            .map_err(|_| refusal(ErrorKind::Unauthorized))?;
        let parent = &self.destination().parent;
        if intent != &self.intent
            || self.context.deadline <= Instant::now()
            || parent.authorization.token_generation != self.backend.token_generation
            || !(self.owner_current)(parent.authorization)
            || (self.cancelled)()
        {
            return Err(refusal(ErrorKind::Unauthorized));
        }
        self.backend
            .ensure_ordinary_location(&parent.scope.space_id, &self.path)
            .map_err(|_| refusal(ErrorKind::Forbidden))?;
        // This also compares the client's current bearer generation, without
        // any HTTP or credential exposure. The lease is only held for the check.
        self.backend
            .client
            .with_provider_generation(self.context.token_generation, || ())?;
        Ok(())
    }
    fn preflight(&self, intent: &NamespaceIntent) -> Result<(), CloudError> {
        self.ensure_authorized(intent)?;
        self.check_parent(true)?;
        let scope = &self.destination().parent.scope;
        match self.backend.client.recovery_stat_with_context(
            &scope.space_id,
            &self.root_path,
            &scope.root_resource_id,
            self.relative_path()?,
            self.context,
        ) {
            Err(error) if error.kind == ErrorKind::NotFound => (),
            Err(error) => return Err(error),
            Ok(_) => return Err(refusal(ErrorKind::Conflict)),
        }
        self.ensure_authorized(intent)
    }
    fn create(
        &self,
        dispatch: &DirectoryCreateDispatch<'_>,
    ) -> Result<DirectoryCreateResponse, CloudError> {
        let intent = dispatch.intent();
        // All checks here precede the helper's at-most-one send. Repeating the
        // preflight narrows, but never claims to eliminate, the parent race.
        if self.attempted.get() {
            return Err(refusal(ErrorKind::Conflict));
        }
        self.preflight(intent)?;
        self.attempted.set(true);
        let scope = &self.destination().parent.scope;
        let response = self.backend.client.mkdir_with_context_and_cancellation(
            &scope.space_id,
            &self.root_path,
            &scope.root_resource_id,
            self.relative_path()?,
            self.context,
            || {
                // Final SDK admission after its own metadata work. Only the
                // ORIGINAL atomic owner/job/backend/token observations; no
                // HTTP, state/catalog/route lock, journal or new epoch here.
                self.context.deadline <= Instant::now()
                    || !(self.owner_current)(self.destination().parent.authorization)
                    || (self.cancelled)()
                    || self.backend.revoked.load(Ordering::Acquire)
                    || self.backend.token_generation != self.context.token_generation
                    || self.destination().parent.authorization.token_generation
                        != self.context.token_generation
                    || !self
                        .backend
                        .client
                        .provider_generation_is_current(self.context.token_generation)
            },
        )?;
        if let Err(error) = self.ensure_authorized(intent) {
            return Ok(DirectoryCreateResponse::Uncertain(error));
        }
        self.created
            .set(matches!(response, DirectoryCreateResponse::Created));
        Ok(response)
    }
    fn observe(&self, intent: &NamespaceIntent) -> Result<NamespaceDestinationReport, CloudError> {
        self.ensure_authorized(intent)?;
        self.check_parent(false)?;
        let before = self.child()?;
        self.check_parent(false)?;
        let after = self.child()?;
        if before.id != after.id || before.etag != after.etag {
            return Err(refusal(ErrorKind::Conflict));
        }
        self.check_parent(false)?;
        self.ensure_authorized(intent)?;
        let report = NamespaceDestinationReport {
            destination: self.destination().clone(),
            remote: RemoteEditBaseline {
                resource_id: after.id,
                etag: after.etag,
                byte_len: 0,
            },
            content: None,
        };
        self.observed.replace(Some(report.clone()));
        Ok(report)
    }
}

#[cfg(test)]
#[path = "namespace_tests.rs"]
mod tests;

/// The enclosing closure owns exactly one backend lease for this entire
/// nonserializable session. Remote-only compatibility uses the same object.
pub struct DirectoryCreateSession<'backend> {
    remote: LiveDirectoryCreate<'backend>,
}
/// Fresh qualified path readback + catalog publication, never reconstructed
/// from a stored RemoteVerified/LocalCompleted report.
pub struct VerifiedDirectoryPublication<'session, 'backend> {
    session: &'session DirectoryCreateSession<'backend>,
    readback: &'session DirectoryCreateReadback,
    identity: OpaqueIdentity,
}
impl<'backend> DirectoryCreateSession<'backend> {
    pub fn remote(&self) -> &dyn DirectoryCreateRemote {
        &self.remote
    }
    pub fn intent(&self) -> &NamespaceIntent {
        &self.remote.intent
    }
    pub(crate) fn backend(&self) -> &OpenCloudPlaceholderBackend {
        self.remote.backend
    }
    fn fresh_readback(&self, readback: &DirectoryCreateReadback) -> Result<(), BackendError> {
        if !self.remote.created.get()
            || self.remote.observed.borrow().as_ref() != Some(readback.report())
        {
            return Err(BackendError::Unavailable);
        }
        let latest = self
            .remote
            .observe(&self.remote.intent)
            .map_err(|_| BackendError::Unavailable)?;
        if &latest != readback.report() {
            return Err(BackendError::Unavailable);
        }
        Ok(())
    }
    /// Admission linearizes before invoking the durable append. An already
    /// admitted append may finish FS sync; a postcheck error preserves any
    /// written factual report, rather than pretending it was never written.
    pub(crate) fn record_directory_completion<F>(
        &self,
        readback: &DirectoryCreateReadback,
        identity: &[u8; 16],
        record: F,
    ) -> Result<(), DirectoryCompletionError>
    where
        F: FnOnce() -> Result<(), DirectoryCompletionError>,
    {
        self.fresh_readback(readback)
            .map_err(|_| DirectoryCompletionError::Unavailable)?;
        let remaining = self
            .remote
            .context
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or(DirectoryCompletionError::Unavailable)?;
        let cancellation = CancellationToken::with_timeout(remaining);
        let _permit = self
            .backend()
            .begin_scoped_publish(&cancellation)
            .map_err(|_| DirectoryCompletionError::Unavailable)?;
        let current = || {
            self.remote.context.deadline > Instant::now()
                && (self.remote.owner_current)(self.remote.destination().parent.authorization)
                && !(self.remote.cancelled)()
                && self.backend().ensure_active().is_ok()
        };
        if !current() {
            return Err(DirectoryCompletionError::Unavailable);
        }
        let state = self
            .backend()
            .state
            .try_lock()
            .map_err(|_| DirectoryCompletionError::Unavailable)?;
        let expected = self.remote.destination();
        let binding = state
            .directories
            .get(&OpaqueIdentity(*identity))
            .ok_or(DirectoryCompletionError::Unavailable)?;
        if binding.space_id != expected.parent.scope.space_id
            || binding.root_resource_id != expected.parent.scope.root_resource_id
            || binding.path != self.remote.path
            || binding.remote_id != readback.report().remote.resource_id
        {
            return Err(DirectoryCompletionError::Unavailable);
        }
        record()?;
        if !current() {
            return Err(DirectoryCompletionError::Uncertain);
        }
        Ok(())
    }
    pub fn prepare_verified_directory<'session>(
        &'session self,
        readback: &'session DirectoryCreateReadback,
    ) -> Result<VerifiedDirectoryPublication<'session, 'backend>, BackendError> {
        self.fresh_readback(readback)?;
        let scope = &self.remote.destination().parent.scope;
        let identity = self.remote.backend.register_observed_directory_in_session(
            scope,
            &self.remote.path,
            &readback.report().remote,
            self.remote.context,
        )?;
        self.fresh_readback(readback)?;
        Ok(VerifiedDirectoryPublication {
            session: self,
            readback,
            identity,
        })
    }
}
impl VerifiedDirectoryPublication<'_, '_> {
    pub fn identity(&self) -> &[u8; 16] {
        self.identity.as_bytes()
    }
    pub fn intent(&self) -> &NamespaceIntent {
        self.session.intent()
    }
    pub(crate) fn backend(&self) -> &OpenCloudPlaceholderBackend {
        self.session.backend()
    }
    fn atomic_current(&self) -> Result<(), crate::Error> {
        let remote = &self.session.remote;
        if remote.context.deadline <= Instant::now()
            || !(remote.owner_current)(remote.destination().parent.authorization)
            || (remote.cancelled)()
            || remote.backend.ensure_active().is_err()
        {
            return Err(crate::Error::EditRecoveryUnavailable);
        }
        Ok(())
    }
    /// No recursive backend read or token lock: fresh HTTP runs outside the
    /// local publication fence, while the SAME outer backend lease stays held.
    pub fn publish_and_complete<T>(
        &self,
        complete: impl FnOnce() -> Result<T, crate::Error>,
    ) -> Result<T, crate::Error> {
        let unavailable = || crate::Error::EditRecoveryUnavailable;
        self.session
            .fresh_readback(self.readback)
            .map_err(|_| unavailable())?;
        let remaining = self
            .session
            .remote
            .context
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(unavailable)?;
        let cancellation = CancellationToken::with_timeout(remaining);
        let permit = self
            .backend()
            .begin_scoped_publish(&cancellation)
            .map_err(|_| unavailable())?;
        self.atomic_current()?;
        let result = complete()?;
        self.atomic_current()?;
        drop(permit);
        self.session
            .fresh_readback(self.readback)
            .map_err(|_| unavailable())?;
        self.atomic_current()?;
        Ok(result)
    }
}

/// Borrowed live parent context for LOCAL capture only. No public constructor,
/// Clone or serialization; the lease/context cannot escape the callback.
#[cfg(any(windows, test))]
pub struct PlainFileCaptureParent<'lease> {
    backend: &'lease OpenCloudPlaceholderBackend,
    captured: CapturedDirectoryParent,
    components: Vec<String>,
    authorization: CapturedAuthorization,
    job: &'lease crate::StreamedRecoveryJob,
    owner_current: &'lease dyn Fn(CapturedAuthorization) -> bool,
}
#[cfg(any(windows, test))]
impl PlainFileCaptureParent<'_> {
    pub(crate) fn check_current(&self) -> Result<(), BackendError> {
        self.job.check()?;
        if !(self.owner_current)(self.authorization) {
            return Err(BackendError::Unavailable);
        }
        self.backend.ensure_active()
    }
    #[cfg(windows)]
    pub(crate) fn backend(&self) -> &OpenCloudPlaceholderBackend {
        self.backend
    }
    #[cfg(windows)]
    pub(crate) fn captured(&self) -> &CapturedDirectoryParent {
        &self.captured
    }
    #[cfg(windows)]
    pub(crate) fn components(&self) -> &[String] {
        &self.components
    }
    #[cfg(windows)]
    pub(crate) fn authorization(&self) -> CapturedAuthorization {
        self.authorization
    }
}
#[cfg(any(windows, test))]
impl OpenCloudPlaceholderBackend {
    /// HTTP discovery happens here, BEFORE the native-only callback. One lease
    /// spans discovery/callback; neither callback nor its native code may acquire
    /// another backend read or AccountState guard. Only local evidence returns.
    pub fn with_plain_file_capture_parent<T>(
        &self,
        root: crate::ConfiguredRootIdentity,
        components: &[&str],
        authorization: CapturedAuthorization,
        job: &crate::StreamedRecoveryJob,
        owner_current: &dyn Fn(CapturedAuthorization) -> bool,
        run: impl FnOnce(&PlainFileCaptureParent<'_>) -> T,
    ) -> Result<T, BackendError> {
        job.check()?;
        if !owner_current(authorization) {
            return Err(BackendError::Unavailable);
        }
        let original = job.clone();
        let metadata = CancellationToken::for_recovery_job_with_deadline(
            crate::StreamedRecoveryPolicy::default(),
            Some(job.deadline().min(Instant::now() + Duration::from_secs(30))),
        )
        .with_revocation_check(Arc::new(move || original.is_stopped()));
        let _lease = self
            .lease_gate
            .read()
            .map_err(|_| BackendError::Unavailable)?;
        if metadata.is_stopped() || !owner_current(authorization) {
            return Err(BackendError::Unavailable);
        }
        let captured = self.capture_namespace_parent_under_lease(
            components,
            root,
            authorization,
            metadata.cancellation(),
        )?;
        let parent = PlainFileCaptureParent {
            backend: self,
            captured,
            components: components.iter().map(|s| (*s).to_owned()).collect(),
            authorization,
            job,
            owner_current,
        };
        parent.check_current()?;
        let result = run(&parent);
        parent.check_current()?;
        Ok(result)
    }
}

#[cfg(any(windows, test))]
pub(crate) struct CapturedDirectoryParent {
    pub(crate) route: Vec<crate::PlaceholderChild>,
    pub(crate) identity: OpaqueIdentity,
    pub(crate) scope: crate::EditJournalScope,
    pub(crate) remote: RemoteEditBaseline,
    pub(crate) path: String,
}
impl OpenCloudPlaceholderBackend {
    /// Resolve hints only through a freshly authenticated managed namespace.
    /// Each expected opaque directory identity is later checked on native pins.
    #[cfg(windows)]
    pub(crate) fn capture_namespace_parent(
        &self,
        components: &[&str],
        root: crate::ConfiguredRootIdentity,
        authorization: CapturedAuthorization,
    ) -> Result<CapturedDirectoryParent, BackendError> {
        let _lease = self
            .lease_gate
            .read()
            .map_err(|_| BackendError::Unavailable)?;
        let cancellation = CancellationToken::with_timeout(Duration::from_secs(30));
        self.capture_namespace_parent_under_lease(components, root, authorization, &cancellation)
    }
    #[cfg(any(windows, test))]
    pub(super) fn capture_namespace_parent_under_lease(
        &self,
        components: &[&str],
        root: crate::ConfiguredRootIdentity,
        authorization: CapturedAuthorization,
        cancellation: &CancellationToken,
    ) -> Result<CapturedDirectoryParent, BackendError> {
        // The cached vault delete callback has its own exact encrypted route.
        // An ordinary namespace parent must never be promoted from a cached
        // catalogue into a live Personal/Spaces mutation authority.
        if self.is_cached_only() {
            return Err(BackendError::Unavailable);
        }
        self.ensure_active()?;
        if components.is_empty()
            || components.len() > 256
            || authorization.agent_generation == 0
            || authorization.token_generation != self.token_generation
        {
            return Err(BackendError::Unavailable);
        }
        let catalog = self
            .catalog_scope_snapshot()?
            .ok_or(BackendError::Unavailable)?;
        if catalog.local_root() != root {
            return Err(BackendError::Unavailable);
        }
        let mut identity = {
            let state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
            let mut roots = state.namespace_directories.iter().filter_map(|(id, kind)|
                matches!(kind, NamespaceDirectory::Root { account_id, .. } if account_id == self.scope.account_id()).then_some(*id));
            let selected = roots.next().ok_or(BackendError::Unavailable)?;
            if roots.next().is_some() {
                return Err(BackendError::Unavailable);
            }
            selected
        };
        let mut route = Vec::with_capacity(components.len());
        for component in components {
            if cancellation.is_cancelled() || cancellation.is_expired() {
                return Err(BackendError::Unavailable);
            }
            let children = self.enumerate_scoped(identity.as_bytes(), cancellation)?;
            let child = children
                .into_iter()
                .find(|child| child.name == *component && child.metadata.is_directory)
                .ok_or(BackendError::NotFound)?;
            identity = OpaqueIdentity(
                child
                    .identity
                    .as_slice()
                    .try_into()
                    .map_err(|_| BackendError::Unavailable)?,
            );
            route.push(child);
        }
        let parent = self
            .state
            .lock()
            .map_err(|_| BackendError::Unavailable)?
            .directories
            .get(&identity)
            .cloned()
            .ok_or(BackendError::Unavailable)?;
        self.ensure_ordinary_location(&parent.space_id, &parent.path)?;
        let context = RangeReadContext {
            deadline: cancellation.deadline(),
            token_generation: self.token_generation,
        };
        let root_entry = self
            .client
            .stat_with_context(&parent.space_id, "/", context)
            .map_err(|_| BackendError::Unavailable)?;
        let entry = self
            .client
            .stat_with_context(&parent.space_id, &parent.path, context)
            .map_err(|_| BackendError::Unavailable)?;
        if root_entry.id != parent.root_resource_id
            || root_entry.encrypted
            || !root_entry.writable
            || !root_entry.directory
            || entry.id != parent.remote_id
            || entry.encrypted
            || !entry.directory
            || !entry.writable
            || !strong(&entry.etag)
        {
            return Err(BackendError::Unavailable);
        }
        self.ensure_active()?;
        Ok(CapturedDirectoryParent {
            path: parent.path,
            route,
            identity,
            scope: crate::EditJournalScope {
                profile_id: self.scope.profile_id().into(),
                account_subject: self.scope.account_id().into(),
                server_origin: self.scope.server_origin().into(),
                space_id: parent.space_id,
                root_resource_id: parent.root_resource_id,
                root_volume_serial: root.volume_serial,
                root_file_index: root.file_index,
            },
            remote: RemoteEditBaseline {
                resource_id: entry.id,
                etag: entry.etag,
                byte_len: 0,
            },
        })
    }
}

/// Owned SDK-only directory context. No native pin, journal or backend lease.
#[cfg(windows)]
pub(crate) struct OwnedDirectorySession {
    pub(crate) captured: CapturedDirectoryParent,
    backend: Arc<OpenCloudPlaceholderBackend>,
    catalog: Arc<dyn ProviderIdentityCatalog>,
    catalog_scope: ProviderIdentityCatalogScope,
    auth: CapturedAuthorization,
    job: crate::StreamedRecoveryJob,
    current: Arc<dyn Fn(CapturedAuthorization) -> bool + Send + Sync>,
}
#[cfg(windows)]
pub(crate) enum OwnedDirectorySend {
    Verified(Box<NamespaceDestinationReport>),
    Rejected(CloudError),
    Uncertain,
}
#[cfg(windows)]
pub(crate) struct RefreshedDirectory {
    report: Box<NamespaceDestinationReport>,
}
#[cfg(windows)]
impl OwnedDirectorySession {
    /// Mint only from this original SDK-verified parent, which is retained
    /// through directory send/publication. The token grants no native custody.
    pub(crate) fn fresh_create_space(&self) -> Result<crate::FreshCreateSpace, BackendError> {
        self.check()?;
        let space = crate::FreshCreateSpace::from_verified_scope(self.captured.scope.clone());
        self.check()?;
        Ok(space)
    }
    pub(crate) fn prepare(
        backend: Arc<OpenCloudPlaceholderBackend>,
        components: &[&str],
        root: crate::ConfiguredRootIdentity,
        auth: CapturedAuthorization,
        job: crate::StreamedRecoveryJob,
        current: Arc<dyn Fn(CapturedAuthorization) -> bool + Send + Sync>,
    ) -> Result<Self, BackendError> {
        job.check()?;
        if crate::personal_create_relative(components, "probe").is_none() || !(current)(auth) {
            return Err(BackendError::Unavailable);
        }
        let catalog = backend
            .identity_catalog
            .clone()
            .ok_or(BackendError::Unavailable)?;
        let catalog_scope = backend
            .catalog_scope_snapshot()?
            .ok_or(BackendError::Unavailable)?;
        if catalog_scope.local_root() != root {
            return Err(BackendError::Unavailable);
        }
        // Original deadline; no new cancellation epoch. No outer read lease spans
        // metadata: discovery itself takes only short state locks and checks the
        // original token/context; all observations are revalidated by the owner.
        backend.validate_namespace_scope(
            backend.scope.account_id(),
            catalog_scope.personal_space_id(),
            catalog_scope.personal_root_resource_id(),
            job.deadline(),
        )?;
        let captured = backend.capture_namespace_parent_under_lease(
            components,
            root,
            auth,
            job.cancellation(),
        )?;
        let result = Self {
            captured,
            backend,
            catalog,
            catalog_scope,
            auth,
            job,
            current,
        };
        result.check()?;
        let metadata = result.job.cancellation().bounded_request();
        qualify_create_target(
            &result.backend,
            &result.captured.scope,
            &components
                .iter()
                .map(|part| (*part).to_owned())
                .collect::<Vec<_>>(),
            RangeReadContext {
                deadline: metadata.deadline(),
                token_generation: auth.token_generation,
            },
        )
        .map_err(|_| BackendError::Unavailable)?;
        result.check()?;
        Ok(result)
    }
    pub(crate) fn check(&self) -> Result<(), BackendError> {
        self.job.check()?;
        if !(self.current)(self.auth)
            || self.auth.token_generation != self.backend.token_generation
            || self
                .backend
                .identity_catalog
                .as_ref()
                .is_none_or(|c| !Arc::ptr_eq(c, &self.catalog))
            || !self
                .backend
                .client
                .provider_generation_is_current(self.auth.token_generation)
        {
            return Err(BackendError::Unavailable);
        }
        self.backend.ensure_active()
    }
    pub(crate) fn original_backend(&self, backend: &Arc<OpenCloudPlaceholderBackend>) -> bool {
        Arc::ptr_eq(&self.backend, backend)
    }
    fn live<'a>(&'a self, intent: &NamespaceIntent) -> Result<LiveDirectoryCreate<'a>, CloudError> {
        self.check().map_err(|_| refusal(ErrorKind::Unauthorized))?;
        let NamespaceOperation::CreateDirectory { destination } = &intent.operation else {
            return Err(refusal(ErrorKind::Conflict));
        };
        if destination.parent.scope != self.captured.scope
            || destination.parent.authorization != self.auth
            || destination.parent.remote != self.captured.remote
        {
            return Err(refusal(ErrorKind::Conflict));
        }
        let path = format!(
            "{}/{}",
            self.captured.path.trim_end_matches('/'),
            destination.name
        );
        if !valid_remote_path(
            &self.captured.scope.space_id,
            &self.captured.scope.root_resource_id,
            &path,
            false,
        ) {
            return Err(refusal(ErrorKind::Conflict));
        }
        let job = self.job.clone();
        Ok(LiveDirectoryCreate {
            backend: &self.backend,
            intent: intent.clone(),
            parent: DirectoryBinding {
                space_id: self.captured.scope.space_id.clone(),
                root_resource_id: self.captured.scope.root_resource_id.clone(),
                path: self.captured.path.clone(),
                remote_id: self.captured.remote.resource_id.clone(),
            },
            path,
            root_path: "/".into(),
            context: RangeReadContext {
                deadline: self.job.deadline(),
                token_generation: self.auth.token_generation,
            },
            owner_current: self.current.as_ref(),
            attempted: Cell::new(false),
            created: Cell::new(false),
            observed: RefCell::new(None),
            cancelled: Arc::new(move || job.is_stopped()),
        })
    }
    pub(crate) fn preflight(&self, intent: &NamespaceIntent) -> Result<(), CloudError> {
        self.live(intent)?.preflight(intent)
    }
    pub(crate) fn send(&self, dispatch: &DirectoryCreateDispatch<'_>) -> OwnedDirectorySend {
        let remote = match self.live(dispatch.intent()) {
            Ok(remote) => remote,
            Err(error) => return OwnedDirectorySend::Rejected(error),
        };
        match remote.create(dispatch) {
            Err(error) | Ok(DirectoryCreateResponse::Rejected(error)) => {
                OwnedDirectorySend::Rejected(error)
            }
            Ok(DirectoryCreateResponse::Uncertain(_)) => OwnedDirectorySend::Uncertain,
            Ok(DirectoryCreateResponse::Created) => match remote.observe(dispatch.intent()) {
                Ok(report) => OwnedDirectorySend::Verified(Box::new(report)),
                Err(_) => OwnedDirectorySend::Uncertain,
            },
        }
    }
    pub(crate) fn refresh(
        &self,
        intent: &NamespaceIntent,
        report: &NamespaceDestinationReport,
    ) -> Result<RefreshedDirectory, BackendError> {
        let latest = self
            .live(intent)
            .map_err(|_| BackendError::Unavailable)?
            .observe(intent)
            .map_err(|_| BackendError::Unavailable)?;
        self.check()?;
        if &latest != report {
            return Err(BackendError::Unavailable);
        }
        Ok(RefreshedDirectory {
            report: Box::new(latest),
        })
    }
    /// Only local catalog/native work spans the original publication fence.
    pub(crate) fn publish<T>(
        &self,
        proof: &RefreshedDirectory,
        run: impl FnOnce(&[u8; 16]) -> Result<T, crate::Error>,
    ) -> Result<T, crate::Error> {
        let unavailable = || crate::Error::EditRecoveryUnavailable;
        self.check().map_err(|_| unavailable())?;
        let report = &proof.report;
        if report.destination.parent.scope != self.captured.scope
            || report.destination.parent.remote != self.captured.remote
        {
            return Err(unavailable());
        }
        let scope = &self.captured.scope;
        let path = format!(
            "{}/{}",
            self.captured.path.trim_end_matches('/'),
            report.destination.name
        );
        let identity = binding_identity(
            &self.catalog_scope,
            "directory",
            &[
                &scope.space_id,
                &scope.root_resource_id,
                &path,
                &report.remote.resource_id,
            ],
        );
        let _permit = self
            .backend
            .begin_scoped_publish(self.job.cancellation())
            .map_err(|_| unavailable())?;
        self.check().map_err(|_| unavailable())?;
        let mut state = self.backend.state.try_lock().map_err(|_| unavailable())?;
        let composite = composite_root_identity(
            &self.backend.scope,
            self.catalog_scope.personal_space_id(),
            self.catalog_scope.personal_root_resource_id(),
        );
        if !matches!(state.namespace_directories.get(&composite), Some(NamespaceDirectory::Root { account_id, personal_space_id, personal_root_id }) if account_id == self.backend.scope.account_id() && personal_space_id == self.catalog_scope.personal_space_id() && personal_root_id == self.catalog_scope.personal_root_resource_id())
            || state
                .directories
                .get(&self.captured.identity)
                .is_none_or(|parent| {
                    parent.space_id != scope.space_id
                        || parent.root_resource_id != scope.root_resource_id
                        || parent.path != self.captured.path
                        || parent.remote_id != self.captured.remote.resource_id
                })
            || binding_count(&state) >= MAX_IDENTITY_CATALOG_ENTRIES
            || state.files.contains_key(&identity)
            || state.namespace_directories.contains_key(&identity)
            || state.directories.iter().any(|(key, prior)| {
                *key == identity || (prior.space_id == scope.space_id && prior.path == path)
            })
        {
            return Err(unavailable());
        }
        self.backend
            .upsert_identity_binding(
                &self.catalog_scope,
                &ProviderIdentityBinding::Directory {
                    identity: *identity.as_bytes(),
                    space_id: scope.space_id.clone(),
                    root_resource_id: scope.root_resource_id.clone(),
                    path: path.clone(),
                    remote_id: report.remote.resource_id.clone(),
                },
            )
            .map_err(|_| unavailable())?;
        state.directories.insert(
            identity,
            DirectoryBinding {
                space_id: scope.space_id.clone(),
                root_resource_id: scope.root_resource_id.clone(),
                path,
                remote_id: report.remote.resource_id.clone(),
            },
        );
        self.check().map_err(|_| unavailable())?;
        let result = run(identity.as_bytes())?;
        self.check().map_err(|_| unavailable())?;
        Ok(result)
    }
}
