//! Original-lease ordinary Personal or writable Space-file deletion session.
//! Native callback ownership and journal admission remain with the caller.
use super::*;
use crate::namespace_file_delete::{
    FileDeleteAbsence, FileDeleteDispatch, FileDeleteRemote, FileDeleteSend,
};
use crate::namespace_intent::{
    CapturedAuthorization, ExistingNamespaceEntry, NamespaceIntent, NamespaceObjectKind,
    NamespaceOperation, StorageClassification,
};
use raiun_core::backend::CloudError;
use raiun_opencloud::{
    ConditionalDeleteRequest, ConditionalDeleteResponse, OrdinaryPresenceRequest,
    OrdinaryTargetPresence,
};
use std::{
    cell::Cell,
    time::{Duration, Instant},
};

fn refusal(kind: ErrorKind) -> CloudError {
    CloudError::new(kind, "ordinary file delete evidence unavailable")
}
fn source(intent: &NamespaceIntent) -> Option<&ExistingNamespaceEntry> {
    match &intent.operation {
        NamespaceOperation::DeleteFile { source }
        | NamespaceOperation::DeleteDirectory { source } => Some(source),
        _ => None,
    }
}
fn supported(intent: &NamespaceIntent) -> bool {
    let Some(source) = source(intent) else {
        return false;
    };
    matches!(
        source.local.object_kind,
        NamespaceObjectKind::File | NamespaceObjectKind::Directory
    ) && (source.local.object_kind != NamespaceObjectKind::Directory || source.remote.byte_len == 0)
        && source.local.parent.classification == StorageClassification::Ordinary
        && local_prefix(&source.local.parent.local_components).is_some()
        && namespace::strong(&source.remote.etag)
        && valid_remote_id(&source.remote.resource_id)
}
fn relative_to_root(root: &str, path: &str) -> Option<String> {
    let root = root.trim_end_matches('/');
    path.strip_prefix(root)
        .and_then(|tail| tail.strip_prefix('/'))
        .filter(|tail| !tail.is_empty())
        .map(str::to_owned)
}
fn local_prefix(components: &[String]) -> Option<usize> {
    match components.first().map(String::as_str) {
        Some("Personal") => Some(1),
        Some("Spaces") if components.len() >= 2 => Some(2),
        _ => None,
    }
}
fn parent_path_matches(path: &str, components: &[String]) -> bool {
    let Some(prefix) = local_prefix(components) else {
        return false;
    };
    let tail = &components[prefix..];
    let remote = path
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    remote.len() == tail.len()
        && remote
            .iter()
            .zip(tail)
            .all(|(remote, local)| *remote == local)
}

/// Personal remains the account anchor; the target is selected only by its
/// captured Space ID. A displayed Spaces label never becomes a remote ID.
fn verified_target_root(
    backend: &OpenCloudPlaceholderBackend,
    scope: &crate::EditJournalScope,
    components: &[String],
    context: RangeReadContext,
) -> Result<raiun_core::backend::RemoteEntry, CloudError> {
    let catalog = backend
        .catalog_scope_snapshot()
        .map_err(|_| refusal(ErrorKind::Conflict))?
        .ok_or_else(|| refusal(ErrorKind::Conflict))?;
    let spaces = backend
        .client
        .spaces_with_context_limited(context, MAX_PROVIDER_SPACES)?;
    let personal = verified_personal(&spaces).map_err(|_| refusal(ErrorKind::Conflict))?;
    if personal.id != catalog.personal_space_id
        || derive_account_id(&backend.client.configured_server_url(), &personal.id)
            != backend.scope.account_id
    {
        return Err(refusal(ErrorKind::Conflict));
    }
    let anchor = backend
        .client
        .stat_discovered_space_root_with_context(personal, context)?;
    if !anchor.directory || anchor.encrypted || anchor.id != catalog.personal_root_resource_id {
        return Err(refusal(ErrorKind::Conflict));
    }
    let mut candidates = spaces.iter().filter(|space| space.id == scope.space_id);
    let target = candidates
        .next()
        .ok_or_else(|| refusal(ErrorKind::Conflict))?;
    if candidates.next().is_some()
        || !target.writable
        || target.encrypted
        || match local_prefix(components) {
            Some(1) => !target.personal || target.id != personal.id,
            Some(2) => target.personal || target.id == personal.id,
            _ => true,
        }
    {
        return Err(refusal(ErrorKind::Conflict));
    }
    let root = if target.id == personal.id {
        anchor
    } else {
        backend
            .client
            .stat_discovered_space_root_with_context(target, context)?
    };
    if !root.directory
        || root.encrypted
        || !root.writable
        || root.id != scope.root_resource_id
        || !valid_remote_path(&scope.space_id, &scope.root_resource_id, &root.path, true)
    {
        return Err(refusal(ErrorKind::Conflict));
    }
    Ok(root)
}

impl OpenCloudPlaceholderBackend {
    /// The ORIGINAL backend read lease brackets the complete closure, including
    /// remote verification and any later caller-owned local completion. No
    /// callback metadata, path string or record can create native authority.
    pub fn with_file_delete_session<T>(
        &self,
        intent: &NamespaceIntent,
        parent_identity: OpaqueIdentity,
        owner_current: &dyn Fn(CapturedAuthorization) -> bool,
        run: impl FnOnce(&super::FileDeleteSession<'_>) -> T,
    ) -> Result<T, BackendError> {
        intent.validate().map_err(|_| BackendError::Unavailable)?;
        if !supported(intent) {
            return Err(BackendError::Unavailable);
        }
        let source = source(intent).ok_or(BackendError::Unavailable)?;
        let scope = &source.local.parent.scope;
        let authorization = source.local.parent.authorization;
        if authorization.token_generation != self.token_generation
            || scope.profile_id != self.scope.profile_id
            || scope.account_subject != self.scope.account_id
            || scope.server_origin != self.scope.server_origin
            || !owner_current(authorization)
        {
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
        if catalog.local_root() != self.local_root_identity.ok_or(BackendError::Unavailable)?
            || catalog.root_volume_serial != scope.root_volume_serial
            || catalog.root_file_index != scope.root_file_index
            || catalog.profile_id != scope.profile_id
            || catalog.account_id != scope.account_subject
            || catalog.server_origin != scope.server_origin
            || !owner_current(authorization)
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
            || parent.remote_id != source.local.parent.remote.resource_id
            || !parent.path.starts_with('/')
            || !parent_path_matches(&parent.path, &source.local.parent.local_components)
        {
            return Err(BackendError::Unavailable);
        }
        let context = RangeReadContext {
            deadline: Instant::now() + Duration::from_secs(30),
            token_generation: self.token_generation,
        };
        let root =
            verified_target_root(self, scope, &source.local.parent.local_components, context)
                .map_err(|error| self.reject_cached_cloud_error(error))?;
        let path = format!(
            "{}/{}",
            parent.path.trim_end_matches('/'),
            source.local.name
        );
        if !valid_remote_path(&scope.space_id, &scope.root_resource_id, &path, false) {
            return Err(BackendError::Unavailable);
        }
        let relative = relative_to_root(&root.path, &path).ok_or(BackendError::Unavailable)?;
        let (source_identity, source_binding) =
            if source.local.object_kind == NamespaceObjectKind::Directory {
                let state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
                let mut matches = state.directories.iter().filter(|(_, binding)| {
                    binding.space_id == scope.space_id
                        && binding.root_resource_id == scope.root_resource_id
                        && binding.path == path
                        && binding.remote_id == source.remote.resource_id
                });
                let (identity, binding) = matches.next().ok_or(BackendError::Unavailable)?;
                if matches.next().is_some() {
                    return Err(BackendError::Unavailable);
                }
                (*identity, DeleteBinding::Directory(binding.clone()))
            } else {
                let (identity, binding) = self
                    .state
                    .lock()
                    .map_err(|_| BackendError::Unavailable)?
                    .files
                    .iter()
                    .find(|(_, binding)| {
                        binding.space_id == scope.space_id
                            && binding.root_resource_id == scope.root_resource_id
                            && binding.path == path
                            && binding.remote_id == source.remote.resource_id
                            && binding.etag == source.remote.etag
                            && binding.size == source.remote.byte_len
                    })
                    .map(|(identity, binding)| (*identity, binding.clone()))
                    .ok_or(BackendError::Unavailable)?;
                (identity, DeleteBinding::File(binding))
            };
        let cancellation = self.client.transfer_budget().cancellation();
        let remote = LiveFileDelete {
            backend: self,
            intent: intent.clone(),
            parent_identity,
            parent,
            source_identity,
            source_binding,
            root_path: root.path,
            path,
            relative,
            context,
            owner_current,
            attempted: Cell::new(false),
            deleted: Cell::new(false),
            cancelled: Arc::new(move || cancellation.is_cancelled()),
        };
        remote
            .ensure_authorized(intent)
            .map_err(|_| BackendError::Unavailable)?;
        Ok(run(&FileDeleteSession { remote }))
    }
}

enum DeleteBinding {
    File(FileBinding),
    Directory(DirectoryBinding),
}
struct LiveFileDelete<'a> {
    backend: &'a OpenCloudPlaceholderBackend,
    intent: NamespaceIntent,
    parent_identity: OpaqueIdentity,
    parent: DirectoryBinding,
    source_identity: OpaqueIdentity,
    source_binding: DeleteBinding,
    root_path: String,
    path: String,
    relative: String,
    context: RangeReadContext,
    owner_current: &'a dyn Fn(CapturedAuthorization) -> bool,
    attempted: Cell<bool>,
    deleted: Cell<bool>,
    cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
}
fn below(parent: &str, child: &str) -> bool {
    child.trim_end_matches('/') == parent.trim_end_matches('/')
        || child
            .strip_prefix(parent.trim_end_matches('/'))
            .is_some_and(|tail| tail.starts_with('/'))
}
impl LiveFileDelete<'_> {
    fn original(&self) -> &ExistingNamespaceEntry {
        source(&self.intent).expect("private constructor accepts only file deletes")
    }
    fn authoritative(&self, error: CloudError) -> CloudError {
        let _ = self.backend.reject_cached_cloud_error(error.clone());
        error
    }
    fn ensure_authorized(&self, intent: &NamespaceIntent) -> Result<(), CloudError> {
        self.backend
            .ensure_active()
            .map_err(|_| refusal(ErrorKind::Unauthorized))?;
        let authorization = self.original().local.parent.authorization;
        if intent != &self.intent
            || Instant::now() >= self.context.deadline
            || authorization.token_generation != self.backend.token_generation
            || !(self.owner_current)(authorization)
            || (self.cancelled)()
        {
            return Err(refusal(ErrorKind::Unauthorized));
        }
        self.backend
            .ensure_ordinary_location(&self.original().local.parent.scope.space_id, &self.path)
            .map_err(|_| refusal(ErrorKind::Forbidden))?;
        let state = self
            .backend
            .state
            .lock()
            .map_err(|_| refusal(ErrorKind::Io))?;
        let current_source = match &self.source_binding {
            DeleteBinding::File(binding) => state.files.get(&self.source_identity) == Some(binding),
            DeleteBinding::Directory(binding) => {
                state.directories.get(&self.source_identity) == Some(binding)
                    && !state.files.values().any(|child| {
                        child.space_id == binding.space_id && below(&binding.path, &child.path)
                    })
                    && !state.directories.iter().any(|(id, child)| {
                        *id != self.source_identity
                            && child.space_id == binding.space_id
                            && below(&binding.path, &child.path)
                    })
            }
        };
        let current =
            current_source && state.directories.get(&self.parent_identity) == Some(&self.parent);
        drop(state);
        if !current {
            return Err(refusal(ErrorKind::Conflict));
        }
        self.backend
            .client
            .with_token_generation(self.context.token_generation, || ())?;
        Ok(())
    }
    fn check_parent(&self, captured_etag: bool) -> Result<(), CloudError> {
        self.ensure_authorized(&self.intent)?;
        let scope = &self.original().local.parent.scope;
        let root = verified_target_root(
            self.backend,
            scope,
            &self.original().local.parent.local_components,
            self.context,
        )
        .map_err(|error| self.authoritative(error))?;
        if !root.directory
            || root.encrypted
            || !root.writable
            || root.id != scope.root_resource_id
            || root.path.trim_end_matches('/') != self.root_path.trim_end_matches('/')
        {
            return Err(self.authoritative(refusal(ErrorKind::Conflict)));
        }
        let parent = self
            .backend
            .client
            .stat_with_context(&scope.space_id, &self.parent.path, self.context)
            .map_err(|error| self.authoritative(error))?;
        if !parent.directory
            || parent.encrypted
            || !parent.writable
            || parent.id != self.parent.remote_id
            || parent.path.trim_end_matches('/') != self.parent.path.trim_end_matches('/')
            || !namespace::strong(&parent.etag)
            || (captured_etag && parent.etag != self.original().local.parent.remote.etag)
        {
            return Err(self.authoritative(refusal(ErrorKind::Conflict)));
        }
        self.ensure_authorized(&self.intent)
    }
    fn leaf(&self) -> Result<OrdinaryTargetPresence, CloudError> {
        let scope = &self.original().local.parent.scope;
        self.backend
            .client
            .ordinary_target_presence_with_context(OrdinaryPresenceRequest {
                space: &scope.space_id,
                remote_root_path: &self.root_path,
                expected_root_id: &scope.root_resource_id,
                relative_path: &self.relative,
                context: self.context,
            })
            .map_err(|error| self.authoritative(error))
    }
}
impl FileDeleteRemote for LiveFileDelete<'_> {
    fn ensure_authorized(&self, intent: &NamespaceIntent) -> Result<(), CloudError> {
        LiveFileDelete::ensure_authorized(self, intent)
    }
    fn preflight(&self, intent: &NamespaceIntent) -> Result<ExistingNamespaceEntry, CloudError> {
        self.ensure_authorized(intent)?;
        self.check_parent(true)?;
        match self.leaf()? {
            OrdinaryTargetPresence::Present(entry)
                if entry.path.trim_end_matches('/') == self.path.trim_end_matches('/')
                    && entry.id == self.original().remote.resource_id
                    && entry.etag == self.original().remote.etag
                    && (self.original().local.object_kind == NamespaceObjectKind::Directory
                        || entry.size == self.original().remote.byte_len)
                    && namespace::strong(&entry.etag)
                    && entry.directory
                        == (self.original().local.object_kind
                            == NamespaceObjectKind::Directory)
                    && !entry.encrypted
                    && entry.writable => {}
            _ => return Err(self.authoritative(refusal(ErrorKind::Conflict))),
        }
        if self.original().local.object_kind == NamespaceObjectKind::Directory {
            self.backend
                .client
                .list_with_context(
                    &self.original().local.parent.scope.space_id,
                    &self.path,
                    self.context,
                    &mut |_| Err(refusal(ErrorKind::Conflict)),
                )
                .map_err(|error| self.authoritative(error))?;
        }
        self.check_parent(true)?;
        Ok(self.original().clone())
    }
    fn delete_with_send_guard(
        &self,
        dispatch: &FileDeleteDispatch<'_>,
        before_send: &mut dyn FnMut() -> Result<(), CloudError>,
    ) -> Result<FileDeleteSend, CloudError> {
        if self.attempted.replace(true) {
            return Err(refusal(ErrorKind::Conflict));
        }
        let intent = dispatch.intent();
        self.preflight(intent)?;
        let scope = &self.original().local.parent.scope;
        let hook_refused = Cell::new(false);
        let request = ConditionalDeleteRequest {
            space: &scope.space_id,
            remote_root_path: &self.root_path,
            expected_root_id: &scope.root_resource_id,
            source_relative_path: &self.relative,
            expected_source_id: &self.original().remote.resource_id,
            expected_source_size: self.original().remote.byte_len,
            expected_source_etag: &self.original().remote.etag,
            context: self.context,
        };
        // Local-only claim: all remote emptiness/role/root work precedes this hook.
        let guard = || {
            let result = self.ensure_authorized(intent).and_then(|()| before_send());
            if result.is_err() {
                hook_refused.set(true);
            }
            result
        };
        let response = if self.original().local.object_kind == NamespaceObjectKind::Directory {
            self.backend
                .client
                .conditional_empty_directory_delete_with_context_before_send(request, guard)
        } else {
            self.backend
                .client
                .conditional_delete_with_context_before_send(request, guard)
        };
        match response {
            Ok(ConditionalDeleteResponse::Deleted) => {
                if self.ensure_authorized(intent).is_err() {
                    return Ok(FileDeleteSend::Uncertain);
                }
                self.deleted.set(true);
                Ok(FileDeleteSend::Deleted)
            }
            Ok(ConditionalDeleteResponse::Uncertain(error)) => {
                self.authoritative(error);
                Ok(FileDeleteSend::Uncertain)
            }
            Err(error) if hook_refused.get() => Err(error),
            Err(error) => Err(self.authoritative(error)),
        }
    }
    fn observe_absence(&self, intent: &NamespaceIntent) -> Result<FileDeleteAbsence, CloudError> {
        self.ensure_authorized(intent)?;
        if !self.deleted.get() {
            return Err(refusal(ErrorKind::Conflict));
        }
        self.check_parent(false)?;
        match self.leaf()? {
            OrdinaryTargetPresence::Absent => (),
            OrdinaryTargetPresence::Present(_) => {
                return Err(self.authoritative(refusal(ErrorKind::Conflict)));
            }
        }
        self.check_parent(false)?;
        self.ensure_authorized(intent)?;
        Ok(FileDeleteAbsence {
            source: self.original().clone(),
            original_path_absent: true,
        })
    }
}

pub struct FileDeleteSession<'backend> {
    remote: LiveFileDelete<'backend>,
}
impl FileDeleteSession<'_> {
    pub fn remote(&self) -> &dyn FileDeleteRemote {
        &self.remote
    }
    pub fn intent(&self) -> &NamespaceIntent {
        &self.remote.intent
    }
}

#[cfg(test)]
#[path = "file_delete_tests.rs"]
mod tests;
