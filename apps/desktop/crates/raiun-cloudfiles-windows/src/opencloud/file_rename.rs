//! Live SDK session for one same-parent ordinary-file rename.
//!
//! This remains an adapter seam only. It supplies no journal, native proof,
//! filesystem mutation, registration or production activation.
use super::*;
use crate::RemoteEditBaseline;
use crate::namespace_file_rename::{
    FileRenameDispatch, FileRenameObservation, FileRenameReadback, FileRenameRemote, FileRenameSend,
};
use crate::namespace_intent::{
    CapturedAuthorization, NamespaceDestinationReport, NamespaceIntent, NamespaceObjectKind,
    NamespaceOperation,
};
use raiun_core::backend::{CloudError, ErrorKind};
use raiun_opencloud::{
    ConditionalRenameRequest, ConditionalRenameResponse, OrdinaryPresenceRequest,
    OrdinaryTargetPresence,
};
use std::{
    cell::{Cell, RefCell},
    time::Duration,
};

#[path = "file_rename_publication.rs"]
mod publication;
pub use publication::VerifiedFileRenamePublication;
#[cfg(any(windows, test))]
#[path = "file_rename_content.rs"]
mod content;
#[cfg(any(windows, test))]
pub(crate) use content::{VerifiedRenameContentPublication, VerifiedRenameSourceContent};

fn refusal(kind: ErrorKind) -> CloudError {
    CloudError::new(kind, "ordinary file rename evidence unavailable")
}

fn strong(etag: &str) -> bool {
    super::namespace::strong(etag)
}

fn move_entries(
    intent: &NamespaceIntent,
) -> Option<(
    &crate::namespace_intent::ExistingNamespaceEntry,
    &crate::namespace_intent::LocalNamespaceEntry,
)> {
    match &intent.operation {
        NamespaceOperation::MoveWithinScope {
            source,
            destination,
        } => Some((source, destination)),
        _ => None,
    }
}

fn supported(intent: &NamespaceIntent) -> bool {
    let Some((source, destination)) = move_entries(intent) else {
        return false;
    };
    source.local.object_kind == NamespaceObjectKind::File
        && destination.object_kind == NamespaceObjectKind::File
        && source.local.parent == destination.parent
        && source.local.local_file == destination.local_file
        && source.local.parent.classification
            == crate::namespace_intent::StorageClassification::Ordinary
        && source
            .local
            .parent
            .local_components
            .first()
            .is_some_and(|p| p == "Personal")
        && source.local.name != destination.name
        && !source.local.name.eq_ignore_ascii_case(&destination.name)
        && strong(&source.remote.etag)
        && valid_remote_id(&source.remote.resource_id)
}

fn joined(parent: &str, leaf: &str) -> String {
    format!("{}/{}", parent.trim_end_matches('/'), leaf)
}

fn relative_to_root(root: &str, path: &str) -> Option<String> {
    let root = root.trim_end_matches('/');
    if root.is_empty() {
        return path
            .strip_prefix('/')
            .filter(|relative| !relative.is_empty())
            .map(str::to_owned);
    }
    path.strip_prefix(root)
        .and_then(|relative| relative.strip_prefix('/'))
        .filter(|relative| !relative.is_empty())
        .map(str::to_owned)
}

fn parent_path_matches_components(path: &str, components: &[String]) -> bool {
    let Some((_, tail)) = components.split_first() else {
        return false;
    };
    let remote_parts: Vec<_> = path.split('/').filter(|part| !part.is_empty()).collect();
    remote_parts.len() == tail.len()
        && remote_parts
            .iter()
            .zip(tail)
            .all(|(remote, local)| *remote == local)
}

impl OpenCloudPlaceholderBackend {
    /// Hold one backend read lease across dispatch and all subsequent readback.
    /// No nested backend lease is acquired by the remote adapter.
    pub fn with_file_rename_session<T>(
        &self,
        intent: &NamespaceIntent,
        parent_identity: OpaqueIdentity,
        owner_current: &dyn Fn(CapturedAuthorization) -> bool,
        run: impl FnOnce(&FileRenameSession<'_>) -> T,
    ) -> Result<T, BackendError> {
        intent.validate().map_err(|_| BackendError::Unavailable)?;
        if !supported(intent) {
            return Err(BackendError::Unavailable);
        }
        let (source, destination) = move_entries(intent).ok_or(BackendError::Unavailable)?;
        let scope = &source.local.parent.scope;
        let authorization = source.local.parent.authorization;
        if source.local.parent != destination.parent
            || authorization != destination.parent.authorization
            || authorization.agent_generation == 0
            || authorization.token_generation != self.token_generation
            || scope.profile_id != self.scope.profile_id
            || scope.account_subject != self.scope.account_id
            || scope.server_origin != self.scope.server_origin
            || scope.space_id.is_empty()
            || scope.root_resource_id.is_empty()
            || scope.root_file_index == 0
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
        if scope.root_volume_serial != catalog.root_volume_serial
            || scope.root_file_index != catalog.root_file_index
            || scope.space_id != catalog.personal_space_id
            || scope.root_resource_id != catalog.personal_root_resource_id
            || scope.profile_id != catalog.profile_id
            || scope.account_subject != catalog.account_id
            || scope.server_origin != catalog.server_origin
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
            || !parent_path_matches_components(&parent.path, &source.local.parent.local_components)
        {
            return Err(BackendError::Unavailable);
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let context = RangeReadContext {
            deadline,
            token_generation: self.token_generation,
        };
        // Keep fresh server denials and binding conflicts distinct from local
        // admission failures. A cached backend must remain fenced after an
        // authoritative loss of its account/root, even while this read lease
        // is held; the existing helper takes only the publication gate.
        let spaces = self
            .client
            .spaces_with_context_limited(context, MAX_PROVIDER_SPACES)
            .map_err(|error| self.reject_cached_cloud_error(error))?;
        if spaces.iter().any(|space| {
            space.id.is_empty() || space.id.len() > 512 || space.id.chars().any(char::is_control)
        }) {
            return Err(BackendError::Unavailable);
        }
        let space = verified_personal(&spaces)
            .map_err(|_| self.reject_cached_cloud_error(refusal(ErrorKind::Conflict)))?;
        if space.id != catalog.personal_space_id()
            || space.id != scope.space_id
            || derive_account_id(&self.client.configured_server_url(), &space.id)
                != self.scope.account_id()
            || !space.writable
            || space.encrypted
        {
            return Err(self.reject_cached_cloud_error(refusal(ErrorKind::Conflict)));
        }
        let root = self
            .client
            .stat_discovered_space_root_with_context(space, context)
            .map_err(|error| self.reject_cached_cloud_error(error))?;
        if !root.directory
            || root.encrypted
            || !root.writable
            || root.id != scope.root_resource_id
            || !valid_remote_path(&scope.space_id, &scope.root_resource_id, &root.path, true)
        {
            return Err(self.reject_cached_cloud_error(refusal(ErrorKind::Conflict)));
        }
        let source_path = joined(&parent.path, &source.local.name);
        let destination_path = joined(&parent.path, &destination.name);
        if !valid_remote_path(
            &scope.space_id,
            &scope.root_resource_id,
            &source_path,
            false,
        ) || !valid_remote_path(
            &scope.space_id,
            &scope.root_resource_id,
            &destination_path,
            false,
        ) {
            return Err(BackendError::Unavailable);
        }
        let source_relative =
            relative_to_root(&root.path, &source_path).ok_or(BackendError::Unavailable)?;
        let destination_relative =
            relative_to_root(&root.path, &destination_path).ok_or(BackendError::Unavailable)?;
        let (source_identity, source_binding) = self
            .state
            .lock()
            .map_err(|_| BackendError::Unavailable)?
            .files
            .iter()
            .find(|(_, binding)| {
                binding.space_id == scope.space_id
                    && binding.root_resource_id == scope.root_resource_id
                    && binding.path == source_path
                    && binding.remote_id == source.remote.resource_id
                    && binding.etag == source.remote.etag
                    && binding.size == source.remote.byte_len
            })
            .map(|(identity, binding)| (*identity, binding.clone()))
            .ok_or(BackendError::Unavailable)?;
        let transfer_cancellation = self.client.transfer_budget().cancellation();
        let remote = LiveFileRename {
            backend: self,
            intent: intent.clone(),
            parent_identity,
            parent,
            source_identity,
            source_binding,
            root_path: root.path,
            source_path,
            destination_path,
            source_relative,
            destination_relative,
            context,
            owner_current,
            attempted: Cell::new(false),
            renamed: Cell::new(false),
            publication_claimed: Cell::new(false),
            observed: RefCell::new(None),
            cancelled: Arc::new(move || transfer_cancellation.is_cancelled()),
        };
        remote
            .ensure_authorized(intent)
            .map_err(|_| BackendError::Unavailable)?;
        Ok(run(&FileRenameSession { remote }))
    }
}

struct LiveFileRename<'a> {
    backend: &'a OpenCloudPlaceholderBackend,
    intent: NamespaceIntent,
    parent_identity: OpaqueIdentity,
    parent: DirectoryBinding,
    source_identity: OpaqueIdentity,
    source_binding: FileBinding,
    root_path: String,
    source_path: String,
    destination_path: String,
    source_relative: String,
    destination_relative: String,
    context: RangeReadContext,
    owner_current: &'a dyn Fn(CapturedAuthorization) -> bool,
    attempted: Cell<bool>,
    renamed: Cell<bool>,
    publication_claimed: Cell<bool>,
    observed: RefCell<Option<(NamespaceDestinationReport, bool)>>,
    cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
}

impl LiveFileRename<'_> {
    fn authoritative(&self, error: CloudError) -> CloudError {
        // Preserve the original kind and post-send uncertainty. Expected typed
        // absence is never sent here, nor are local cancellation/owner errors.
        let _ = self.backend.reject_cached_cloud_error(error.clone());
        error
    }
    fn source(&self) -> &crate::namespace_intent::ExistingNamespaceEntry {
        move_entries(&self.intent)
            .map(|(source, _)| source)
            .expect("private constructor only accepts file moves")
    }
    fn destination(&self) -> &crate::namespace_intent::LocalNamespaceEntry {
        move_entries(&self.intent)
            .map(|(_, destination)| destination)
            .expect("private constructor only accepts file moves")
    }
    fn ensure_authorized(&self, intent: &NamespaceIntent) -> Result<(), CloudError> {
        let authorization = self.source().local.parent.authorization;
        self.backend
            .ensure_active()
            .map_err(|_| refusal(ErrorKind::Unauthorized))?;
        if intent != &self.intent
            || self.context.deadline <= std::time::Instant::now()
            || authorization.token_generation != self.backend.token_generation
            || !((self.owner_current)(authorization))
            || (self.cancelled)()
        {
            return Err(refusal(ErrorKind::Unauthorized));
        }
        self.backend
            .ensure_ordinary_location(
                &self.source().local.parent.scope.space_id,
                &self.source_path,
            )
            .map_err(|_| refusal(ErrorKind::Forbidden))?;
        self.backend
            .ensure_ordinary_location(
                &self.source().local.parent.scope.space_id,
                &self.destination_path,
            )
            .map_err(|_| refusal(ErrorKind::Forbidden))?;
        let state = self
            .backend
            .state
            .lock()
            .map_err(|_| refusal(ErrorKind::Io))?;
        let pinned = state
            .directories
            .get(&self.parent_identity)
            .is_some_and(|current| current == &self.parent)
            && state
                .files
                .get(&self.source_identity)
                .is_some_and(|current| current == &self.source_binding);
        drop(state);
        if !pinned {
            return Err(refusal(ErrorKind::Conflict));
        }
        self.backend
            .client
            .with_token_generation(self.context.token_generation, || ())?;
        Ok(())
    }
    fn check_parent(&self, captured_etag: bool) -> Result<(), CloudError> {
        self.ensure_authorized(&self.intent)?;
        let scope = &self.source().local.parent.scope;
        let root = self
            .backend
            .client
            .stat_with_context(&scope.space_id, &self.root_path, self.context)
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
        if parent.path.trim_end_matches('/') != self.parent.path.trim_end_matches('/')
            || !parent.directory
            || parent.encrypted
            || !parent.writable
            || parent.id != self.parent.remote_id
            || !strong(&parent.etag)
            || (captured_etag && parent.etag != self.source().local.parent.remote.etag)
        {
            return Err(self.authoritative(refusal(ErrorKind::Conflict)));
        }
        self.ensure_authorized(&self.intent)
    }
    fn leaf(&self, relative_path: &str) -> Result<OrdinaryTargetPresence, CloudError> {
        self.backend
            .client
            .ordinary_target_presence_with_context(OrdinaryPresenceRequest {
                space: &self.source().local.parent.scope.space_id,
                remote_root_path: &self.root_path,
                expected_root_id: &self.source().local.parent.scope.root_resource_id,
                relative_path,
                context: self.context,
            })
            .map_err(|error| self.authoritative(error))
    }
    fn checked_source(&self, entry: &raiun_core::backend::RemoteEntry) -> bool {
        entry.path.trim_end_matches('/') == self.source_path.trim_end_matches('/')
            && entry.id == self.source().remote.resource_id
            && entry.size == self.source().remote.byte_len
            && entry.etag == self.source().remote.etag
            && strong(&entry.etag)
            && !entry.directory
            && !entry.encrypted
            && entry.writable
    }
    fn checked_destination(&self, entry: &raiun_core::backend::RemoteEntry) -> bool {
        entry.path.trim_end_matches('/') == self.destination_path.trim_end_matches('/')
            && entry.id == self.source().remote.resource_id
            && entry.size == self.source().remote.byte_len
            && strong(&entry.etag)
            && !entry.directory
            && !entry.encrypted
            && entry.writable
    }
}

impl FileRenameRemote for LiveFileRename<'_> {
    fn ensure_authorized(&self, intent: &NamespaceIntent) -> Result<(), CloudError> {
        LiveFileRename::ensure_authorized(self, intent)
    }

    fn preflight(&self, intent: &NamespaceIntent) -> Result<(), CloudError> {
        self.ensure_authorized(intent)?;
        self.check_parent(true)?;
        match self.leaf(&self.source_relative)? {
            OrdinaryTargetPresence::Present(entry) if self.checked_source(&entry) => {}
            OrdinaryTargetPresence::Present(_) => {
                return Err(self.authoritative(refusal(ErrorKind::Conflict)));
            }
            OrdinaryTargetPresence::Absent => {
                return Err(self.authoritative(refusal(ErrorKind::NotFound)));
            }
        }
        match self.leaf(&self.destination_relative)? {
            OrdinaryTargetPresence::Absent => {}
            OrdinaryTargetPresence::Present(_) => return Err(refusal(ErrorKind::Conflict)),
        }
        self.check_parent(true)?;
        self.ensure_authorized(intent)
    }

    fn rename(&self, dispatch: &FileRenameDispatch<'_>) -> Result<FileRenameSend, CloudError> {
        if self.attempted.replace(true) {
            return Err(refusal(ErrorKind::Conflict));
        }
        let intent = dispatch.intent();
        self.preflight(intent)?;
        let response =
            self.backend
                .client
                .conditional_rename_with_context(ConditionalRenameRequest {
                    space: &self.source().local.parent.scope.space_id,
                    remote_root_path: &self.root_path,
                    expected_root_id: &self.source().local.parent.scope.root_resource_id,
                    source_relative_path: &self.source_relative,
                    destination_relative_path: &self.destination_relative,
                    expected_source_id: &self.source().remote.resource_id,
                    expected_source_size: self.source().remote.byte_len,
                    expected_source_etag: &self.source().remote.etag,
                    context: self.context,
                });
        match response {
            Ok(ConditionalRenameResponse::Renamed) => {
                if self.ensure_authorized(intent).is_err() {
                    return Ok(FileRenameSend::Uncertain);
                }
                self.renamed.set(true);
                Ok(FileRenameSend::Renamed)
            }
            Ok(ConditionalRenameResponse::Rejected(error))
            | Ok(ConditionalRenameResponse::Uncertain(error)) => {
                self.authoritative(error);
                Ok(FileRenameSend::Uncertain)
            }
            Err(error) => Err(self.authoritative(error)),
        }
    }

    fn observe(&self, intent: &NamespaceIntent) -> Result<FileRenameObservation, CloudError> {
        self.ensure_authorized(intent)?;
        if !self.renamed.get() {
            return Err(refusal(ErrorKind::Conflict));
        }
        self.check_parent(false)?;
        let destination = match self.leaf(&self.destination_relative)? {
            OrdinaryTargetPresence::Present(entry) if self.checked_destination(&entry) => entry,
            OrdinaryTargetPresence::Present(_) => {
                return Err(self.authoritative(refusal(ErrorKind::Conflict)));
            }
            OrdinaryTargetPresence::Absent => {
                return Err(self.authoritative(refusal(ErrorKind::NotFound)));
            }
        };
        match self.leaf(&self.source_relative)? {
            OrdinaryTargetPresence::Absent => {}
            OrdinaryTargetPresence::Present(_) => {
                return Err(self.authoritative(refusal(ErrorKind::Conflict)));
            }
        }
        let final_destination = match self.leaf(&self.destination_relative)? {
            OrdinaryTargetPresence::Present(entry)
                if self.checked_destination(&entry)
                    && entry.id == destination.id
                    && entry.etag == destination.etag =>
            {
                entry
            }
            OrdinaryTargetPresence::Present(_) => {
                return Err(self.authoritative(refusal(ErrorKind::Conflict)));
            }
            OrdinaryTargetPresence::Absent => {
                return Err(self.authoritative(refusal(ErrorKind::NotFound)));
            }
        };
        self.check_parent(false)?;
        self.ensure_authorized(intent)?;
        let observation = FileRenameObservation {
            destination: NamespaceDestinationReport {
                destination: self.destination().clone(),
                remote: RemoteEditBaseline {
                    resource_id: final_destination.id,
                    etag: final_destination.etag,
                    byte_len: final_destination.size,
                },
                content: None,
            },
            source_absent: true,
        };
        self.observed.replace(Some((
            observation.destination.clone(),
            observation.source_absent,
        )));
        Ok(observation)
    }
}

/// Borrowed live session that keeps its enclosing backend lease held.
pub struct FileRenameSession<'backend> {
    remote: LiveFileRename<'backend>,
}

impl<'backend> FileRenameSession<'backend> {
    pub fn remote(&self) -> &dyn FileRenameRemote {
        &self.remote
    }
    pub fn intent(&self) -> &NamespaceIntent {
        &self.remote.intent
    }
    pub fn prepare_verified_file_rename<'session>(
        &'session self,
        readback: &'session FileRenameReadback,
    ) -> Result<VerifiedFileRenamePublication<'session, 'backend>, BackendError> {
        publication::prepare(self, readback)
    }

    #[cfg(any(windows, test))]
    pub(crate) fn verify_source_content<'session>(
        &'session self,
        expected_sha256: [u8; 32],
    ) -> Result<VerifiedRenameSourceContent<'session, 'backend>, CloudError> {
        content::verify_source_content(self, expected_sha256)
    }

    #[cfg(any(windows, test))]
    pub(crate) fn prepare_content_verified_file_rename<'session>(
        &'session self,
        readback: &'session FileRenameReadback,
        source_content: &VerifiedRenameSourceContent<'_, 'backend>,
    ) -> Result<VerifiedRenameContentPublication<'session, 'backend>, BackendError> {
        content::prepare_content_verified_file_rename(self, readback, source_content)
    }

    #[cfg(windows)]
    pub(crate) fn backend(&self) -> &OpenCloudPlaceholderBackend {
        self.remote.backend
    }

    #[cfg(windows)]
    pub(crate) fn parent_identity(&self) -> OpaqueIdentity {
        self.remote.parent_identity
    }

    #[cfg(windows)]
    pub(crate) fn source_identity(&self) -> OpaqueIdentity {
        self.remote.source_identity
    }

    #[cfg(windows)]
    pub(crate) fn deadline(&self) -> std::time::Instant {
        self.remote.context.deadline
    }

    #[cfg(windows)]
    pub(crate) fn capture_native_parent(
        &self,
    ) -> Result<super::namespace::CapturedDirectoryParent, BackendError> {
        let remote = &self.remote;
        let intent = &remote.intent;
        remote
            .ensure_authorized(intent)
            .map_err(|_| BackendError::Unavailable)?;
        let source = remote.source();
        let components = source
            .local
            .parent
            .local_components
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let scope = &source.local.parent.scope;
        let root = crate::ConfiguredRootIdentity {
            volume_serial: scope.root_volume_serial,
            file_index: scope.root_file_index,
        };
        let remaining = remote
            .context
            .deadline
            .checked_duration_since(std::time::Instant::now())
            .ok_or(BackendError::Unavailable)?;
        let cancellation = crate::CancellationToken::with_timeout(remaining);
        let captured = remote.backend.capture_namespace_parent_under_lease(
            &components,
            root,
            source.local.parent.authorization,
            &cancellation,
        )?;
        if captured.identity != remote.parent_identity
            || captured.scope != *scope
            || captured.remote != source.local.parent.remote
            || captured.path != remote.parent.path
            || captured.route.len() != components.len()
        {
            return Err(BackendError::Unavailable);
        }
        remote
            .ensure_authorized(intent)
            .map_err(|_| BackendError::Unavailable)?;
        Ok(captured)
    }
}

#[cfg(test)]
#[path = "file_rename_tests.rs"]
mod tests;
