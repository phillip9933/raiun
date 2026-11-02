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

#[cfg(windows)]
use raiun_control_windows::directory_notifications::directory_rename_hints::RenameHintPair;

/// O(1) binding snapshot for a typed rename notification pair.
///
/// This is deliberately not a namespace intent or mutation capability: it
/// has no freshly classified parent ancestry or parent remote validator.
#[cfg(windows)]
pub struct FileRenameBindingCandidate<'hint> {
    source_identity: OpaqueIdentity,
    parent_identity: OpaqueIdentity,
    source: FileBinding,
    parent: DirectoryBinding,
    destination_path: String,
    catalog_scope: crate::ProviderIdentityCatalogScope,
    authorization: CapturedAuthorization,
    local_file_hint: crate::LocalFileIdentity,
    hints: RenameHintPair<'hint>,
}

#[cfg(windows)]
impl FileRenameBindingCandidate<'_> {
    pub fn source_identity(&self) -> OpaqueIdentity {
        self.source_identity
    }

    pub fn parent_identity(&self) -> OpaqueIdentity {
        self.parent_identity
    }

    pub fn space_id(&self) -> &str {
        &self.source.space_id
    }

    pub fn root_resource_id(&self) -> &str {
        &self.source.root_resource_id
    }

    pub fn source_path(&self) -> &str {
        &self.source.path
    }

    pub fn destination_path(&self) -> &str {
        &self.destination_path
    }

    pub fn source_remote_id(&self) -> &str {
        &self.source.remote_id
    }

    pub fn parent_remote_id(&self) -> &str {
        &self.parent.remote_id
    }

    pub fn source_etag(&self) -> &str {
        &self.source.etag
    }

    pub fn source_size(&self) -> u64 {
        self.source.size
    }

    pub fn catalog_scope(&self) -> &crate::ProviderIdentityCatalogScope {
        &self.catalog_scope
    }

    pub fn authorization(&self) -> CapturedAuthorization {
        self.authorization
    }

    pub fn local_file_hint(&self) -> crate::LocalFileIdentity {
        self.local_file_hint
    }

    pub fn rename_hint_pair(&self) -> &RenameHintPair<'_> {
        &self.hints
    }
}

#[cfg(windows)]
impl std::fmt::Debug for FileRenameBindingCandidate<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileRenameBindingCandidate")
            .field("source_identity", &"[BOUND]")
            .field("parent_identity", &"[BOUND]")
            .field("source_binding", &"[BOUND]")
            .field("parent_binding", &"[BOUND]")
            .field("catalog_scope", &"[BOUND]")
            .field("authorization", &"[BOUND]")
            .field("local_file_hint", &"[HINT]")
            .field("rename_hints", &"[UNTRUSTED SAME-BATCH PAIR]")
            .finish()
    }
}

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
        && local_prefix(&source.local.parent.local_components).is_some()
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
    let Some(prefix) = local_prefix(components) else {
        return false;
    };
    let tail = &components[prefix..];
    let remote_parts: Vec<_> = path.split('/').filter(|part| !part.is_empty()).collect();
    remote_parts.len() == tail.len()
        && remote_parts
            .iter()
            .zip(tail)
            .all(|(remote, local)| *remote == local)
}

fn local_prefix(components: &[String]) -> Option<usize> {
    match components.first().map(String::as_str) {
        Some("Personal") => Some(1),
        Some("Spaces") if components.len() >= 2 => Some(2),
        _ => None,
    }
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
    if spaces.iter().any(|space| {
        space.id.is_empty() || space.id.len() > 512 || space.id.chars().any(char::is_control)
    }) {
        return Err(refusal(ErrorKind::Conflict));
    }
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
    #[cfg(windows)]
    pub(crate) fn file_rename_token_is_current(&self) -> bool {
        !self.revoked.load(Ordering::Acquire)
            && self.client.token_generation() == self.token_generation
    }

    /// Resolve an untrusted rename pair through fresh remote parent metadata
    /// while bracketing exact existing-binding checks with a backend lease.
    /// The callback may do local-only work; it must not re-enter this backend
    /// or access the rename store. The read lease is dropped before the
    /// method returns to its caller.
    #[cfg(windows)]
    pub(crate) fn with_file_rename_candidate_parent<T>(
        &self,
        candidate: &FileRenameBindingCandidate<'_>,
        owner_current: &dyn Fn(CapturedAuthorization) -> bool,
        run: impl FnOnce(&super::namespace::CapturedDirectoryParent) -> T,
    ) -> Result<T, BackendError> {
        let authorization = candidate.authorization;
        let hints = &candidate.hints;
        let old = hints.old_components();
        let new = hints.new_components();
        if authorization.agent_generation == 0
            || authorization.token_generation != self.token_generation
            || old.len() < 2
            || old.len() != new.len()
            || local_prefix(&old[..old.len() - 1]).is_none()
            || old[..old.len() - 1] != new[..new.len() - 1]
            || !self.file_rename_token_is_current()
            || !owner_current(authorization)
        {
            return Err(BackendError::Unavailable);
        }
        let lease = self
            .lease_gate
            .read()
            .map_err(|_| BackendError::Unavailable)?;
        self.ensure_active()?;
        let catalog_scope = self
            .catalog_scope_snapshot()?
            .ok_or(BackendError::Unavailable)?;
        if catalog_scope != candidate.catalog_scope
            || catalog_scope.local_root()
                != self.local_root_identity.ok_or(BackendError::Unavailable)?
            || catalog_scope.profile_id() != self.scope.profile_id()
            || catalog_scope.account_id() != self.scope.account_id()
            || catalog_scope.server_origin() != self.scope.server_origin()
            || authorization.token_generation != self.scope.token_generation()
        {
            return Err(BackendError::Unavailable);
        }
        let bindings_match = || -> Result<bool, BackendError> {
            let state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
            Ok(
                state.files.get(&candidate.source_identity) == Some(&candidate.source)
                    && state.directories.get(&candidate.parent_identity) == Some(&candidate.parent),
            )
        };
        if !bindings_match()?
            || candidate.local_file_hint.volume_serial != catalog_scope.local_root().volume_serial
            || candidate.local_file_hint.file_index == 0
            || !super::valid_remote_id(&candidate.source.remote_id)
            || !strong(&candidate.source.etag)
            || !owner_current(authorization)
        {
            return Err(BackendError::Unavailable);
        }

        let components = old[..old.len() - 1]
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let cancellation = crate::CancellationToken::with_timeout(Duration::from_secs(30));
        let captured = self.capture_namespace_parent_under_lease(
            &components,
            catalog_scope.local_root(),
            authorization,
            &cancellation,
        )?;
        let expected_path = candidate
            .source
            .path
            .rsplit_once('/')
            .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
            .ok_or(BackendError::Unavailable)?;
        if captured.identity != candidate.parent_identity
            || captured.path != expected_path
            || captured.path != candidate.parent.path
            || captured.remote.resource_id != candidate.parent.remote_id
            || captured.scope.profile_id != catalog_scope.profile_id
            || captured.scope.account_subject != catalog_scope.account_id
            || captured.scope.server_origin != catalog_scope.server_origin
            || captured.scope.space_id != candidate.parent.space_id
            || captured.scope.root_resource_id != candidate.parent.root_resource_id
            || captured.scope.root_volume_serial != catalog_scope.root_volume_serial
            || captured.scope.root_file_index != catalog_scope.root_file_index
            || captured.route.len() != components.len()
            || !strong(&captured.remote.etag)
        {
            return Err(BackendError::Unavailable);
        }
        if !bindings_match()? || !owner_current(authorization) {
            return Err(BackendError::Unavailable);
        }
        let result = run(&captured);
        self.ensure_active()?;
        let token_current = self.file_rename_token_is_current();
        if !token_current || !bindings_match()? {
            return Err(BackendError::Unavailable);
        }
        drop(lease);
        if !owner_current(authorization) {
            return Err(BackendError::Unavailable);
        }
        Ok(result)
    }

    /// Resolve a notification through the fresh managed namespace before
    /// looking up the ORIGINAL source binding. Labels supply no target IDs.
    #[cfg(windows)]
    pub fn file_rename_binding_candidate_from_hint<'hint>(
        &self,
        hints: RenameHintPair<'hint>,
        authorization: CapturedAuthorization,
        local_file_hint: crate::LocalFileIdentity,
        owner_current: &dyn Fn(CapturedAuthorization) -> bool,
    ) -> Result<FileRenameBindingCandidate<'hint>, BackendError> {
        let old = hints.old_components();
        let new = hints.new_components();
        if old.len() < 2
            || old.len() > 256
            || old.len() != new.len()
            || local_prefix(&old[..old.len() - 1]).is_none()
            || old[..old.len() - 1] != new[..new.len() - 1]
            || !owner_current(authorization)
        {
            return Err(BackendError::Unavailable);
        }
        let parts = old[..old.len() - 1]
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let captured = self.capture_namespace_parent(
            &parts,
            self.local_root_identity.ok_or(BackendError::Unavailable)?,
            authorization,
        )?;
        let source_path = joined(&captured.path, old.last().ok_or(BackendError::Unavailable)?);
        let source_identity = {
            let state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
            let mut matches = state.files.iter().filter(|(_, binding)| {
                binding.space_id == captured.scope.space_id
                    && binding.root_resource_id == captured.scope.root_resource_id
                    && binding.path == source_path
            });
            let identity = *matches.next().ok_or(BackendError::Unavailable)?.0;
            if matches.next().is_some() {
                return Err(BackendError::Unavailable);
            }
            identity
        };
        self.file_rename_binding_candidate(
            source_identity,
            captured.identity,
            hints,
            authorization,
            local_file_hint,
            owner_current,
        )
    }

    /// Bind one complete notification-batch pair to the exact existing
    /// durable source and parent identities. The result remains partial
    /// evidence; a later caller must capture and validate the parent locally
    /// and remotely before constructing any namespace intent.
    #[cfg(windows)]
    pub fn file_rename_binding_candidate<'hint>(
        &self,
        source_identity: OpaqueIdentity,
        parent_identity: OpaqueIdentity,
        hints: RenameHintPair<'hint>,
        authorization: CapturedAuthorization,
        local_file_hint: crate::LocalFileIdentity,
        owner_current: &dyn Fn(CapturedAuthorization) -> bool,
    ) -> Result<FileRenameBindingCandidate<'hint>, BackendError> {
        let old = hints.old_components();
        let new = hints.new_components();
        if old.len() < 2
            || old.len() != new.len()
            || local_prefix(&old[..old.len() - 1]).is_none()
            || old[..old.len() - 1] != new[..new.len() - 1]
            || old
                .iter()
                .chain(new)
                .any(|component| !super::valid_windows_component(component))
            || old[old.len() - 1].eq_ignore_ascii_case(&new[new.len() - 1])
            || authorization.agent_generation == 0
            || authorization.token_generation != self.token_generation
            || local_file_hint.volume_serial == 0
            || local_file_hint.file_index == 0
            || !self.file_rename_token_is_current()
            || !owner_current(authorization)
        {
            return Err(BackendError::Unavailable);
        }
        let lease = self
            .lease_gate
            .read()
            .map_err(|_| BackendError::Unavailable)?;
        self.ensure_active()?;

        let catalog_scope = self
            .catalog_scope_snapshot()?
            .ok_or(BackendError::Unavailable)?;
        let Some(local_root) = self.local_root_identity else {
            return Err(BackendError::Unavailable);
        };
        if catalog_scope.local_root() != local_root
            || catalog_scope.profile_id() != self.scope.profile_id()
            || catalog_scope.account_id() != self.scope.account_id()
            || catalog_scope.server_origin() != self.scope.server_origin()
            || !super::valid_remote_path(
                catalog_scope.personal_space_id(),
                catalog_scope.personal_root_resource_id(),
                "/",
                true,
            )
            || local_file_hint.volume_serial != local_root.volume_serial
            || self.scope.token_generation() != authorization.token_generation
        {
            return Err(BackendError::Unavailable);
        }

        let parent_components = &old[..old.len() - 1];
        let (parent, source) = {
            let state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
            let parent = state
                .directories
                .get(&parent_identity)
                .cloned()
                .ok_or(BackendError::NotFound)?;
            let source = state
                .files
                .get(&source_identity)
                .cloned()
                .ok_or(BackendError::NotFound)?;
            (parent, source)
        };
        let expected_source_path =
            joined(&parent.path, old.last().ok_or(BackendError::Unavailable)?);
        let destination_path = joined(&parent.path, new.last().ok_or(BackendError::Unavailable)?);
        if source.space_id != parent.space_id
            || source.root_resource_id != parent.root_resource_id
            || source.path != expected_source_path
            || !parent_path_matches_components(&parent.path, parent_components)
            || !super::valid_remote_path(
                &parent.space_id,
                &parent.root_resource_id,
                &parent.path,
                true,
            )
            || !super::valid_remote_path(
                &source.space_id,
                &source.root_resource_id,
                &source.path,
                false,
            )
            || !super::valid_remote_path(
                &parent.space_id,
                &parent.root_resource_id,
                &destination_path,
                false,
            )
            || !super::valid_remote_id(&parent.remote_id)
            || !super::valid_remote_id(&source.remote_id)
            || !strong(&source.etag)
            || self
                .ensure_ordinary_location(&parent.space_id, &parent.path)
                .is_err()
            || self
                .ensure_ordinary_location(&source.space_id, &source.path)
                .is_err()
            || self
                .ensure_ordinary_location(&parent.space_id, &destination_path)
                .is_err()
        {
            return Err(BackendError::Unavailable);
        }
        self.ensure_active()?;
        let token_current = self.file_rename_token_is_current();
        drop(lease);
        if !token_current || !owner_current(authorization) {
            return Err(BackendError::Unavailable);
        }
        Ok(FileRenameBindingCandidate {
            source_identity,
            parent_identity,
            source,
            parent,
            destination_path,
            catalog_scope,
            authorization,
            local_file_hint,
            hints,
        })
    }

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
        let root =
            verified_target_root(self, scope, &source.local.parent.local_components, context)
                .map_err(|error| self.reject_cached_cloud_error(error))?;
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
            clean_cloud_source: RefCell::new(None),
            observed: RefCell::new(None),
            cancelled: Arc::new(move || transfer_cancellation.is_cancelled()),
        };
        remote
            .ensure_authorized(intent)
            .map_err(|_| BackendError::Unavailable)?;
        Ok(run(&FileRenameSession { remote }))
    }
}

// Private readonly original revision proof; never a body-write or replay grant.
#[derive(Eq, PartialEq)]
struct CleanCloudSourceProof {
    scope: crate::EditJournalScope,
    authorization: CapturedAuthorization,
    remote: RemoteEditBaseline,
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
    clean_cloud_source: RefCell<Option<CleanCloudSourceProof>>,
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
        let root = verified_target_root(
            self.backend,
            scope,
            &self.source().local.parent.local_components,
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
        self.rename_with_send_guard(dispatch, &mut || Ok(()))
    }

    fn rename_with_send_guard(
        &self,
        dispatch: &FileRenameDispatch<'_>,
        before_send: &mut dyn FnMut() -> Result<(), CloudError>,
    ) -> Result<FileRenameSend, CloudError> {
        if self.attempted.replace(true) {
            return Err(refusal(ErrorKind::Conflict));
        }
        let intent = dispatch.intent();
        self.preflight(intent)?;
        let local_hook_refused = Cell::new(false);
        let response = self
            .backend
            .client
            .conditional_rename_with_context_before_send(
                ConditionalRenameRequest {
                    space: &self.source().local.parent.scope.space_id,
                    remote_root_path: &self.root_path,
                    expected_root_id: &self.source().local.parent.scope.root_resource_id,
                    source_relative_path: &self.source_relative,
                    destination_relative_path: &self.destination_relative,
                    expected_source_id: &self.source().remote.resource_id,
                    expected_source_size: self.source().remote.byte_len,
                    expected_source_etag: &self.source().remote.etag,
                    context: self.context,
                },
                || {
                    // Remote qualification completed in caller/SDK preflight.
                    // This hook must stay local: no network or client reentry
                    // while consuming the one-use native admission claim.
                    let result = self.ensure_authorized(intent).and_then(|()| before_send());
                    if result.is_err() {
                        local_hook_refused.set(true);
                    }
                    result
                },
            );
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
            Err(error) if local_hook_refused.get() => Err(error),
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
    pub(crate) fn verify_clean_cloud_source_metadata(&self) -> Result<(), CloudError> {
        let remote = &self.remote;
        remote.ensure_authorized(&remote.intent)?;
        let source = remote.source();
        let expected = CleanCloudSourceProof {
            scope: source.local.parent.scope.clone(),
            authorization: source.local.parent.authorization,
            remote: source.remote.clone(),
        };
        {
            let proof = remote
                .clean_cloud_source
                .try_borrow()
                .map_err(|_| refusal(ErrorKind::Io))?;
            if let Some(proof) = proof.as_ref() {
                return if *proof == expected {
                    Ok(())
                } else {
                    Err(refusal(ErrorKind::Conflict))
                };
            }
        }
        if remote.attempted.get() || !strong(&source.remote.etag) {
            return Err(refusal(ErrorKind::Conflict));
        }
        remote.preflight(&remote.intent)?;
        remote.ensure_authorized(&remote.intent)?;
        *remote
            .clean_cloud_source
            .try_borrow_mut()
            .map_err(|_| refusal(ErrorKind::Io))? = Some(expected);
        Ok(())
    }
    #[cfg(windows)]
    pub(crate) fn prepare_clean_cloud_file_rename<'session>(
        &'session self,
        readback: &'session FileRenameReadback,
    ) -> Result<VerifiedFileRenamePublication<'session, 'backend>, BackendError> {
        let source = self.remote.source();
        if !self
            .remote
            .clean_cloud_source
            .try_borrow()
            .map_err(|_| BackendError::Unavailable)?
            .as_ref()
            .is_some_and(|p| {
                p.scope == source.local.parent.scope
                    && p.authorization == source.local.parent.authorization
                    && p.remote == source.remote
            })
            || readback.destination().remote != source.remote
            || !strong(&source.remote.etag)
        {
            return Err(BackendError::Unavailable);
        }
        publication::prepare(self, readback)
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

#[cfg(windows)]
mod empty_directory {
    use super::*;
    use std::time::Instant;
    /// Metadata-only custody for one already observed local empty-directory rename.
    /// No descendant bindings are rebased or discarded by this operation.
    pub(crate) struct EmptyDirectoryRenameBinding {
        pub(crate) parent: namespace::CapturedDirectoryParent,
        pub(crate) source_identity: OpaqueIdentity,
        pub(crate) source_remote: RemoteEditBaseline,
        source: DirectoryBinding,
        authorization: CapturedAuthorization,
        destination_path: String,
        catalog: ProviderIdentityCatalogScope,
        context: RangeReadContext,
        cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
    }
    impl OpenCloudPlaceholderBackend {
        pub(crate) fn prepare_empty_directory_rename(
            &self,
            pair: raiun_control_windows::directory_notifications::directory_rename_hints::RenameHintPair<'_>,
            root: crate::ConfiguredRootIdentity,
            auth: CapturedAuthorization,
            current: &dyn Fn(CapturedAuthorization) -> bool,
        ) -> Result<EmptyDirectoryRenameBinding, BackendError> {
            let old = pair.old_components();
            let new = pair.new_components();
            if old.len() < 2
                || old.len() != new.len()
                || old[..old.len() - 1] != new[..new.len() - 1]
                || old
                    .last()
                    .unwrap()
                    .eq_ignore_ascii_case(new.last().unwrap())
                || !current(auth)
            {
                return Err(BackendError::Unavailable);
            }
            let parent_parts = old[..old.len() - 1]
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>();
            if crate::personal_create_relative(&parent_parts, old.last().unwrap()).is_none() {
                return Err(BackendError::Unavailable);
            }
            let cancellation = self.client.transfer_budget().cancellation();
            let context = RangeReadContext {
                deadline: Instant::now() + Duration::from_secs(30),
                token_generation: auth.token_generation,
            };
            let catalog = self
                .catalog_scope_snapshot()?
                .ok_or(BackendError::Unavailable)?;
            if catalog.local_root() != root || auth.token_generation != self.token_generation {
                return Err(BackendError::Unavailable);
            }
            let parent = self.capture_namespace_parent(&parent_parts, root, auth)?;
            let source_path = format!(
                "{}/{}",
                parent.path.trim_end_matches('/'),
                old.last().unwrap()
            );
            let destination_path = format!(
                "{}/{}",
                parent.path.trim_end_matches('/'),
                new.last().unwrap()
            );
            let (source_identity, source) = {
                let state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
                let mut found = state.directories.iter().filter(|(_, d)| {
                    d.space_id == parent.scope.space_id
                        && d.root_resource_id == parent.scope.root_resource_id
                        && d.path == source_path
                });
                let (id, source) = found.next().ok_or(BackendError::Unavailable)?;
                if found.next().is_some() {
                    return Err(BackendError::Unavailable);
                }
                (*id, source.clone())
            };
            let entry = self
                .client
                .stat_with_context(&parent.scope.space_id, &source_path, context)
                .map_err(|e| self.reject_cached_cloud_error(e))?;
            if !entry.directory
                || entry.encrypted
                || !entry.writable
                || !strong(&entry.etag)
                || entry.id != source.remote_id
                || entry.path != source_path
            {
                return Err(BackendError::Unavailable);
            }
            let result = EmptyDirectoryRenameBinding {
                parent,
                source_identity,
                source_remote: RemoteEditBaseline {
                    resource_id: entry.id,
                    etag: entry.etag,
                    byte_len: 0,
                },
                source,
                authorization: auth,
                destination_path,
                catalog,
                context,
                cancelled: Arc::new(move || cancellation.is_cancelled()),
            };
            if !current(auth) {
                return Err(BackendError::Unavailable);
            }
            Ok(result)
        }
        pub(crate) fn with_empty_directory_rename<T>(
            &self,
            binding: &EmptyDirectoryRenameBinding,
            intent: &NamespaceIntent,
            current: &dyn Fn(CapturedAuthorization) -> bool,
            run: impl FnOnce(&EmptyDirectoryRenameSession<'_>) -> T,
        ) -> Result<T, BackendError> {
            intent.validate().map_err(|_| BackendError::Unavailable)?;
            let _lease = self
                .lease_gate
                .read()
                .map_err(|_| BackendError::Unavailable)?;
            let session = EmptyDirectoryRenameSession {
                backend: self,
                binding,
                intent: intent.clone(),
                current,
                attempted: Cell::new(false),
                renamed: Cell::new(false),
                observed: RefCell::new(None),
            };
            session
                .ensure_authorized(intent)
                .map_err(|_| BackendError::Unavailable)?;
            Ok(run(&session))
        }
    }
    pub(crate) struct EmptyDirectoryRenameSession<'a> {
        backend: &'a OpenCloudPlaceholderBackend,
        binding: &'a EmptyDirectoryRenameBinding,
        intent: NamespaceIntent,
        current: &'a dyn Fn(CapturedAuthorization) -> bool,
        attempted: Cell<bool>,
        renamed: Cell<bool>,
        observed: RefCell<Option<NamespaceDestinationReport>>,
    }
    impl EmptyDirectoryRenameSession<'_> {
        fn parts(
            &self,
        ) -> (
            &crate::namespace_intent::ExistingNamespaceEntry,
            &crate::namespace_intent::LocalNamespaceEntry,
        ) {
            match &self.intent.operation {
                NamespaceOperation::MoveWithinScope {
                    source,
                    destination,
                } => (source, destination),
                _ => unreachable!("private validated move"),
            }
        }
        fn metadata(&self, captured: bool) -> Result<(), CloudError> {
            self.ensure_authorized(&self.intent)?;
            let (source, _) = self.parts();
            let scope = &source.local.parent.scope;
            namespace::qualify_create_target(
                self.backend,
                scope,
                &source.local.parent.local_components,
                self.binding.context,
            )?;
            let parent = self.backend.client.stat_with_context(
                &scope.space_id,
                &self.binding.parent.path,
                self.binding.context,
            )?;
            if !parent.directory
                || parent.encrypted
                || !parent.writable
                || parent.id != self.binding.parent.remote.resource_id
                || !strong(&parent.etag)
                || (captured && parent.etag != self.binding.parent.remote.etag)
            {
                return Err(refusal(ErrorKind::Conflict));
            }
            self.ensure_authorized(&self.intent)
        }
        fn empty(&self, path: &str) -> Result<(), CloudError> {
            self.backend.client.list_with_context(
                &self.binding.parent.scope.space_id,
                path,
                self.binding.context,
                &mut |_| Err(refusal(ErrorKind::Conflict)),
            )
        }
        fn presence(&self, path: &str) -> Result<OrdinaryTargetPresence, CloudError> {
            self.backend
                .client
                .ordinary_target_presence_with_context(OrdinaryPresenceRequest {
                    space: &self.binding.parent.scope.space_id,
                    remote_root_path: "/",
                    expected_root_id: &self.binding.parent.scope.root_resource_id,
                    relative_path: path.trim_start_matches('/'),
                    context: self.binding.context,
                })
        }
        fn bindings(&self, state: &State) -> bool {
            let b = self.binding;
            let account_root = composite_root_identity(
                &self.backend.scope,
                b.catalog.personal_space_id(),
                b.catalog.personal_root_resource_id(),
            );
            matches!(state.namespace_directories.get(&account_root),Some(NamespaceDirectory::Root {account_id,personal_space_id,personal_root_id})
            if account_id==self.backend.scope.account_id() && personal_space_id==b.catalog.personal_space_id() && personal_root_id==b.catalog.personal_root_resource_id())
                && state.directories.get(&b.source_identity) == Some(&b.source)
                && state.directories.get(&b.parent.identity).is_some_and(|p| {
                    p.space_id == b.parent.scope.space_id
                        && p.root_resource_id == b.parent.scope.root_resource_id
                        && p.path == b.parent.path
                        && p.remote_id == b.parent.remote.resource_id
                })
                && !state.files.values().any(|p| {
                    p.space_id == b.source.space_id
                        && [b.source.path.as_str(), b.destination_path.as_str()]
                            .iter()
                            .any(|root| empty_directory_overlap(root, &p.path))
                })
                && !state.directories.iter().any(|(id, p)| {
                    *id != b.source_identity
                        && p.space_id == b.source.space_id
                        && [b.source.path.as_str(), b.destination_path.as_str()]
                            .iter()
                            .any(|root| empty_directory_overlap(root, &p.path))
                })
        }
        pub(crate) fn publish_completion(
            &self,
            readback: &FileRenameReadback,
            mut native: impl FnMut(
                &[u8; 16],
            ) -> Result<
                (),
                crate::namespace_file_rename::FileRenameCompletionError,
            >,
            record: impl FnOnce() -> Result<(), crate::streamed_store::StoreError>,
        ) -> Result<(), crate::namespace_file_rename::FileRenameCompletionError> {
            use crate::namespace_file_rename::FileRenameCompletionError as E;
            self.ensure_authorized(&self.intent)
                .map_err(|_| E::Unavailable)?;
            let fresh = self.observe(&self.intent).map_err(|_| E::Unavailable)?;
            if !fresh.source_absent || &fresh.destination != readback.destination() {
                return Err(E::Unavailable);
            }
            let b = self.binding;
            let report = readback.destination();
            let identity = binding_identity(
                &b.catalog,
                "directory",
                &[
                    &b.source.space_id,
                    &b.source.root_resource_id,
                    &b.destination_path,
                    &report.remote.resource_id,
                ],
            );
            let remaining = b
                .context
                .deadline
                .checked_duration_since(Instant::now())
                .ok_or(E::Unavailable)?;
            let cancellation = CancellationToken::with_timeout(remaining);
            let _permit = self
                .backend
                .begin_scoped_publish(&cancellation)
                .map_err(|_| E::Unavailable)?;
            if Instant::now() >= b.context.deadline
                || !(self.current)(b.authorization)
                || (b.cancelled)()
                || self.backend.is_revoked()
            {
                return Err(E::Unavailable);
            }
            let mut state = self.backend.state.try_lock().map_err(|_| E::Unavailable)?;
            if !self.bindings(&state)
                || identity_in_use(&state, identity)
                || binding_count(&state) >= MAX_IDENTITY_CATALOG_ENTRIES
            {
                return Err(E::Unavailable);
            }
            let binding = ProviderIdentityBinding::Directory {
                identity: *identity.as_bytes(),
                space_id: b.source.space_id.clone(),
                root_resource_id: b.source.root_resource_id.clone(),
                path: b.destination_path.clone(),
                remote_id: report.remote.resource_id.clone(),
            };
            self.backend
                .upsert_identity_binding(&b.catalog, &binding)
                .map_err(|_| E::Uncertain)?;
            state.directories.insert(
                identity,
                DirectoryBinding {
                    space_id: b.source.space_id.clone(),
                    root_resource_id: b.source.root_resource_id.clone(),
                    path: b.destination_path.clone(),
                    remote_id: report.remote.resource_id.clone(),
                },
            );
            // No client re-entry under publication/state locks. Only exact native
            // metadata update/readback, protected catalogue IO and durable record.
            native(identity.as_bytes())?;
            if !(self.current)(self.parts().0.local.parent.authorization)
                || (b.cancelled)()
                || self.backend.is_revoked()
            {
                return Err(E::Uncertain);
            }
            self.backend
                .identity_catalog
                .as_ref()
                .ok_or(E::Uncertain)?
                .remove(&b.catalog, b.source_identity)
                .map_err(|_| E::Uncertain)?;
            state.directories.remove(&b.source_identity);
            record().map_err(E::Store)
        }
    }
    fn empty_directory_overlap(root: &str, path: &str) -> bool {
        path == root
            || path
                .strip_prefix(root.trim_end_matches('/'))
                .is_some_and(|p| p.starts_with('/'))
    }
    impl FileRenameRemote for EmptyDirectoryRenameSession<'_> {
        fn ensure_authorized(&self, intent: &NamespaceIntent) -> Result<(), CloudError> {
            self.backend
                .ensure_active()
                .map_err(|_| refusal(ErrorKind::Unauthorized))?;
            let (source, destination) = self.parts();
            let b = self.binding;
            if intent != &self.intent
                || source.local.object_kind != NamespaceObjectKind::Directory
                || destination.object_kind != NamespaceObjectKind::Directory
                || source.local.parent.scope != b.parent.scope
                || source.local.parent.remote != b.parent.remote
                || source.local.parent.authorization != b.authorization
                || source.remote != b.source_remote
                || source.remote.byte_len != 0
                || source.local.parent != destination.parent
                || source.local.local_file != destination.local_file
                || source.local.parent.authorization.token_generation
                    != self.backend.token_generation
                || !(self.current)(source.local.parent.authorization)
                || (b.cancelled)()
                || Instant::now() >= b.context.deadline
                || format!(
                    "{}/{}",
                    b.parent.path.trim_end_matches('/'),
                    source.local.name
                ) != b.source.path
                || format!(
                    "{}/{}",
                    b.parent.path.trim_end_matches('/'),
                    destination.name
                ) != b.destination_path
            {
                return Err(refusal(ErrorKind::Unauthorized));
            }
            self.backend
                .ensure_ordinary_location(&b.source.space_id, &b.source.path)
                .map_err(|_| refusal(ErrorKind::Forbidden))?;
            self.backend
                .ensure_ordinary_location(&b.source.space_id, &b.destination_path)
                .map_err(|_| refusal(ErrorKind::Forbidden))?;
            if self
                .backend
                .catalog_scope_snapshot()
                .map_err(|_| refusal(ErrorKind::Conflict))?
                .as_ref()
                != Some(&b.catalog)
            {
                return Err(refusal(ErrorKind::Conflict));
            }
            let state = self
                .backend
                .state
                .lock()
                .map_err(|_| refusal(ErrorKind::Io))?;
            if !self.bindings(&state) {
                return Err(refusal(ErrorKind::Conflict));
            }
            drop(state);
            self.backend
                .client
                .with_token_generation(b.context.token_generation, || ())?;
            Ok(())
        }
        fn preflight(&self, intent: &NamespaceIntent) -> Result<(), CloudError> {
            self.ensure_authorized(intent)?;
            self.metadata(true)?;
            match self.presence(&self.binding.source.path)? {
                OrdinaryTargetPresence::Present(e)
                    if e.directory
                        && !e.encrypted
                        && e.writable
                        && e.id == self.binding.source.remote_id
                        && e.etag == self.binding.source_remote.etag
                        && strong(&e.etag) =>
                {
                    ()
                }
                _ => return Err(refusal(ErrorKind::Conflict)),
            }
            self.empty(&self.binding.source.path)?;
            if !matches!(
                self.presence(&self.binding.destination_path)?,
                OrdinaryTargetPresence::Absent
            ) {
                return Err(refusal(ErrorKind::Conflict));
            }
            self.metadata(true)
        }
        fn rename(&self, _: &FileRenameDispatch<'_>) -> Result<FileRenameSend, CloudError> {
            Err(refusal(ErrorKind::Unsupported))
        }
        fn rename_with_send_guard(
            &self,
            dispatch: &FileRenameDispatch<'_>,
            guard: &mut dyn FnMut() -> Result<(), CloudError>,
        ) -> Result<FileRenameSend, CloudError> {
            if self.attempted.replace(true) {
                return Err(refusal(ErrorKind::Conflict));
            }
            self.preflight(dispatch.intent())?;
            let b = self.binding;
            let response = self
                .backend
                .client
                .conditional_empty_directory_rename_with_context_before_send(
                    ConditionalRenameRequest {
                        space: &b.source.space_id,
                        remote_root_path: "/",
                        expected_root_id: &b.source.root_resource_id,
                        source_relative_path: b.source.path.trim_start_matches('/'),
                        destination_relative_path: b.destination_path.trim_start_matches('/'),
                        expected_source_id: &b.source.remote_id,
                        expected_source_size: 0,
                        expected_source_etag: &b.source_remote.etag,
                        context: b.context,
                    },
                    || {
                        self.ensure_authorized(dispatch.intent())?;
                        guard()
                    },
                )?;
            match response {
                ConditionalRenameResponse::Renamed => {
                    self.renamed.set(true);
                    Ok(FileRenameSend::Renamed)
                }
                ConditionalRenameResponse::Rejected(e) => Ok(FileRenameSend::Rejected(e)),
                ConditionalRenameResponse::Uncertain(_) => Ok(FileRenameSend::Uncertain),
            }
        }
        fn observe(&self, intent: &NamespaceIntent) -> Result<FileRenameObservation, CloudError> {
            self.ensure_authorized(intent)?;
            if !self.renamed.get() {
                return Err(refusal(ErrorKind::Conflict));
            }
            self.metadata(false)?;
            let b = self.binding;
            let entry = match self.presence(&b.destination_path)? {
                OrdinaryTargetPresence::Present(e)
                    if e.directory
                        && !e.encrypted
                        && e.writable
                        && e.id == b.source.remote_id
                        && strong(&e.etag) =>
                {
                    e
                }
                _ => return Err(refusal(ErrorKind::Conflict)),
            };
            self.empty(&b.destination_path)?;
            if !matches!(
                self.presence(&b.source.path)?,
                OrdinaryTargetPresence::Absent
            ) {
                return Err(refusal(ErrorKind::Conflict));
            }
            self.metadata(false)?;
            let report = NamespaceDestinationReport {
                destination: self.parts().1.clone(),
                remote: RemoteEditBaseline {
                    resource_id: entry.id,
                    etag: entry.etag,
                    byte_len: 0,
                },
                content: None,
            };
            *self.observed.borrow_mut() = Some(report.clone());
            Ok(FileRenameObservation {
                destination: report,
                source_absent: true,
            })
        }
    }
}
#[cfg(windows)]
pub(crate) use empty_directory::{EmptyDirectoryRenameBinding, EmptyDirectoryRenameSession};
