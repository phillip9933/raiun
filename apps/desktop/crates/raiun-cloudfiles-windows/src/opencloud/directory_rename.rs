//! Bounded nonempty directory rename. No recovered replay, recursive delete or
//! server subtree-CAS claim. Partial publication retains both protected row sets.

use super::*;
use crate::RemoteEditBaseline;
use crate::namespace_file_rename::{
    FileRenameDispatch, FileRenameObservation, FileRenameReadback, FileRenameRemote, FileRenameSend,
};
use crate::namespace_intent::{
    CapturedAuthorization, NamespaceDestinationReport, NamespaceIntent, NamespaceObjectKind,
    NamespaceOperation,
};
use raiun_core::backend::{CloudError, ErrorKind, RemoteEntry};
use raiun_opencloud::{
    ConditionalMoveRequest, ConditionalRenameResponse, OrdinaryPresenceRequest,
    OrdinaryTargetPresence,
};
use std::{
    cell::{Cell, RefCell},
    time::Duration,
};
fn refusal(kind: ErrorKind) -> CloudError {
    CloudError::new(kind, "directory rename binding changed")
}
fn strong(etag: &str) -> bool {
    namespace::strong(etag)
}
const LIMIT: usize = 1024;
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct DirectoryRenameNode {
    pub(crate) original: ProviderIdentityBinding,
    pub(crate) entry: RemoteEntry,
}
impl DirectoryRenameNode {
    pub(crate) fn identity(&self) -> OpaqueIdentity {
        self.original.identity()
    }
}
fn catalog_nodes(
    state: &State,
    space: &str,
    root: &str,
    path: &str,
) -> Result<Vec<ProviderIdentityBinding>, BackendError> {
    let mut rows = Vec::new();
    for (id, d) in &state.directories {
        if d.space_id == space && subtree_overlap(path, &d.path) {
            if d.root_resource_id != root {
                return Err(BackendError::Unavailable);
            }
            rows.push(ProviderIdentityBinding::Directory {
                identity: *id.as_bytes(),
                space_id: d.space_id.clone(),
                root_resource_id: d.root_resource_id.clone(),
                path: d.path.clone(),
                remote_id: d.remote_id.clone(),
            });
        }
    }
    for (id, f) in &state.files {
        if f.space_id == space && subtree_overlap(path, &f.path) {
            if f.root_resource_id != root {
                return Err(BackendError::Unavailable);
            }
            rows.push(ProviderIdentityBinding::File {
                identity: *id.as_bytes(),
                space_id: f.space_id.clone(),
                root_resource_id: f.root_resource_id.clone(),
                path: f.path.clone(),
                remote_id: f.remote_id.clone(),
                etag: f.etag.clone(),
                size: f.size,
            });
        }
    }
    rows.sort_by_key(|r| *r.identity().as_bytes());
    if rows.len() > LIMIT {
        return Err(BackendError::Unavailable);
    }
    Ok(rows)
}
fn row_matches(row: &ProviderIdentityBinding, e: &RemoteEntry) -> bool {
    match row {
        ProviderIdentityBinding::Directory {
            path, remote_id, ..
        } => e.directory && e.path == *path && e.id == *remote_id,
        ProviderIdentityBinding::File {
            path,
            remote_id,
            etag,
            size,
            ..
        } => {
            !e.directory
                && e.path == *path
                && e.id == *remote_id
                && e.etag == *etag
                && e.size == *size
        }
        _ => false,
    }
}
fn collect_tree(
    backend: &OpenCloudPlaceholderBackend,
    space: &str,
    path: &str,
    context: RangeReadContext,
) -> Result<Vec<RemoteEntry>, CloudError> {
    let root = backend.client.stat_with_context(space, path, context)?;
    let mut result = vec![root];
    let mut pending = vec![path.to_owned()];
    while let Some(parent) = pending.pop() {
        backend
            .client
            .list_with_context(space, &parent, context, &mut |e| {
                let local_parent = e
                    .path
                    .rsplit_once('/')
                    .map(|(p, _)| if p.is_empty() { "/" } else { p });
                if result.len() >= LIMIT
                    || local_parent != Some(parent.as_str())
                    || e.encrypted
                    || !e.writable
                    || e.path.split('/').count() > 64
                    || result
                        .iter()
                        .any(|n| n.id == e.id || n.path.eq_ignore_ascii_case(&e.path))
                {
                    return Err(refusal(ErrorKind::Conflict));
                }
                if e.directory {
                    pending.push(e.path.clone());
                }
                result.push(e);
                Ok(())
            })?;
    }
    if result.iter().any(|e| e.encrypted || !e.writable) {
        return Err(refusal(ErrorKind::Forbidden));
    }
    Ok(result)
}
use std::time::Instant;
/// One original bounded catalog and fresh remote subtree; never reconstructed for replay.
pub(crate) struct DirectoryRenameBinding {
    pub(crate) parent: namespace::CapturedDirectoryParent,
    pub(crate) destination_parent: namespace::CapturedDirectoryParent,
    pub(crate) source_identity: OpaqueIdentity,
    pub(crate) source_remote: RemoteEditBaseline,
    pub(crate) nodes: Vec<DirectoryRenameNode>,
    source: DirectoryBinding,
    authorization: CapturedAuthorization,
    destination_path: String,
    catalog: ProviderIdentityCatalogScope,
    context: RangeReadContext,
    cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
}
impl DirectoryRenameBinding {
    pub(crate) fn source_remote_path(&self) -> String {
        self.source.path.clone()
    }
}
impl OpenCloudPlaceholderBackend {
    pub(crate) fn prepare_directory_rename(
        &self,
        pair: &raiun_control_windows::directory_notifications::directory_rename_hints::RenameHintPair<'_>,
        root: crate::ConfiguredRootIdentity,
        auth: CapturedAuthorization,
        current: &dyn Fn(CapturedAuthorization) -> bool,
    ) -> Result<DirectoryRenameBinding, BackendError> {
        let old = pair.old_components();
        let new = pair.new_components();
        if old.len() < 2
            || new.len() < 2
            || old
                .iter()
                .map(|p| p.to_lowercase())
                .eq(new.iter().map(|p| p.to_lowercase()))
            || !current(auth)
        {
            return Err(BackendError::Unavailable);
        }
        let parent_parts = old[..old.len() - 1]
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let destination_parent_parts = new[..new.len() - 1]
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        if crate::personal_create_relative(&parent_parts, old.last().unwrap()).is_none()
            || crate::personal_create_relative(&destination_parent_parts, new.last().unwrap())
                .is_none()
        {
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
        let destination_parent =
            self.capture_namespace_parent(&destination_parent_parts, root, auth)?;
        if parent.scope != destination_parent.scope
            || parent.scope.root_resource_id != destination_parent.scope.root_resource_id
        {
            return Err(BackendError::Unavailable);
        }
        let source_path = format!(
            "{}/{}",
            parent.path.trim_end_matches('/'),
            old.last().unwrap()
        );
        let destination_path = format!(
            "{}/{}",
            destination_parent.path.trim_end_matches('/'),
            new.last().unwrap()
        );
        if subtree_overlap(
            &source_path.to_lowercase(),
            &destination_parent.path.to_lowercase(),
        ) {
            return Err(BackendError::Unavailable);
        }
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
        let originals = {
            let state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
            if !catalog_nodes(
                &state,
                &parent.scope.space_id,
                &parent.scope.root_resource_id,
                &destination_path,
            )?
            .is_empty()
            {
                return Err(BackendError::Unavailable);
            }
            catalog_nodes(
                &state,
                &parent.scope.space_id,
                &parent.scope.root_resource_id,
                &source_path,
            )?
        };
        let remote = collect_tree(self, &parent.scope.space_id, &source_path, context)
            .map_err(|e| self.reject_cached_cloud_error(e))?;
        if originals.is_empty() || originals.len() != remote.len() {
            return Err(BackendError::Unavailable);
        }
        let mut nodes = Vec::new();
        for original in originals {
            let mut found = remote.iter().filter(|e| row_matches(&original, e));
            let entry = found.next().ok_or(BackendError::Unavailable)?.clone();
            if found.next().is_some() {
                return Err(BackendError::Unavailable);
            }
            nodes.push(DirectoryRenameNode { original, entry });
        }
        let result = DirectoryRenameBinding {
            parent,
            destination_parent,
            source_identity,
            source_remote: RemoteEditBaseline {
                resource_id: entry.id,
                etag: entry.etag,
                byte_len: 0,
            },
            source,
            nodes,
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
    pub(crate) fn with_directory_rename<T>(
        &self,
        binding: &DirectoryRenameBinding,
        intent: &NamespaceIntent,
        current: &dyn Fn(CapturedAuthorization) -> bool,
        run: impl FnOnce(&DirectoryRenameSession<'_>) -> T,
    ) -> Result<T, BackendError> {
        intent.validate().map_err(|_| BackendError::Unavailable)?;
        let _lease = self
            .lease_gate
            .read()
            .map_err(|_| BackendError::Unavailable)?;
        let session = DirectoryRenameSession {
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
pub(crate) struct DirectoryRenameSession<'a> {
    backend: &'a OpenCloudPlaceholderBackend,
    binding: &'a DirectoryRenameBinding,
    intent: NamespaceIntent,
    current: &'a dyn Fn(CapturedAuthorization) -> bool,
    attempted: Cell<bool>,
    renamed: Cell<bool>,
    observed: RefCell<Option<NamespaceDestinationReport>>,
}
impl DirectoryRenameSession<'_> {
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
        let (source, destination) = self.parts();
        for (parent, components) in [
            (&self.binding.parent, &source.local.parent.local_components),
            (
                &self.binding.destination_parent,
                &destination.parent.local_components,
            ),
        ] {
            namespace::qualify_create_target(
                self.backend,
                &parent.scope,
                components,
                self.binding.context,
            )?;
            let entry = self.backend.client.stat_with_context(
                &parent.scope.space_id,
                &parent.path,
                self.binding.context,
            )?;
            if !entry.directory
                || entry.encrypted
                || !entry.writable
                || entry.id != parent.remote.resource_id
                || !strong(&entry.etag)
                || (captured && entry.etag != parent.remote.etag)
            {
                return Err(refusal(ErrorKind::Conflict));
            }
        }
        self.ensure_authorized(&self.intent)
    }
    fn tree(&self, path: &str, root_etag: Option<&str>) -> Result<(), CloudError> {
        let b = self.binding;
        let actual = collect_tree(self.backend, &b.source.space_id, path, b.context)?;
        if actual.len() != b.nodes.len()
            || actual.iter().any(|e| {
                !b.nodes.iter().any(|n| {
                    let suffix = n.entry.path.strip_prefix(&b.source.path).unwrap();
                    let expected_path = format!("{path}{suffix}");
                    e.path == expected_path
                        && e.id == n.entry.id
                        && e.directory == n.entry.directory
                        && (e.directory || e.size == n.entry.size)
                        && e.etag
                            == if suffix.is_empty() {
                                root_etag.unwrap_or(&n.entry.etag)
                            } else {
                                &n.entry.etag
                            }
                })
            })
        {
            return Err(refusal(ErrorKind::Conflict));
        }
        Ok(())
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
            && state
                .directories
                .get(&b.destination_parent.identity)
                .is_some_and(|p| {
                    p.space_id == b.destination_parent.scope.space_id
                        && p.root_resource_id == b.destination_parent.scope.root_resource_id
                        && p.path == b.destination_parent.path
                        && p.remote_id == b.destination_parent.remote.resource_id
                })
            && catalog_nodes(
                state,
                &b.source.space_id,
                &b.source.root_resource_id,
                &b.source.path,
            )
            .is_ok_and(|rows| {
                rows == b
                    .nodes
                    .iter()
                    .map(|n| n.original.clone())
                    .collect::<Vec<_>>()
            })
            && catalog_nodes(
                state,
                &b.source.space_id,
                &b.source.root_resource_id,
                &b.destination_path,
            )
            .is_ok_and(|rows| rows.is_empty())
    }
    pub(crate) fn publish_completion(
        &self,
        readback: &FileRenameReadback,
        mut native: impl FnMut(
            &[([u8; 16], [u8; 16])],
        )
            -> Result<(), crate::namespace_file_rename::FileRenameCompletionError>,
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
        let mut staged = Vec::new();
        for node in &b.nodes {
            let path = format!(
                "{}{}",
                b.destination_path,
                node.entry
                    .path
                    .strip_prefix(&b.source.path)
                    .ok_or(E::Unavailable)?
            );
            let identity = binding_identity(
                &b.catalog,
                if node.entry.directory {
                    "directory"
                } else {
                    "file"
                },
                &[
                    &b.source.space_id,
                    &b.source.root_resource_id,
                    &path,
                    &node.entry.id,
                ],
            );
            let row = if node.entry.directory {
                ProviderIdentityBinding::Directory {
                    identity: *identity.as_bytes(),
                    space_id: b.source.space_id.clone(),
                    root_resource_id: b.source.root_resource_id.clone(),
                    path,
                    remote_id: node.entry.id.clone(),
                }
            } else {
                ProviderIdentityBinding::File {
                    identity: *identity.as_bytes(),
                    space_id: b.source.space_id.clone(),
                    root_resource_id: b.source.root_resource_id.clone(),
                    path,
                    remote_id: node.entry.id.clone(),
                    etag: node.entry.etag.clone(),
                    size: node.entry.size,
                }
            };
            staged.push(row);
        }
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
            || staged
                .iter()
                .any(|row| identity_in_use(&state, row.identity()))
            || binding_count(&state).saturating_add(staged.len()) > MAX_IDENTITY_CATALOG_ENTRIES
        {
            return Err(E::Unavailable);
        }
        // Every new binding is durable before the first native identity changes.
        // All originals remain live until every native node has factual readback.
        for row in &staged {
            self.backend
                .upsert_identity_binding(&b.catalog, row)
                .map_err(|_| E::Uncertain)?;
            match row {
                ProviderIdentityBinding::Directory {
                    identity,
                    space_id,
                    root_resource_id,
                    path,
                    remote_id,
                } => {
                    state.directories.insert(
                        OpaqueIdentity(*identity),
                        DirectoryBinding {
                            space_id: space_id.clone(),
                            root_resource_id: root_resource_id.clone(),
                            path: path.clone(),
                            remote_id: remote_id.clone(),
                        },
                    );
                }
                ProviderIdentityBinding::File {
                    identity,
                    space_id,
                    root_resource_id,
                    path,
                    remote_id,
                    etag,
                    size,
                } => {
                    state.files.insert(
                        OpaqueIdentity(*identity),
                        FileBinding {
                            space_id: space_id.clone(),
                            root_resource_id: root_resource_id.clone(),
                            path: path.clone(),
                            remote_id: remote_id.clone(),
                            etag: etag.clone(),
                            size: *size,
                        },
                    );
                }
                _ => return Err(E::Uncertain),
            }
        }
        // No client re-entry under publication/state locks. Only exact native
        // metadata update/readback, protected catalogue IO and durable record.
        let identities = b
            .nodes
            .iter()
            .zip(&staged)
            .map(|(node, row)| (*node.identity().as_bytes(), *row.identity().as_bytes()))
            .collect::<Vec<_>>();
        native(&identities)?;
        if !(self.current)(self.parts().0.local.parent.authorization)
            || (b.cancelled)()
            || self.backend.is_revoked()
        {
            return Err(E::Uncertain);
        }
        for node in &b.nodes {
            self.backend
                .identity_catalog
                .as_ref()
                .ok_or(E::Uncertain)?
                .remove(&b.catalog, node.identity())
                .map_err(|_| E::Uncertain)?;
            state.directories.remove(&node.identity());
            state.files.remove(&node.identity());
        }
        record().map_err(E::Store)
    }
}
fn subtree_overlap(root: &str, path: &str) -> bool {
    path == root
        || path
            .strip_prefix(root.trim_end_matches('/'))
            .is_some_and(|p| p.starts_with('/'))
}
impl FileRenameRemote for DirectoryRenameSession<'_> {
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
            || source.local.parent.scope != destination.parent.scope
            || source.local.parent.authorization != destination.parent.authorization
            || destination.parent.scope != b.destination_parent.scope
            || destination.parent.remote != b.destination_parent.remote
            || source.local.local_file != destination.local_file
            || source.local.parent.authorization.token_generation != self.backend.token_generation
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
                b.destination_parent.path.trim_end_matches('/'),
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
            .with_provider_generation(b.context.token_generation, || ())?;
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
        self.tree(&self.binding.source.path, None)?;
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
            .conditional_directory_rename_with_context_before_send(
                ConditionalMoveRequest {
                    space: &b.source.space_id,
                    remote_root_path: "/",
                    expected_root_id: &b.source.root_resource_id,
                    source_relative_path: b.source.path.trim_start_matches('/'),
                    destination_relative_path: b.destination_path.trim_start_matches('/'),
                    expected_source_id: &b.source.remote_id,
                    expected_source_size: 0,
                    expected_source_etag: &b.source_remote.etag,
                    source_parent_id: &b.parent.remote.resource_id,
                    source_parent_etag: &b.parent.remote.etag,
                    destination_parent_id: &b.destination_parent.remote.resource_id,
                    destination_parent_etag: &b.destination_parent.remote.etag,
                    context: b.context,
                },
                &b.nodes.iter().map(|n| n.entry.clone()).collect::<Vec<_>>(),
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
        self.tree(&b.destination_path, Some(&entry.etag))?;
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
