//! One clean-file move between two managed parents in one verified Space/root.
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
    ConditionalMoveRequest, ConditionalMoveResponse, OrdinaryPresenceRequest,
    OrdinaryTargetPresence, RangeReadContext,
};
use std::{
    cell::{Cell, RefCell},
    time::Duration,
};
fn strong(value: &str) -> bool {
    namespace::strong(value)
}
fn refusal(kind: ErrorKind) -> CloudError {
    CloudError::new(kind, "ordinary file move binding changed")
}
use std::time::Instant;
/// Positive read-only body evidence for this original live operation. A
/// strong revision proof never replaces fresh metadata, parent or native pins.
#[derive(Eq, PartialEq)]
struct ContentProof {
    scope: crate::EditJournalScope,
    auth_generation: u64,
    resource_id: String,
    etag: String,
    size: u64,
    sha256: [u8; 32],
}
/// Original custody for one already observed local cross-parent file move.
/// Only the exact original file binding is updated; neither parent subtree is rebased.
pub(crate) struct FileMoveBinding {
    pub(crate) parent: namespace::CapturedDirectoryParent,
    pub(crate) destination_parent: namespace::CapturedDirectoryParent,
    pub(crate) source_identity: OpaqueIdentity,
    pub(crate) source_remote: RemoteEditBaseline,
    source: FileBinding,
    authorization: CapturedAuthorization,
    destination_path: String,
    catalog: ProviderIdentityCatalogScope,
    context: RangeReadContext,
    cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
    source_content: RefCell<Option<ContentProof>>,
    destination_content: RefCell<Option<ContentProof>>,
}
impl FileMoveBinding {
    pub(crate) fn deadline(&self) -> Instant {
        self.context.deadline
    }
}
impl OpenCloudPlaceholderBackend {
    pub(crate) fn prepare_file_move(
        &self,
        pair: raiun_control_windows::directory_notifications::directory_rename_hints::RenameHintPair<'_>,
        root: crate::ConfiguredRootIdentity,
        auth: CapturedAuthorization,
        current: &dyn Fn(CapturedAuthorization) -> bool,
    ) -> Result<FileMoveBinding, BackendError> {
        let old = pair.old_components();
        let new = pair.new_components();
        if old.len() < 2
            || old.len() > 256
            || new.len() < 2
            || new.len() > 256
            || old[..old.len() - 1] == new[..new.len() - 1]
            || old
                .iter()
                .chain(new)
                .any(|part| !valid_windows_component(part))
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
        let destination_parts = new[..new.len() - 1]
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        if crate::personal_create_relative(&destination_parts, new.last().unwrap()).is_none() {
            return Err(BackendError::Unavailable);
        }
        let destination_parent = self.capture_namespace_parent(&destination_parts, root, auth)?;
        if parent.scope != destination_parent.scope
            || parent.identity == destination_parent.identity
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
        let (source_identity, source) = {
            let state = self.state.lock().map_err(|_| BackendError::Unavailable)?;
            let mut found = state.files.iter().filter(|(_, d)| {
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
        if entry.directory
            || entry.size != source.size
            || entry.etag != source.etag
            || entry.encrypted
            || !entry.writable
            || !strong(&entry.etag)
            || entry.id != source.remote_id
            || entry.path != source_path
        {
            return Err(BackendError::Unavailable);
        }
        let result = FileMoveBinding {
            parent,
            destination_parent,
            source_identity,
            source_remote: RemoteEditBaseline {
                resource_id: entry.id,
                etag: entry.etag,
                byte_len: entry.size,
            },
            source,
            authorization: auth,
            destination_path,
            catalog,
            context,
            cancelled: Arc::new(move || cancellation.is_cancelled()),
            source_content: RefCell::new(None),
            destination_content: RefCell::new(None),
        };
        if !current(auth) {
            return Err(BackendError::Unavailable);
        }
        Ok(result)
    }
    pub(crate) fn with_file_move<T>(
        &self,
        binding: &FileMoveBinding,
        intent: &NamespaceIntent,
        digest: [u8; 32],
        current: &dyn Fn(CapturedAuthorization) -> bool,
        run: impl FnOnce(&FileMoveSession<'_>) -> T,
    ) -> Result<T, BackendError> {
        intent.validate().map_err(|_| BackendError::Unavailable)?;
        let _lease = self
            .lease_gate
            .read()
            .map_err(|_| BackendError::Unavailable)?;
        let session = FileMoveSession {
            backend: self,
            binding,
            intent: intent.clone(),
            current,
            digest,
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
pub(crate) struct FileMoveSession<'a> {
    backend: &'a OpenCloudPlaceholderBackend,
    binding: &'a FileMoveBinding,
    intent: NamespaceIntent,
    current: &'a dyn Fn(CapturedAuthorization) -> bool,
    digest: [u8; 32],
    attempted: Cell<bool>,
    renamed: Cell<bool>,
    observed: RefCell<Option<NamespaceDestinationReport>>,
}
impl FileMoveSession<'_> {
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
        namespace::qualify_create_target(
            self.backend,
            scope,
            &self.parts().1.parent.local_components,
            self.binding.context,
        )?;
        for captured_parent in [&self.binding.parent, &self.binding.destination_parent] {
            let parent = self.backend.client.stat_with_context(
                &scope.space_id,
                &captured_parent.path,
                self.binding.context,
            )?;
            if !parent.directory
                || parent.encrypted
                || !parent.writable
                || parent.id != captured_parent.remote.resource_id
                || !strong(&parent.etag)
                || (captured && parent.etag != captured_parent.remote.etag)
            {
                return Err(refusal(ErrorKind::Conflict));
            }
        }
        self.ensure_authorized(&self.intent)
    }
    fn body(&self, path: &str, etag: &str, source: bool) -> Result<(), CloudError> {
        self.ensure_authorized(&self.intent)?;
        if !strong(etag) {
            return Err(refusal(ErrorKind::Conflict));
        }
        let b = self.binding;
        let expected = ContentProof {
            scope: b.parent.scope.clone(),
            auth_generation: b.context.token_generation,
            resource_id: b.source.remote_id.clone(),
            etag: etag.to_owned(),
            size: b.source.size,
            sha256: self.digest,
        };
        let cell = if source {
            &b.source_content
        } else {
            &b.destination_content
        };
        {
            let cached = cell.try_borrow().map_err(|_| refusal(ErrorKind::Io))?;
            if let Some(proof) = cached.as_ref() {
                // Reuse only the exact independently verified strong revision.
                // A changed revision is conflict, never a second body fetch or
                // silent adoption/rebasing during this one live operation.
                return if *proof == expected {
                    Ok(())
                } else {
                    Err(refusal(ErrorKind::Conflict))
                };
            }
        }
        let proof = self
            .backend
            .client
            .recovery_read_digest_cancellable_with_context(
                &b.source.space_id,
                "/",
                &b.source.root_resource_id,
                path.trim_start_matches('/'),
                &b.source.remote_id,
                etag,
                b.source.size,
                self.digest,
                b.context,
                Arc::clone(&b.cancelled),
            )?;
        if proof.bytes != b.source.size
            || proof.sha256 != self.digest
            || proof.entry.id != b.source.remote_id
            || proof.entry.etag != etag
            || proof.entry.directory
            || proof.entry.encrypted
            || !proof.entry.writable
            || proof.entry.path != path
        {
            return Err(refusal(ErrorKind::Conflict));
        }
        self.ensure_authorized(&self.intent)?;
        let mut cached = cell.try_borrow_mut().map_err(|_| refusal(ErrorKind::Io))?;
        if cached.is_some() {
            return Err(refusal(ErrorKind::Conflict));
        }
        *cached = Some(expected);
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
            && state.files.get(&b.source_identity) == Some(&b.source)
            && [&b.parent, &b.destination_parent].iter().all(|parent| {
                state.directories.get(&parent.identity).is_some_and(|p| {
                    p.space_id == parent.scope.space_id
                        && p.root_resource_id == parent.scope.root_resource_id
                        && p.path == parent.path
                        && p.remote_id == parent.remote.resource_id
                })
            })
            && !state.files.iter().any(|(id, p)| {
                *id != b.source_identity
                    && p.space_id == b.source.space_id
                    && p.root_resource_id == b.source.root_resource_id
                    && p.path == b.destination_path
            })
            && !state.directories.values().any(|p| {
                p.space_id == b.source.space_id
                    && p.root_resource_id == b.source.root_resource_id
                    && p.path == b.destination_path
            })
    }

    pub(crate) fn publish_completion(
        &self,
        readback: &FileRenameReadback,
        mut native: impl FnMut(
            &[u8; 16],
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
        let report = readback.destination();
        let identity = binding_identity(
            &b.catalog,
            "file",
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
        let binding = ProviderIdentityBinding::File {
            identity: *identity.as_bytes(),
            space_id: b.source.space_id.clone(),
            root_resource_id: b.source.root_resource_id.clone(),
            path: b.destination_path.clone(),
            remote_id: report.remote.resource_id.clone(),
            etag: report.remote.etag.clone(),
            size: report.remote.byte_len,
        };
        self.backend
            .upsert_identity_binding(&b.catalog, &binding)
            .map_err(|_| E::Uncertain)?;
        state.files.insert(
            identity,
            FileBinding {
                space_id: b.source.space_id.clone(),
                root_resource_id: b.source.root_resource_id.clone(),
                path: b.destination_path.clone(),
                remote_id: report.remote.resource_id.clone(),
                etag: report.remote.etag.clone(),
                size: report.remote.byte_len,
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
        state.files.remove(&b.source_identity);
        record().map_err(E::Store)
    }
}
impl FileRenameRemote for FileMoveSession<'_> {
    fn ensure_authorized(&self, intent: &NamespaceIntent) -> Result<(), CloudError> {
        self.backend
            .ensure_active()
            .map_err(|_| refusal(ErrorKind::Unauthorized))?;
        let (source, destination) = self.parts();
        let b = self.binding;
        if intent != &self.intent
            || source.local.object_kind != NamespaceObjectKind::File
            || destination.object_kind != NamespaceObjectKind::File
            || source.local.parent.scope != b.parent.scope
            || source.local.parent.remote != b.parent.remote
            || source.local.parent.authorization != b.authorization
            || source.remote != b.source_remote
            || source.remote.byte_len != b.source.size
            || source.local.parent.scope != destination.parent.scope
            || source.local.parent.authorization != destination.parent.authorization
            || destination.parent.remote != b.destination_parent.remote
            || source.local.parent == destination.parent
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
            .with_token_generation(b.context.token_generation, || ())?;
        Ok(())
    }
    fn preflight(&self, intent: &NamespaceIntent) -> Result<(), CloudError> {
        self.ensure_authorized(intent)?;
        self.metadata(true)?;
        match self.presence(&self.binding.source.path)? {
            OrdinaryTargetPresence::Present(e)
                if !e.directory
                    && e.size == self.binding.source.size
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
        self.body(
            &self.binding.source.path,
            &self.binding.source_remote.etag,
            true,
        )?;
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
            .conditional_move_with_context_before_send(
                ConditionalMoveRequest {
                    space: &b.source.space_id,
                    remote_root_path: "/",
                    expected_root_id: &b.source.root_resource_id,
                    source_relative_path: b.source.path.trim_start_matches('/'),
                    destination_relative_path: b.destination_path.trim_start_matches('/'),
                    expected_source_id: &b.source.remote_id,
                    expected_source_size: b.source.size,
                    expected_source_etag: &b.source_remote.etag,
                    source_parent_id: &b.parent.remote.resource_id,
                    source_parent_etag: &b.parent.remote.etag,
                    destination_parent_id: &b.destination_parent.remote.resource_id,
                    destination_parent_etag: &b.destination_parent.remote.etag,
                    context: b.context,
                },
                || {
                    self.ensure_authorized(dispatch.intent())?;
                    guard()
                },
            )?;
        match response {
            ConditionalMoveResponse::Renamed => {
                self.renamed.set(true);
                Ok(FileRenameSend::Renamed)
            }
            ConditionalMoveResponse::Rejected(e) => Ok(FileRenameSend::Rejected(e)),
            ConditionalMoveResponse::Uncertain(_) => Ok(FileRenameSend::Uncertain),
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
                if !e.directory
                    && e.size == b.source.size
                    && !e.encrypted
                    && e.writable
                    && e.id == b.source.remote_id
                    && strong(&e.etag) =>
            {
                e
            }
            _ => return Err(refusal(ErrorKind::Conflict)),
        };
        self.body(&b.destination_path, &entry.etag, false)?;
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
                byte_len: entry.size,
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
