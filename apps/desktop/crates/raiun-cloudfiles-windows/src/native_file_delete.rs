//! Native clean-file delete owner for an explicitly account-bound connection.
//! All callback pointers are copied while valid; no per-callback thread escapes.
use super::*;
use crate::RemoteEditBaseline;
use crate::close_capture_admission::{DeferredDeletedClose, SaveRenameTicket};
use crate::namespace_file_delete::{
    FileDeleteAbsence, FileDeleteCompletionError, FileDeleteDispatch, FileDeleteLocal,
    FileDeleteLocalObservation, FileDeleteOutcome, FileDeleteReadback, FileDeleteRemote,
    FileDeleteSend, reconcile_file_delete,
};
use crate::namespace_intent::{
    CapturedAuthorization, ExistingNamespaceEntry, LocalNamespaceEntry, NamespaceIntent,
    NamespaceObjectKind, NamespaceOperation, NamespaceParent, StorageClassification,
};
use crate::streamed_store::namespace_file_delete_store::{
    FileDeletePublishResult, FileDeleteStore,
};
use raiun_core::backend::{CloudError, ErrorKind};
use std::{
    cell::RefCell,
    sync::{
        Weak,
        atomic::{AtomicBool, AtomicI64},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub(super) const NOTIFY_DELETE: i32 = 9;
pub(super) const DELETE_COMPLETION: i32 = 10;
const ACK_DELETE: i32 = 6;
// Microsoft windows-sys Foundation STATUS_CLOUD_FILE_UNSUCCESSFUL.
const DELETE_REFUSED: i32 = 0xC000_CF12_u32 as i32;
const LIMIT: Duration = Duration::from_secs(45);
const DRAIN_LIMIT: Duration = Duration::from_secs(2);
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct CallbackDelete {
    pub flags: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct AckDelete {
    flags: u32,
    completion_status: i32,
}
const _: () = {
    assert!(size_of::<CallbackDelete>() == 4);
    assert!(size_of::<AckDelete>() == 8);
};

pub(crate) struct Config {
    pub authorization: CapturedAuthorization,
    pub current: Arc<dyn Fn(CapturedAuthorization) -> bool + Send + Sync>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Key {
    connection: i64,
    transfer: i64,
    request: i64,
    volume: u32,
    root: u64,
    file: u64,
    identity: [u8; 16],
}
#[derive(Clone)]
struct Ticket {
    key: Key,
    path: PathBuf,
    size: u64,
    deadline: Instant,
}
struct Slot {
    ticket: Ticket,
    taken: bool,
    ack_attempted: bool,
    ack_success: bool,
    completed: bool,
    deferred: Vec<DeferredDeletedClose>,
}
struct Inner {
    slot: Option<Slot>,
    last: Option<Ticket>,
    result: Option<FileDeleteOutcome>,
}
pub(super) struct Shared {
    state: Weak<CallbackState>,
    backend: Arc<crate::OpenCloudPlaceholderBackend>,
    config: Config,
    root: crate::ConfiguredRootIdentity,
    composite: [u8; 16],
    connection: AtomicI64,
    closed: AtomicBool,
    done: AtomicBool,
    poisoned: AtomicBool,
    inner: Mutex<Inner>,
    changed: Condvar,
}
pub(super) struct Owner {
    shared: Arc<Shared>,
    worker: Option<JoinHandle<()>>,
    joined: bool,
}
impl Owner {
    pub(super) fn start(
        state: &Arc<CallbackState>,
        backend: Arc<crate::OpenCloudPlaceholderBackend>,
        composite: crate::OpaqueIdentity,
        config: Config,
    ) -> Result<Self, Error> {
        let root = state.root_identity.ok_or(Error::ConfiguredRootChanged)?;
        if config.authorization.agent_generation == 0
            || config.authorization.token_generation != backend.scope().token_generation()
            || !(config.current)(config.authorization)
        {
            return Err(Error::ProviderUnavailable);
        }
        let shared = Arc::new(Shared {
            state: Arc::downgrade(state),
            backend,
            config,
            root: crate::ConfiguredRootIdentity {
                volume_serial: root.volume_serial,
                file_index: root.file_index,
            },
            composite: *composite.as_bytes(),
            connection: AtomicI64::new(0),
            closed: AtomicBool::new(false),
            done: AtomicBool::new(false),
            poisoned: AtomicBool::new(false),
            inner: Mutex::new(Inner {
                slot: None,
                last: None,
                result: None,
            }),
            changed: Condvar::new(),
        });
        let run = shared.clone();
        let worker = thread::Builder::new()
            .name("raiun-native-delete".into())
            .spawn(move || {
                let result = catch_unwind(AssertUnwindSafe(|| worker(&run)));
                if result.is_err() {
                    run.poison();
                }
                run.done.store(true, Ordering::Release);
                run.changed.notify_all();
            })
            .map_err(|error| io_error("start owned delete worker", error))?;
        Ok(Self {
            shared,
            worker: Some(worker),
            joined: false,
        })
    }
    pub(super) fn shared(&self) -> Arc<Shared> {
        self.shared.clone()
    }
    pub(super) fn connected(&self, key: CfConnectionKey) {
        self.shared
            .connection
            .store(key.internal, Ordering::Release);
    }
    /// Cancellation is published BEFORE any join or backend writer can wait.
    pub(super) fn stop_and_join(&mut self) -> bool {
        // Serialize the cancellation transition with the one irreversible
        // ACK claim. No I/O or authority callback runs under this mutex.
        {
            let _pending = self
                .shared
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.shared.closed.store(true, Ordering::Release);
        }
        self.shared.changed.notify_all();
        // Wait only with the callback-required mutex released by the condvar.
        // A bounded timeout preserves the original owner, never detaches it.
        if let Some(worker) = self.worker.as_ref() {
            let deadline = Instant::now() + DRAIN_LIMIT;
            let Ok(mut inner) = self.shared.inner.lock() else {
                return false;
            };
            while !self.shared.done.load(Ordering::Acquire) || !worker.is_finished() {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return false;
                }
                let Ok((next, _)) = self
                    .shared
                    .changed
                    .wait_timeout(inner, remaining.min(Duration::from_millis(20)))
                else {
                    return false;
                };
                inner = next;
            }
            drop(inner);
            self.joined = self
                .worker
                .take()
                .is_some_and(|worker| worker.join().is_ok());
            if !self.joined {
                self.shared.poisoned.store(true, Ordering::Release);
            }
        }
        // No pre-join snapshot can authorize release: the worker may publish
        // Uncertain or poison immediately before exiting. Inspect final custody
        // only after a positive join, including on subsequent finish attempts.
        self.joined
            && self.shared.done.load(Ordering::Acquire)
            && self
                .shared
                .inner
                .lock()
                .is_ok_and(|inner| inner.releasable(self.shared.poisoned.load(Ordering::Acquire)))
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        if !self.stop_and_join() {
            // Preserve unresolved physical custody and the real join handle.
            let _ = Box::leak(Box::new((self.worker.take(), self.shared.clone())));
        }
    }
}
impl Inner {
    fn releasable(&self, poisoned: bool) -> bool {
        !poisoned
            && self.slot.is_none()
            && !matches!(
                self.result,
                Some(FileDeleteOutcome::Uncertain | FileDeleteOutcome::RemoteVerifiedLocalPending)
            )
    }
}
impl Shared {
    fn live(&self, ticket: &Ticket) -> bool {
        !self.closed.load(Ordering::Acquire)
            && Instant::now() < ticket.deadline
            && !self.backend.is_revoked()
            && (self.config.current)(self.config.authorization)
            && self.backend.scope().token_generation() == self.config.authorization.token_generation
    }
    fn poison(&self) {
        self.poisoned.store(true, Ordering::Release);
        self.closed.store(true, Ordering::Release);
        if let Some(state) = self.state.upgrade() {
            drop(state.close_capture_admission.begin_close());
        }
        // Any deferred close is retired unknown, never silently discarded.
        if let Ok(mut inner) = self.inner.lock() {
            inner.result = Some(FileDeleteOutcome::Uncertain);
            if let Some(slot) = inner.slot.as_mut() {
                slot.deferred.clear();
            }
        }
        self.changed.notify_all();
    }
    fn submit(&self, ticket: Ticket) -> bool {
        if !self.live(&ticket) {
            return false;
        }
        let Ok(mut inner) = self.inner.try_lock() else {
            return false;
        };
        // Stop uses this same mutex: a callback that passed live() before
        // cancellation cannot publish new custody after the worker was joined.
        if self.closed.load(Ordering::Acquire) || inner.slot.is_some() {
            return false;
        }
        inner.slot = Some(Slot {
            ticket,
            taken: false,
            ack_attempted: false,
            ack_success: false,
            completed: false,
            deferred: Vec::new(),
        });
        self.changed.notify_all();
        true
    }
    fn completion(&self, key: Key) {
        let Ok(mut inner) = self.inner.lock() else {
            self.closed.store(true, Ordering::Release);
            return;
        };
        if let Some(slot) = inner.slot.as_mut()
            && slot.ticket.key == key
            && slot.ack_attempted
        {
            slot.completed = true;
            self.changed.notify_all();
        }
    }
    fn owned_deleted_close(
        &self,
        key: Key,
        permit: &mut crate::close_capture_admission::CloseCapturePermit<'_>,
    ) -> bool {
        let Some(state) = self.state.upgrade() else {
            return false;
        };
        if self.closed.load(Ordering::Acquire) || !(self.config.current)(self.config.authorization)
        {
            return false;
        }
        let mut inner = match self.inner.try_lock() {
            Ok(inner) => inner,
            Err(_) => return false,
        };
        if let Some(slot) = inner.slot.as_mut()
            && slot.ticket.key == key
            && slot.ack_attempted
            && !self.closed.load(Ordering::Acquire)
            && Instant::now() < slot.ticket.deadline
            && slot.deferred.len() < 8
        {
            let Some(owned) = permit.defer_owned_deleted(&state.close_capture_admission) else {
                return false;
            };
            // Still active, never classified clean on ACK alone. Completion
            // processing occurs without this mutex or any callback being held.
            slot.deferred.push(owned);
            self.changed.notify_all();
            return true;
        }
        if let Some(last) = inner.last.as_ref()
            && last.key == key
            && !self.closed.load(Ordering::Acquire)
            && Instant::now() < last.deadline
        {
            let Some(owned) = permit.defer_owned_deleted(&state.close_capture_admission) else {
                return false;
            };
            drop(inner);
            let finished = owned.finish_after_owned_completion();
            if !finished {
                self.poison();
            }
            return finished;
        }
        false
    }
}

fn worker(shared: &Arc<Shared>) {
    loop {
        let ticket = {
            let mut inner = shared
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            loop {
                if let Some(slot) = inner.slot.as_mut()
                    && !slot.taken
                {
                    slot.taken = true;
                    break Some(slot.ticket.clone());
                }
                if shared.closed.load(Ordering::Acquire) {
                    break None;
                }
                inner = shared
                    .changed
                    .wait(inner)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        };
        let Some(ticket) = ticket else {
            return;
        };
        let mut outcome = execute(shared, &ticket);
        let mut inner = shared
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let slot = inner.slot.take();
        // Only this request's owned deferred CLOSE permits belong to this
        // custody decision. A CLOSE can arrive after completion consumed the
        // previous batch but before this terminal transition. Never drop that
        // permit unknown while releasing its delete owner as known complete.
        if slot.as_ref().is_some_and(|slot| !slot.deferred.is_empty()) {
            shared.poisoned.store(true, Ordering::Release);
            outcome = FileDeleteOutcome::Uncertain;
        }
        if outcome == FileDeleteOutcome::Completed
            && slot
                .as_ref()
                .is_some_and(|slot| slot.ack_success && slot.completed)
        {
            inner.last = Some(ticket);
        } else {
            shared.closed.store(true, Ordering::Release);
        }
        if matches!(
            outcome,
            FileDeleteOutcome::Uncertain | FileDeleteOutcome::RemoteVerifiedLocalPending
        ) {
            // Preserve the original keys/phase even after the worker exits.
            // Deferred CLOSE bookkeeping may only retire unknown on this path.
            inner.slot = slot;
            if let Some(slot) = inner.slot.as_mut() {
                slot.deferred.clear();
            }
        } else {
            drop(slot);
        }
        inner.result = Some(outcome);
        shared.changed.notify_all();
    }
}
fn execute(shared: &Arc<Shared>, ticket: &Ticket) -> FileDeleteOutcome {
    let result = (|| -> Result<FileDeleteOutcome, Error> {
        let state = shared.state.upgrade().ok_or(Error::ProviderUnavailable)?;
        if !shared.live(ticket) || state.readiness.load(Ordering::Acquire) != CALLBACK_READY {
            return Err(Error::ProviderUnavailable);
        }
        let tracker = state.close_capture_admission.clone();
        let admission = RefCell::new(
            tracker
                .try_begin_rename()
                .ok_or(Error::EditRecoveryUnavailable)?,
        );
        let recovery = state
            .recovery
            .as_ref()
            .ok_or(Error::EditRecoveryUnavailable)?;
        if recovery
            .has_unresolved()
            .map_err(|_| Error::EditRecoveryUnavailable)?
            || recovery
                .has_unresolved_content_authenticated_legacy()
                .map_err(|_| Error::EditRecoveryUnavailable)?
        {
            return Err(Error::EditRecoveryUnavailable);
        }
        let root_path = state
            .root_path
            .as_ref()
            .ok_or(Error::ConfiguredRootChanged)?;
        if !windows_path_is_within(&ticket.path, root_path) {
            return Err(Error::ConfiguredRootChanged);
        }
        let mut components = ticket
            .path
            .components()
            .skip(root_path.components().count())
            .map(|part| match part {
                std::path::Component::Normal(part) => part.to_str().map(str::to_owned),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(Error::ConfiguredRootChanged)?;
        if components.len() < 2
            || components.first().map(String::as_str) != Some("Personal")
            || components.iter().any(|part| !valid_component(part))
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let name = components.pop().ok_or(Error::ConfiguredRootChanged)?;
        let refs = components.iter().map(String::as_str).collect::<Vec<_>>();
        let captured = shared
            .backend
            .capture_namespace_parent(&refs, shared.root, shared.config.authorization)
            .map_err(|_| Error::ProviderUnavailable)?;
        if !shared.live(ticket) || !admission.borrow().is_current() {
            return Err(Error::ProviderUnavailable);
        }
        let native_lease = pin_registered_configured_root(root_path, shared.root)?;
        let mut root = OwnedConfiguredRoot::new(root_path.clone(), native_lease, true)?;
        root.connected = true; // Same live connection was checked above, never register/unregister here.
        let (parent, parent_snapshot, ancestors) =
            native_namespace_directory::pin_namespace_parent(
                &root,
                &captured.route,
                captured.identity,
                &refs,
                FILE_READ_ATTRIBUTES,
            )?;
        let path = wide_path(&ticket.path)?;
        // The user already owns a DELETE handle. Share DELETE for that exact
        // operation, deny WRITE, open the reparse point itself, never hydrate.
        let raw = unsafe {
            CreateFileW(
                path.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(win32_io_error("pin owned delete leaf"));
        }
        let leaf = RawOwnedHandle(raw);
        let leaf_snapshot = root_snapshot(leaf.0)?;
        // Existing backend API pins the original opaque binding under a read
        // lease. Copy its metadata, then drop that lease before store access or
        // opening the later deletion session (no nested read/write acquisition).
        let prepared = shared
            .backend
            .prepare_edit_binding(&ticket.key.identity)
            .map_err(|_| Error::ProviderUnavailable)?;
        let binding = prepared.binding().clone();
        drop(prepared);
        let logical = format!("{}/{}", captured.path.trim_end_matches('/'), name);
        if binding.profile_id != captured.scope.profile_id
            || binding.server_origin != captured.scope.server_origin
            || binding.account_subject != captured.scope.account_subject
            || binding.account_generation != shared.config.authorization.token_generation
            || binding.space_id != captured.scope.space_id
            || binding.root_resource_id != captured.scope.root_resource_id
            || binding.virtual_path != logical
            || binding.base_size != ticket.size
        {
            return Err(Error::ProviderUnavailable);
        }
        let original_identity = crate::ProviderIdentityBinding::File {
            identity: ticket.key.identity,
            space_id: binding.space_id.clone(),
            root_resource_id: binding.root_resource_id.clone(),
            path: binding.virtual_path.clone(),
            remote_id: binding.remote_resource_id.clone(),
            etag: binding.base_etag.clone(),
            size: binding.base_size,
        }
        .identity();
        let source = ExistingNamespaceEntry {
            local: LocalNamespaceEntry {
                parent: NamespaceParent {
                    scope: captured.scope.clone(),
                    authorization: shared.config.authorization,
                    classification: StorageClassification::Ordinary,
                    local_file: LocalFileIdentity {
                        volume_serial: parent_snapshot.identity.volume_serial,
                        file_index: parent_snapshot.identity.file_index,
                    },
                    local_components: components,
                    remote: captured.remote,
                },
                name,
                local_file: LocalFileIdentity {
                    volume_serial: ticket.key.volume,
                    file_index: ticket.key.file,
                },
                object_kind: NamespaceObjectKind::File,
            },
            remote: RemoteEditBaseline {
                resource_id: binding.remote_resource_id.clone(),
                etag: binding.base_etag.clone(),
                byte_len: binding.base_size,
            },
        };
        let rename = file_rename_store_from_prepared(
            Some(recovery),
            shared.backend.scope(),
            shared.root,
            &source.local.parent.scope,
            shared.config.authorization,
        )?
        .ok_or(Error::EditRecoveryUnavailable)?;
        let store = FileDeleteStore::new(rename.snapshot_store().clone())
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        let mut local = Local {
            shared,
            ticket,
            state: &state,
            admission: &admission,
            root,
            parent,
            _ancestors: ancestors,
            leaf: Some(leaf),
            snapshot: leaf_snapshot,
            source,
            acknowledged: false,
        };
        local.check().map_err(|_| Error::EditRecoveryUnavailable)?;
        let candidate = NamespaceIntent {
            schema_version: 1,
            record_id: "0".repeat(32),
            record_generation: 1,
            operation: NamespaceOperation::DeleteFile {
                source: local.source.clone(),
            },
        };
        let publication = match store
            .publish_intent(candidate)
            .map_err(|_| Error::EditRecoveryUnavailable)?
        {
            FileDeletePublishResult::Fresh(fresh) => fresh,
            FileDeletePublishResult::Retained => return Ok(FileDeleteOutcome::Retained),
        };
        let mut journal = publication
            .acquire_dispatch()
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        let intent = journal.intent().clone();
        let current = |authorization| {
            authorization == shared.config.authorization
                && shared.live(ticket)
                && admission.borrow().is_current()
        };
        let outcome = shared
            .backend
            .with_file_delete_session(&intent, captured.identity, &current, |session| {
                let remote = GuardedRemote {
                    remote: session.remote(),
                    admission: &admission,
                };
                reconcile_file_delete(&mut journal, &remote, &mut local)
            })
            .map_err(|_| Error::ProviderUnavailable)?
            .map_err(|_| Error::EditRecoveryUnavailable)?;
        if !local.acknowledged {
            ack_once(shared, ticket, false);
        }
        if outcome == FileDeleteOutcome::Completed && shared.live(ticket) {
            // Never attempt the exclusive retirement barrier under the HTTP
            // session's read lease. It has already returned above.
            shared
                .backend
                .unregister_file(original_identity)
                .map_err(|_| Error::EditRecoveryUnavailable)?;
        }
        Ok(outcome)
    })();
    // Every admitted NOTIFY receives at most one ACK, including a retained
    // store result or a pre-publication refusal that returned early above.
    ack_once(shared, ticket, false);
    match result {
        Ok(outcome) => outcome,
        Err(_) => {
            ack_once(shared, ticket, false);
            shared.poison();
            FileDeleteOutcome::Uncertain
        }
    }
}
struct GuardedRemote<'a, 'b> {
    remote: &'a dyn FileDeleteRemote,
    admission: &'a RefCell<SaveRenameTicket<'b>>,
}
impl FileDeleteRemote for GuardedRemote<'_, '_> {
    fn ensure_authorized(&self, intent: &NamespaceIntent) -> Result<(), CloudError> {
        if !self.admission.borrow().is_current() {
            return Err(cloud());
        }
        self.remote.ensure_authorized(intent)
    }
    fn preflight(&self, intent: &NamespaceIntent) -> Result<ExistingNamespaceEntry, CloudError> {
        self.ensure_authorized(intent)?;
        self.remote.preflight(intent)
    }
    fn delete_with_send_guard(
        &self,
        dispatch: &FileDeleteDispatch<'_>,
        guard: &mut dyn FnMut() -> Result<(), CloudError>,
    ) -> Result<FileDeleteSend, CloudError> {
        self.remote.delete_with_send_guard(dispatch, &mut || {
            if !self.admission.borrow_mut().claim_dispatch() {
                return Err(cloud());
            }
            guard()
        })
    }
    fn observe_absence(&self, intent: &NamespaceIntent) -> Result<FileDeleteAbsence, CloudError> {
        self.ensure_authorized(intent)?;
        self.remote.observe_absence(intent)
    }
}
fn cloud() -> CloudError {
    CloudError::new(ErrorKind::Forbidden, "owned native delete unavailable")
}
struct Local<'a, 'b> {
    shared: &'a Shared,
    ticket: &'a Ticket,
    state: &'a CallbackState,
    admission: &'a RefCell<SaveRenameTicket<'b>>,
    root: OwnedConfiguredRoot,
    parent: RawOwnedHandle,
    _ancestors: Vec<(RawOwnedHandle, RootSnapshot)>,
    leaf: Option<RawOwnedHandle>,
    snapshot: RootSnapshot,
    source: ExistingNamespaceEntry,
    acknowledged: bool,
}
impl Local<'_, '_> {
    fn check(&self) -> Result<(), CloudError> {
        if !self.shared.live(self.ticket)
            || !self.admission.borrow().is_current()
            || self
                .state
                .unverifiable_placeholder_closes
                .load(Ordering::Acquire)
                != 0
        {
            return Err(cloud());
        }
        self.root.verify_identity(true).map_err(|_| cloud())?;
        self.root.verify_registered().map_err(|_| cloud())?;
        let activity = self.state.activity.try_lock().map_err(|_| cloud())?;
        if activity.active_fetches != 0 || activity.staged_fetches != 0 {
            return Err(cloud());
        }
        drop(activity);
        let leaf = self.leaf.as_ref().ok_or_else(cloud)?;
        let now = root_snapshot(leaf.0).map_err(|_| cloud())?;
        if now.identity != self.snapshot.identity
            || now.identity.volume_serial != self.ticket.key.volume
            || now.identity.file_index != self.ticket.key.file
            || now.file_size != self.ticket.size
            || now.last_write_time != self.snapshot.last_write_time
            || now.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0
            || now.placeholder_state & CF_PLACEHOLDER_STATE_PLACEHOLDER == 0
            || now.placeholder_state & CF_PLACEHOLDER_STATE_IN_SYNC == 0
            || native_namespace_directory::opaque_directory_identity(leaf.0).map_err(|_| cloud())?
                != self.ticket.key.identity
            || modified_ranges_for_handle(leaf.0).map_err(|_| cloud())?
        {
            return Err(cloud());
        }
        let final_path = final_path_for_handle(leaf.0).map_err(|_| cloud())?;
        let root_final = final_path_for_handle(self.root.root_handle().map_err(|_| cloud())?)
            .map_err(|_| cloud())?;
        if !windows_paths_equal(&final_path, &self.ticket.path)
            && !windows_paths_equal(
                &final_path,
                &root_final.join(
                    self.ticket
                        .path
                        .strip_prefix(&self.root.path)
                        .map_err(|_| cloud())?,
                ),
            )
        {
            return Err(cloud());
        }
        if root_snapshot(self.parent.0)
            .map_err(|_| cloud())?
            .identity
            .file_index
            != self.source.local.parent.local_file.file_index
        {
            return Err(cloud());
        }
        if self
            .state
            .recovery
            .as_ref()
            .ok_or_else(cloud)?
            .has_unresolved_content_authenticated_legacy()
            .map_err(|_| cloud())?
        {
            return Err(cloud());
        }
        Ok(())
    }
}
impl FileDeleteLocal for Local<'_, '_> {
    fn observe_clean(
        &mut self,
        _: &NamespaceIntent,
    ) -> Result<FileDeleteLocalObservation, CloudError> {
        self.check()?;
        Ok(FileDeleteLocalObservation {
            source: self.source.clone(),
            ancestry: StorageClassification::Ordinary,
            dirty: false,
            pending: false,
        })
    }
    fn record_completion<F>(
        &mut self,
        _: &NamespaceIntent,
        readback: &FileDeleteReadback,
        record: F,
    ) -> Result<(), FileDeleteCompletionError>
    where
        F: FnOnce() -> Result<(), crate::streamed_store::StoreError>,
    {
        if readback.source() != &self.source || self.check().is_err() {
            return Err(FileDeleteCompletionError::Unavailable);
        }
        // Coordinator has durably appended RemoteDeleted before this method.
        self.acknowledged = true;
        if !ack_once(self.shared, self.ticket, true) {
            return Err(FileDeleteCompletionError::Uncertain);
        }
        self.leaf.take(); // Permit last-close deletion; retain root/ancestor pins.
        loop {
            if !self.shared.live(self.ticket) {
                return Err(FileDeleteCompletionError::Uncertain);
            }
            let mut inner = self
                .shared
                .inner
                .lock()
                .map_err(|_| FileDeleteCompletionError::Uncertain)?;
            let Some(slot) = inner
                .slot
                .as_mut()
                .filter(|slot| slot.ticket.key == self.ticket.key)
            else {
                return Err(FileDeleteCompletionError::Uncertain);
            };
            if slot.ack_success && slot.completed {
                let closes = std::mem::take(&mut slot.deferred);
                drop(inner);
                if closes
                    .into_iter()
                    .any(|close| !close.finish_after_owned_completion())
                    || !self.admission.borrow_mut().claim_completion()
                {
                    return Err(FileDeleteCompletionError::Uncertain);
                }
                return record().map_err(FileDeleteCompletionError::Store);
            }
            let (guard, _) = self
                .shared
                .changed
                .wait_timeout(inner, Duration::from_millis(20))
                .map_err(|_| FileDeleteCompletionError::Uncertain)?;
            drop(guard);
        }
    }
}
fn ack_once(shared: &Shared, ticket: &Ticket, success: bool) -> bool {
    if success && !shared.live(ticket) {
        return false;
    }
    {
        let Ok(mut inner) = shared.inner.lock() else {
            return false;
        };
        let Some(slot) = inner
            .slot
            .as_mut()
            .filter(|slot| slot.ticket.key == ticket.key)
        else {
            return false;
        };
        if slot.ack_attempted {
            return false;
        }
        if success && (shared.closed.load(Ordering::Acquire) || Instant::now() >= ticket.deadline) {
            return false;
        }
        slot.ack_attempted = true;
    }
    let result = ack(ticket.key, success);
    if let Ok(mut inner) = shared.inner.lock()
        && let Some(slot) = inner
            .slot
            .as_mut()
            .filter(|slot| slot.ticket.key == ticket.key)
    {
        slot.ack_success = success && result;
    }
    shared.changed.notify_all();
    result
}
fn ack(key: Key, success: bool) -> bool {
    let info = CfOperationInfo {
        struct_size: size_of::<CfOperationInfo>() as u32,
        operation_type: ACK_DELETE,
        connection_key: CfConnectionKey {
            internal: key.connection,
        },
        transfer_key: CfTransferKey {
            internal: key.transfer,
        },
        correlation_vector: null(),
        sync_status: null(),
        request_key: CfRequestKey {
            internal: key.request,
        },
    };
    let mut parameters = CfOperationParameters {
        param_size: (std::mem::offset_of!(CfOperationParameters, data) + size_of::<AckDelete>())
            as u32,
        data: CfOperationParameterData {
            ack_delete: AckDelete {
                flags: 0,
                completion_status: if success {
                    STATUS_SUCCESS
                } else {
                    DELETE_REFUSED
                },
            },
        },
    };
    // All storage is owned on this stack; keys are copied from the original
    // pending callback. No callback or optional telemetry pointer is retained.
    (unsafe { CfExecute(&info, &mut parameters) }) >= 0
}
fn key(info: &CfCallbackInfo, shared: &Shared) -> Option<Key> {
    if info.connection_key.internal != shared.connection.load(Ordering::Acquire)
        || info.volume_serial_number != shared.root.volume_serial
        || info.sync_root_file_id as u64 != shared.root.file_index
        || info.file_id == 0
        || info.file_identity_length != 16
        || info.file_identity.is_null()
        || info.sync_root_identity_length != 16
        || info.sync_root_identity.is_null()
    {
        return None;
    }
    // CF owns each verified fixed-size buffer for this callback only.
    let identity: [u8; 16] =
        unsafe { std::slice::from_raw_parts(info.file_identity.cast::<u8>(), 16) }
            .try_into()
            .ok()?;
    let composite: [u8; 16] =
        unsafe { std::slice::from_raw_parts(info.sync_root_identity.cast::<u8>(), 16) }
            .try_into()
            .ok()?;
    if composite != shared.composite {
        return None;
    }
    Some(Key {
        connection: info.connection_key.internal,
        transfer: info.transfer_key.internal,
        request: info.request_key.internal,
        volume: info.volume_serial_number,
        root: info.sync_root_file_id as u64,
        file: info.file_id as u64,
        identity,
    })
}
fn path(info: &CfCallbackInfo) -> Option<PathBuf> {
    // Copy callback strings before returning; no pointer escapes this function.
    let dos = unsafe { read_bounded_wide_string(info.volume_dos_name) }.ok()?;
    let normalized = unsafe { read_bounded_wide_string(info.normalized_path) }
        .ok()?
        .replace('/', "\\");
    if dos.len() != 2 || !dos.ends_with(':') {
        return None;
    }
    let mut device = vec![0u16; 32768];
    let name = wide_literal(&dos);
    let n = unsafe { QueryDosDeviceW(name.as_ptr(), device.as_mut_ptr(), device.len() as u32) }
        as usize;
    if n == 0 || n >= device.len() {
        return None;
    }
    let end = device[..n].iter().position(|word| *word == 0)?;
    let device = String::from_utf16(&device[..end]).ok()?;
    let suffix = callback_path_suffix(&normalized, &dos, device.trim_end_matches('\\')).ok()?;
    Some(PathBuf::from(format!("{dos}{suffix}")))
}
pub(super) unsafe extern "system" fn notify(
    info: *const CfCallbackInfo,
    parameters: *const CfCallbackParameters,
) {
    let Some(guard) = callback_guard(info) else {
        return;
    };
    let shared = guard
        .0
        .delete_shared
        .lock()
        .ok()
        .and_then(|shared| shared.clone());
    let Some(shared) = shared else {
        return;
    };
    // callback_guard validated the complete info prefix. Parameters are valid
    // for this invocation; check the documented/aligned one-ULONG arm size.
    let info = unsafe { &*info };
    let Some(key) = key(info, &shared) else {
        return;
    };
    let result = catch_unwind(AssertUnwindSafe(|| {
        if parameters.is_null() {
            return false;
        }
        let parameters = unsafe { &*parameters };
        if !valid_close_completion_param_size(parameters.param_size as usize)
            || unsafe { parameters.data.delete.flags } != 0
            || info.file_size < 0
            || guard.0.readiness.load(Ordering::Acquire) != CALLBACK_READY
        {
            return false;
        }
        let Some(path) = path(info) else {
            return false;
        };
        shared.submit(Ticket {
            key,
            path,
            size: info.file_size as u64,
            deadline: Instant::now() + LIMIT,
        })
    }))
    .unwrap_or(false);
    if !result {
        let _ = ack(key, false);
    }
}
pub(super) unsafe extern "system" fn completed(
    info: *const CfCallbackInfo,
    parameters: *const CfCallbackParameters,
) {
    let Some(guard) = callback_guard(info) else {
        return;
    };
    let shared = guard
        .0
        .delete_shared
        .lock()
        .ok()
        .and_then(|shared| shared.clone());
    let Some(shared) = shared else {
        return;
    };
    let info = unsafe { &*info };
    let Some(key) = key(info, &shared) else {
        return;
    };
    if parameters.is_null() {
        return;
    }
    let parameters = unsafe { &*parameters };
    if valid_close_completion_param_size(parameters.param_size as usize)
        && unsafe { parameters.data.delete_completion.flags } == 0
    {
        shared.completion(key);
    }
}
pub(super) fn deleted_close(
    state: &Arc<CallbackState>,
    info: &CfCallbackInfo,
    permit: &mut crate::close_capture_admission::CloseCapturePermit<'_>,
) -> bool {
    let shared = state
        .delete_shared
        .lock()
        .ok()
        .and_then(|shared| shared.clone());
    let Some(shared) = shared else {
        return false;
    };
    catch_unwind(AssertUnwindSafe(|| {
        key(info, &shared).is_some_and(|key| shared.owned_deleted_close(key, permit))
    }))
    .unwrap_or(false)
}
pub(super) fn table() -> [CfCallbackRegistration; 8] {
    [
        CfCallbackRegistration {
            callback_type: CF_CALLBACK_TYPE_FETCH_DATA,
            callback: Some(fetch_data_callback),
        },
        CfCallbackRegistration {
            callback_type: CF_CALLBACK_TYPE_CANCEL_FETCH_DATA,
            callback: Some(cancel_fetch_data_callback),
        },
        CfCallbackRegistration {
            callback_type: CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS,
            callback: Some(fetch_placeholders_callback),
        },
        CfCallbackRegistration {
            callback_type: CF_CALLBACK_TYPE_CANCEL_FETCH_PLACEHOLDERS,
            callback: Some(cancel_fetch_placeholders_callback),
        },
        CfCallbackRegistration {
            callback_type: CF_CALLBACK_TYPE_NOTIFY_FILE_CLOSE_COMPLETION,
            callback: Some(notify_file_close_completion_callback),
        },
        CfCallbackRegistration {
            callback_type: NOTIFY_DELETE,
            callback: Some(notify),
        },
        CfCallbackRegistration {
            callback_type: DELETE_COMPLETION,
            callback: Some(completed),
        },
        CfCallbackRegistration {
            callback_type: CF_CALLBACK_TYPE_NONE,
            callback: None,
        },
    ]
}

#[cfg(test)]
mod drain_tests {
    use super::*;

    #[test]
    fn terminal_custody_is_checked_after_join_not_before_publication() {
        let inner = Arc::new(Mutex::new(Inner {
            slot: None,
            last: None,
            result: Some(FileDeleteOutcome::Completed),
        }));
        let gate = Arc::new(std::sync::Barrier::new(2));
        let run = inner.clone();
        let worker_gate = gate.clone();
        let worker = thread::spawn(move || {
            worker_gate.wait();
            run.lock().unwrap().result = Some(FileDeleteOutcome::Uncertain);
        });
        assert!(inner.lock().unwrap().releasable(false)); // stale pre-join fact
        gate.wait();
        worker.join().unwrap();
        assert!(!inner.lock().unwrap().releasable(false));
    }

    #[test]
    fn idle_join_can_release_but_caught_panic_never_reuses_old_success() {
        let mut inner = Inner {
            slot: None,
            last: None,
            result: None,
        };
        assert!(inner.releasable(false));
        inner.result = Some(FileDeleteOutcome::Completed);
        assert!(!inner.releasable(true));
        inner.result = Some(FileDeleteOutcome::Uncertain);
        assert!(!inner.releasable(false));
        inner.result = Some(FileDeleteOutcome::RemoteVerifiedLocalPending);
        assert!(!inner.releasable(false));
    }
}
