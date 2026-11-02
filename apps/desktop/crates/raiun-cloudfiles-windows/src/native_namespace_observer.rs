//! Owner-thread-only connected-root observation. This module issues no cloud
//! mutation, inventory adoption, placeholder conversion or clean ACK.
use super::*;
use raiun_control_windows::directory_notifications::{
    DirectoryObserver, NotificationBatch, ObserverPoll, RescanReason,
};
use std::os::windows::io::BorrowedHandle;
use std::sync::Weak;
use std::time::Duration;

const MAX_WAIT: Duration = Duration::from_millis(250);
static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(1);

fn next_instance(counter: &AtomicU64) -> Result<u64, Error> {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        let next = current
            .checked_add(1)
            .ok_or(Error::ConnectionStateInvalid)?;
        match counter.compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(instance) => return Ok(instance),
            Err(observed) => current = observed,
        }
    }
}

#[derive(Clone)]
pub(super) struct NamespaceObserverBinding {
    backend: Weak<crate::OpenCloudPlaceholderBackend>,
    composite: crate::OpaqueIdentity,
}
impl NamespaceObserverBinding {
    pub(super) fn new(
        backend: &Arc<crate::OpenCloudPlaceholderBackend>,
        composite: crate::OpaqueIdentity,
    ) -> Self {
        Self {
            backend: Arc::downgrade(backend),
            composite,
        }
    }
}
pub(super) struct NamespaceObserver {
    observer: DirectoryObserver,
    instance: u64,
}
impl OwnedConfiguredRoot {
    fn prepare_directory_observer(&self) -> Result<DirectoryObserver, Error> {
        self.verify_identity(true)?;
        self.verify_registered()?;
        let expected = raiun_control_windows::PinnedFileIdentity {
            volume_serial: self.identity.volume_serial,
            file_index: self.identity.file_index,
        };
        // SAFETY: root_handle is the final live owned RootInspectionLease
        // handle. Its borrow lasts through the same-object factory, which uses
        // a kernel path locator and verifies the distinct owned OVERLAPPED
        // handle's physical identity/type/tag without closing the borrowed one.
        // The complete no-follow root/ancestor lease stays in the connection.
        let borrowed = unsafe { BorrowedHandle::borrow_raw(self.root_handle()?) };
        #[cfg(all(test, debug_assertions, feature = "synthetic-agent-integration"))]
        let observer = if std::env::var("RAIUN_RUN_CONNECTED_OBSERVER_FIXTURE").as_deref()
            == Ok("fresh-owned-state")
            && std::env::var("RAIUN_CONNECTED_OBSERVER_FIXTURE_CHILD").as_deref() == Ok("1")
        {
            DirectoryObserver::from_borrowed_directory_diagnostic(borrowed, expected).map_err(
                |failure| {
                    eprintln!(
                        "synthetic observer construction stage={} kind={:?} native_code={:?}",
                        failure.stage(),
                        failure.kind(),
                        failure.native_code()
                    );
                    io_error(
                        "prepare connected directory observer",
                        failure.into_io_error(),
                    )
                },
            )?
        } else {
            DirectoryObserver::from_borrowed_directory(borrowed, expected)
                .map_err(|error| io_error("prepare connected directory observer", error))?
        };
        #[cfg(not(all(test, debug_assertions, feature = "synthetic-agent-integration")))]
        let observer = DirectoryObserver::from_borrowed_directory(borrowed, expected)
            .map_err(|error| io_error("prepare connected directory observer", error))?;
        self.verify_identity(true)?;
        self.verify_registered()?;
        if observer.root_identity() != expected {
            return Err(Error::ConfiguredRootChanged);
        }
        // Unarmed here: any factory/postcheck error drops no pending I/O.
        Ok(observer)
    }
}
impl ConfiguredRootConnection {
    fn namespace_observation_context(
        &self,
    ) -> Result<(crate::ConfiguredRootIdentity, crate::ProviderScope), Error> {
        if !self.connected
            || self.namespace_observation_closed
            || self.state.readiness.load(Ordering::Acquire) != CALLBACK_READY
        {
            return Err(Error::ConnectionStateInvalid);
        }
        let backend = self
            .namespace_binding
            .backend
            .upgrade()
            .ok_or(Error::ProviderUnavailable)?;
        if !backend.owns_composite_root_identity(self.namespace_binding.composite) {
            return Err(Error::ProviderUnavailable);
        }
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        let identity = crate::ConfiguredRootIdentity {
            volume_serial: root.identity.volume_serial,
            file_index: root.identity.file_index,
        };
        let recovery = self
            .state
            .recovery
            .as_ref()
            .ok_or(Error::EditRecoveryUnavailable)?;
        if recovery.root_identity() != identity
            || recovery.provider_scope() != backend.scope()
            || !backend.owns_composite_root_identity(self.namespace_binding.composite)
        {
            return Err(Error::ProviderUnavailable);
        }
        Ok((identity, backend.scope().clone()))
    }
    fn observation(
        &self,
        context: (crate::ConfiguredRootIdentity, crate::ProviderScope),
        poll: ObserverPoll,
    ) -> Result<crate::NamespaceObservation, Error> {
        let instance = self
            .namespace_observer
            .as_ref()
            .ok_or(Error::ConnectionStateInvalid)?
            .instance;
        Ok(crate::NamespaceObservation {
            root: context.0,
            provider_scope: context.1,
            instance,
            poll,
        })
    }
    pub(crate) fn attach_namespace_observer(
        &mut self,
    ) -> Result<crate::NamespaceObservation, Error> {
        if self.namespace_observer.is_some() {
            return Err(Error::ConnectionStateInvalid);
        }
        let context = self.namespace_observation_context()?;
        let observer = self
            .root
            .as_ref()
            .ok_or(Error::ConfiguredRootChanged)?
            .prepare_directory_observer()?;
        let instance = next_instance(&NEXT_INSTANCE)?;
        self.namespace_observation_context()?;
        // Publish ownership BEFORE arming so every subsequent error retains
        // all kernel storage; no local pending observer is accidentally dropped.
        self.namespace_observer = Some(NamespaceObserver { observer, instance });
        let poll = self
            .namespace_observer
            .as_mut()
            .ok_or(Error::ConnectionStateInvalid)?
            .observer
            .arm();
        if let Err(error) = self.namespace_observation_context() {
            let _ = self.stop_namespace_observer(Duration::ZERO);
            return Err(error);
        }
        if !matches!(poll, ObserverPoll::Pending) {
            let _ = self.stop_namespace_observer(Duration::ZERO);
            return Err(Error::ConnectionStateInvalid);
        }
        self.observation(context, poll)
    }
    pub(crate) fn poll_namespace_observer(
        &mut self,
        wait: Duration,
    ) -> Result<crate::NamespaceObservation, Error> {
        let context = match self.namespace_observation_context() {
            Ok(context) => context,
            Err(error) => {
                // Physical stop is deliberately unconditional on authorization.
                // Do not rearm or expose late hints from this retired binding.
                let _ = self.stop_namespace_observer(Duration::ZERO);
                return Err(error);
            }
        };
        let (instance, poll) = {
            let owner = self
                .namespace_observer
                .as_mut()
                .ok_or(Error::ConnectionStateInvalid)?;
            (owner.instance, owner.observer.poll(wait.min(MAX_WAIT)))
        };
        if let Err(error) = self.namespace_observation_context() {
            let _ = self.stop_namespace_observer(Duration::ZERO);
            return Err(error);
        }
        // Recheck the backend/token/root after the wait BEFORE any rearm.
        let poll = match poll {
            ObserverPoll::Idle => self
                .namespace_observer
                .as_mut()
                .ok_or(Error::ConnectionStateInvalid)?
                .observer
                .arm(),
            ObserverPoll::Batch(NotificationBatch::Hints(hints)) => {
                match self
                    .namespace_observer
                    .as_mut()
                    .ok_or(Error::ConnectionStateInvalid)?
                    .observer
                    .arm()
                {
                    ObserverPoll::Pending => ObserverPoll::Batch(NotificationBatch::Hints(hints)),
                    _ => ObserverPoll::Batch(NotificationBatch::RescanRequired(
                        RescanReason::RootChanged,
                    )),
                }
            }
            other => other,
        };
        if let Err(error) = self.namespace_observation_context() {
            let _ = self.stop_namespace_observer(Duration::ZERO);
            return Err(error);
        }
        if matches!(
            poll,
            ObserverPoll::Stopped | ObserverPoll::Batch(NotificationBatch::RescanRequired(_))
        ) {
            // Unknown continuity ends this instance. A failed wait/cancel can
            // still have pending I/O; stop retains the same owner in that case.
            let _ = self.stop_namespace_observer(Duration::ZERO);
            return Ok(crate::NamespaceObservation {
                root: context.0,
                provider_scope: context.1,
                instance,
                poll,
            });
        }
        self.observation(context, poll)
    }
    pub(super) fn namespace_observer_drain_pending(&self) -> bool {
        self.namespace_observer
            .as_ref()
            .is_some_and(|owner| owner.observer.has_pending_io())
    }
    pub(crate) fn stop_namespace_observer(&mut self, wait: Duration) -> Result<(), Error> {
        self.namespace_observation_closed = true;
        let Some(owner) = self.namespace_observer.as_mut() else {
            return Ok(());
        };
        let _ = owner.observer.cancel_and_drain(wait.min(MAX_WAIT));
        if owner.observer.has_pending_io() {
            return Err(Error::NamespaceObserverDrainPending);
        }
        // Actual terminal completion, not CancelIoEx success/NOT_FOUND. Drop
        // is now nonblocking and the independent root lease remains owned.
        self.namespace_observer.take();
        Ok(())
    }
}

impl ConfiguredRootConnection {
    pub(crate) fn observe_namespace_entry(
        &self,
        components: &[&str],
    ) -> Result<crate::NamespaceEntryObservation, Error> {
        if !crate::namespace_entry_observation::observation_namespace(components)
            || components.iter().any(|part| !valid_component(part))
            || components.iter().map(|part| part.len() + 1).sum::<usize>() > 32_768
        {
            return Err(Error::InvalidConfiguredRoot);
        }
        let context = self.namespace_observation_context()?;
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        let mut path = root.path.clone();
        let mut ancestors = Vec::with_capacity(components.len() - 1);
        for component in &components[..components.len() - 1] {
            path.push(component);
            let handle = open_root(
                &path,
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
            )?;
            let snapshot = root_snapshot(handle.0)?;
            if snapshot.identity.volume_serial != root.identity.volume_serial
                || snapshot.identity.file_index == 0
                || snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
                || !valid_callback_directory_snapshot(snapshot)
                || !windows_paths_equal(
                    &final_path_for_handle(handle.0).map_err(|_| Error::ConfiguredRootChanged)?,
                    &path,
                )
            {
                return Err(Error::ConfiguredRootChanged);
            }
            ancestors.push((handle, snapshot));
        }
        path.push(components.last().ok_or(Error::InvalidConfiguredRoot)?);
        let wide = wide_path(&path)?;
        // SAFETY: validated bounded path under this live registered root. Each
        // no-follow ancestor remains pinned without DELETE sharing. Metadata-only
        // BACKUP_SEMANTICS permits directories; OPEN_REPARSE_POINT never follows
        // the leaf. No data/WRITE/DELETE access or external handle is provided.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(win32_io_error("observe connected namespace entry metadata"));
        }
        let leaf = RawOwnedHandle(raw);
        let snapshot = root_snapshot(leaf.0)?;
        if snapshot.identity.volume_serial != root.identity.volume_serial
            || snapshot.identity.file_index == 0
            || !windows_paths_equal(
                &final_path_for_handle(leaf.0).map_err(|_| Error::ConfiguredRootChanged)?,
                &path,
            )
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let kind = crate::namespace_entry_observation::classify(
            snapshot.file_attributes,
            snapshot.reparse_tag,
            snapshot.placeholder_state,
            cleanup_cloud_reparse_tag(snapshot.reparse_tag),
        )
        .ok_or(Error::ConfiguredRootChanged)?;
        // Concurrent metadata changes remain unknown. No prior observation or
        // path can substitute for this exact live handle/root check.
        let mut metadata = ancestors
            .iter()
            .map(|(handle, before)| (handle, *before))
            .collect::<Vec<_>>();
        metadata.push((&leaf, snapshot));
        for (handle, before) in metadata {
            let after = root_snapshot(handle.0)?;
            if after.identity != before.identity
                || after.file_attributes != before.file_attributes
                || after.reparse_tag != before.reparse_tag
                || after.placeholder_state != before.placeholder_state
            {
                return Err(Error::ConfiguredRootChanged);
            }
        }
        if self.namespace_observation_context()? != context {
            return Err(Error::ProviderUnavailable);
        }
        Ok(crate::NamespaceEntryObservation {
            local_file: LocalFileIdentity {
                volume_serial: snapshot.identity.volume_serial,
                file_index: snapshot.identity.file_index,
            },
            kind,
            attributes: snapshot.file_attributes,
            reparse_tag: snapshot.reparse_tag,
            placeholder_state: snapshot.placeholder_state,
            byte_len: snapshot.file_size,
        })
    }

    pub(crate) fn observe_namespace_file(
        &self,
        components: &[&str],
    ) -> Result<crate::NamespaceFileObservation, Error> {
        if components.len() < 2
            || components.len() > 256
            || components.first().copied() != Some("Personal")
            || components.iter().any(|part| !valid_component(part))
            || components.iter().map(|part| part.len() + 1).sum::<usize>() > 32_768
        {
            return Err(Error::InvalidConfiguredRoot);
        }
        let context = self.namespace_observation_context()?;
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        let mut path = root.path.clone();
        let mut ancestors = Vec::with_capacity(components.len() - 1);
        for component in &components[..components.len() - 1] {
            path.push(component);
            let handle = open_root(
                &path,
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
            )?;
            let snapshot = root_snapshot(handle.0)?;
            if snapshot.identity.volume_serial != root.identity.volume_serial
                || !valid_callback_directory_snapshot(snapshot)
                || !windows_paths_equal(
                    &final_path_for_handle(handle.0).map_err(|_| Error::ConfiguredRootChanged)?,
                    &path,
                )
            {
                return Err(Error::ConfiguredRootChanged);
            }
            // No FILE_SHARE_DELETE: retain every no-follow directory handle
            // until the final file and live root have both been rechecked.
            ancestors.push(handle);
        }
        path.push(components.last().ok_or(Error::InvalidConfiguredRoot)?);
        let wide = wide_path(&path)?;
        // SAFETY: bounded validated components under the live registered root;
        // all ancestors remain pinned and disallow replacement. Open only the
        // entry itself for metadata, never its reparse target or file data.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(win32_io_error("observe connected namespace file metadata"));
        }
        let file = RawOwnedHandle(raw);
        let snapshot = root_snapshot(file.0)?;
        if snapshot.identity.volume_serial != root.identity.volume_serial
            || snapshot.identity.file_index == 0
            || snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0
            || snapshot.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
            || !cleanup_cloud_reparse_tag(snapshot.reparse_tag)
            || snapshot.placeholder_state & CF_PLACEHOLDER_STATE_PLACEHOLDER == 0
            || snapshot.placeholder_state & CF_PLACEHOLDER_STATE_SYNC_ROOT != 0
            || snapshot.placeholder_state & !0x3f != 0
            || !windows_paths_equal(
                &final_path_for_handle(file.0).map_err(|_| Error::ConfiguredRootChanged)?,
                &path,
            )
        {
            return Err(Error::ConfiguredRootChanged);
        }
        // This is a value-only observation. A subsequent rename attempt must
        // acquire its own pins and revalidate content, identity and currentness.
        if self.namespace_observation_context()? != context {
            return Err(Error::ProviderUnavailable);
        }
        Ok(crate::NamespaceFileObservation {
            local_file: LocalFileIdentity {
                volume_serial: snapshot.identity.volume_serial,
                file_index: snapshot.identity.file_index,
            },
            attributes: snapshot.file_attributes,
            reparse_tag: snapshot.reparse_tag,
            placeholder_state: snapshot.placeholder_state,
            byte_len: snapshot.file_size,
        })
    }

    /// Fixed synthetic-file metadata only, not a caller-selected path or
    /// publication/capture capability. Compiled solely with diagnostic feature.
    #[cfg(feature = "synthetic-agent-integration")]
    pub(crate) fn namespace_observer_fixture_file(
        &self,
    ) -> Result<(LocalFileIdentity, u32, u32, u64), Error> {
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        let path = root
            .path
            .join("Personal")
            .join("namespace-observer-owned.bin");
        let wide = wide_path(&path)?;
        // SAFETY: bounded fixed synthetic child, no-follow metadata-only open,
        // with exact connected-root registration checked around the operation.
        // No read, write, delete or native completion authority is returned.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(win32_io_error("inspect connected observer synthetic file"));
        }
        let handle = RawOwnedHandle(raw);
        let snapshot = root_snapshot(handle.0)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        Ok((
            LocalFileIdentity {
                volume_serial: snapshot.identity.volume_serial,
                file_index: snapshot.identity.file_index,
            },
            snapshot.file_attributes,
            snapshot.placeholder_state,
            snapshot.file_size,
        ))
    }
}

impl ConfiguredRootConnection {
    #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
    pub(crate) fn rename_public_entry_fixture_activity_source(
        &self,
    ) -> crate::RenamePublicEntryFixtureActivitySource {
        let state = Arc::downgrade(&self.state);
        Arc::new(move || {
            let state = state.upgrade()?;
            if state.readiness.load(Ordering::Acquire) != CALLBACK_READY {
                return None;
            }
            let activity = state.activity.try_lock().ok()?;
            Some(crate::RenamePublicEntryFixtureActivity {
                dirty_close_entries: state.fixture_dirty_close_entries.load(Ordering::Acquire),
                close_admission_unknown: state.close_capture_admission.fixture_admission_unknown(),
                active_callbacks: activity.active_callbacks,
                active_fetches: activity.active_fetches,
                staged_fetches: activity.staged_fetches,
                modified_closes: state.modified_placeholder_closes.load(Ordering::Acquire),
                journaled_closes: state.journaled_placeholder_closes.load(Ordering::Acquire),
                unverifiable_closes: state
                    .unverifiable_placeholder_closes
                    .load(Ordering::Acquire),
            })
        })
    }
    /// Diagnostic snapshot only; never callback/capture admission authority.
    #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
    pub(crate) fn rename_public_entry_fixture_callback_counts(
        &self,
    ) -> Option<(usize, usize, usize)> {
        if !self.connected || self.state.readiness.load(Ordering::Acquire) != CALLBACK_READY {
            return None;
        }
        let activity = self.state.activity.try_lock().ok()?;
        Some((
            activity.active_callbacks,
            activity.active_fetches,
            activity.staged_fetches,
        ))
    }
    /// Fixed R58 diagnostic metadata only. No arbitrary route/body or authority.
    #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
    pub(crate) fn rename_public_entry_fixture_observation(
        &self,
        selected: crate::RenamePublicEntryFixturePath,
    ) -> Result<crate::NamespaceDirectoryObservation, Error> {
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        let parent = root.path.join("Personal");
        let parent_handle = open_root(
            &parent,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )?;
        let parent_snapshot = root_snapshot(parent_handle.0)?;
        if parent_snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || !cleanup_cloud_reparse_tag(parent_snapshot.reparse_tag)
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let name = match selected {
            crate::RenamePublicEntryFixturePath::Source => "source.bin",
            crate::RenamePublicEntryFixturePath::Destination => "renamed.bin",
        };
        let path = parent.join(name);
        let wide = wide_path(&path)?;
        // SAFETY: fixed synthetic child under the registered root; its no-follow
        // parent remains pinned without DELETE sharing. Metadata-only access
        // opens the file itself, never its reparse target. No handle escapes.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(win32_io_error("inspect rename public-entry synthetic file"));
        }
        let file = RawOwnedHandle(raw);
        let snapshot = root_snapshot(file.0)?;
        if snapshot.identity.volume_serial != root.identity.volume_serial
            || snapshot.identity.file_index == 0
            || snapshot.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0
            || snapshot.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
            || !cleanup_cloud_reparse_tag(snapshot.reparse_tag)
            || snapshot.placeholder_state & CF_PLACEHOLDER_STATE_PLACEHOLDER == 0
            || snapshot.placeholder_state & CF_PLACEHOLDER_STATE_SYNC_ROOT != 0
            || snapshot.placeholder_state & !0x3f != 0
            || !windows_paths_equal(
                &final_path_for_handle(file.0).map_err(|_| Error::ConfiguredRootChanged)?,
                &path,
            )
        {
            return Err(Error::ConfiguredRootChanged);
        }
        let opaque = native_namespace_directory::opaque_directory_identity(file.0)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        Ok(crate::NamespaceDirectoryObservation {
            local_file: crate::LocalFileIdentity {
                volume_serial: snapshot.identity.volume_serial,
                file_index: snapshot.identity.file_index,
            },
            attributes: snapshot.file_attributes,
            reparse_tag: snapshot.reparse_tag,
            placeholder_state: snapshot.placeholder_state,
            opaque_identity: Some(opaque),
        })
    }
}

impl ConfiguredRootConnection {
    /// Fixed synthetic-only copied metadata. No body/handle/admission escapes.
    #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
    pub(crate) fn create_worker_subfolder_fixture_observation(
        &self,
    ) -> Result<
        (
            crate::NamespaceDirectoryObservation,
            crate::NamespaceDirectoryObservation,
        ),
        Error,
    > {
        let context = self.namespace_observation_context()?;
        let root = self.root.as_ref().ok_or(Error::ConfiguredRootChanged)?;
        root.verify_identity(true)?;
        root.verify_registered()?;
        let mut path = root.path.clone();
        let mut pins = Vec::with_capacity(3);
        for (index, component) in ["Personal", "Courses & CEUs #1", "source.bin"]
            .iter()
            .enumerate()
        {
            path.push(component);
            // No DELETE sharing: every no-follow ancestor remains pinned.
            let handle = if index < 2 {
                open_root(
                    &path,
                    FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                )?
            } else {
                let wide = wide_path(&path)?;
                // SAFETY: fixed synthetic source.bin under pinned no-follow
                // directories; metadata-only access opens the file itself,
                // never its reparse target. RAII keeps the handle local.
                let raw = unsafe {
                    CreateFileW(
                        wide.as_ptr(),
                        FILE_READ_ATTRIBUTES,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        null(),
                        OPEN_EXISTING,
                        FILE_FLAG_OPEN_REPARSE_POINT,
                        null_mut(),
                    )
                };
                if raw.is_null() || raw == INVALID_HANDLE_VALUE {
                    return Err(win32_io_error("inspect create-worker synthetic file"));
                }
                RawOwnedHandle(raw)
            };
            let snapshot = root_snapshot(handle.0)?;
            let kind = crate::namespace_entry_observation::classify(
                snapshot.file_attributes,
                snapshot.reparse_tag,
                snapshot.placeholder_state,
                cleanup_cloud_reparse_tag(snapshot.reparse_tag),
            );
            let expected = if index < 2 {
                crate::NamespaceEntryKind::CloudDirectory
            } else {
                crate::NamespaceEntryKind::CloudFile
            };
            if snapshot.identity.volume_serial != root.identity.volume_serial
                || snapshot.identity.file_index == 0
                || kind != Some(expected)
                || !windows_paths_equal(
                    &final_path_for_handle(handle.0).map_err(|_| Error::ConfiguredRootChanged)?,
                    &path,
                )
            {
                return Err(Error::ConfiguredRootChanged);
            }
            let opaque = native_namespace_directory::opaque_directory_identity(handle.0)?;
            pins.push((handle, snapshot, opaque, path.clone()));
        }
        for (handle, before, opaque, path) in &pins {
            let after = root_snapshot(handle.0)?;
            if after.identity != before.identity
                || after.file_attributes != before.file_attributes
                || after.reparse_tag != before.reparse_tag
                || after.placeholder_state != before.placeholder_state
                || after.file_size != before.file_size
                || native_namespace_directory::opaque_directory_identity(handle.0)? != *opaque
                || !windows_paths_equal(
                    &final_path_for_handle(handle.0).map_err(|_| Error::ConfiguredRootChanged)?,
                    path,
                )
            {
                return Err(Error::ConfiguredRootChanged);
            }
        }
        root.verify_identity(true)?;
        root.verify_registered()?;
        if self.namespace_observation_context()? != context {
            return Err(Error::ProviderUnavailable);
        }
        let copied = |index: usize| {
            let (_, snapshot, opaque, _) = &pins[index];
            crate::NamespaceDirectoryObservation {
                local_file: crate::LocalFileIdentity {
                    volume_serial: snapshot.identity.volume_serial,
                    file_index: snapshot.identity.file_index,
                },
                attributes: snapshot.file_attributes,
                reparse_tag: snapshot.reparse_tag,
                placeholder_state: snapshot.placeholder_state,
                opaque_identity: Some(*opaque),
            }
        };
        Ok((copied(1), copied(2)))
    }
}
