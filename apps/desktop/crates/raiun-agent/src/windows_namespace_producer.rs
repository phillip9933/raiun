//! Bounded ordinary mkdir producer. No hint grants mutation/deletion authority.
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

const MAX_PENDING: usize = 1024;
const MAX_HINTS_PER_TICK: usize = 64;
fn bounded_hints<T>(hints: &[T]) -> (&[T], usize) {
    let admitted = hints.len().min(MAX_HINTS_PER_TICK);
    (&hints[..admitted], hints.len() - admitted)
}
#[derive(Clone)]
struct Candidate {
    components: Vec<String>,
    expected_file: Option<(u32, u64)>,
    attempts: u8,
    ready: Instant,
    #[cfg(windows)]
    presend: Option<connected::PreSend>,
}
#[derive(Default)]
struct Candidates {
    pending: VecDeque<Candidate>,
    exhausted_paths: Vec<Vec<String>>,
    blocked_paths: Vec<Vec<String>>,
    stopped: bool,
}
impl Candidates {
    fn push(&mut self, parts: Vec<String>, file: Option<(u32, u64)>) -> bool {
        if parts.len() < 2
            || parts.len() > 256
            || parts.iter().any(|p| {
                p.is_empty()
                    || p.len() > 255
                    || matches!(p.as_str(), "." | "..")
                    || p.chars()
                        .any(|c| c.is_control() || matches!(c, '/' | '\\' | ':'))
            })
            || parts.iter().map(String::len).sum::<usize>() + parts.len() > 32768
        {
            return false;
        }
        if self.stopped {
            return false;
        }
        if self.exhausted_paths.contains(&parts) || self.blocked_paths.contains(&parts) {
            return true;
        }
        if self.pending.iter().any(|v| v.components == parts) {
            return true;
        }
        if self.pending.len() == MAX_PENDING {
            return false;
        }
        self.pending.push_back(Candidate {
            components: parts,
            expected_file: file,
            attempts: 0,
            ready: Instant::now(),
            #[cfg(windows)]
            presend: None,
        });
        true
    }
    fn take(&mut self) -> Option<Candidate> {
        let count = self.pending.len();
        for _ in 0..count {
            let item = self.pending.pop_front()?;
            if item.ready <= Instant::now() {
                return Some(item);
            }
            self.pending.push_back(item);
        }
        None
    }
    fn defer(&mut self, mut item: Candidate) -> bool {
        if item.attempts >= 2 || self.pending.len() == MAX_PENDING {
            // Periodic inventory cannot refresh an exhausted retry allowance.
            // A verified parent publication explicitly starts a new inventory.
            self.retire(item);
            return false;
        }
        item.attempts += 1;
        item.ready = Instant::now() + Duration::from_secs(1);
        self.pending.push_back(item);
        true
    }
    fn retire(&mut self, item: Candidate) {
        if self.exhausted_paths.len() < MAX_PENDING {
            self.exhausted_paths.push(item.components);
        } else {
            self.stopped = true;
        }
    }
    fn block_publication(&mut self, item: Candidate) {
        // Io/uncertain publication is not known to be pre-write. An unrelated
        // verified parent must never refresh this path's publication allowance.
        if self.blocked_paths.len() < MAX_PENDING {
            self.blocked_paths.push(item.components);
        } else {
            self.stopped = true;
        }
    }
}

#[cfg(windows)]
mod connected {
    use super::*;
    use raiun_cloudfiles_windows::{
        ConfiguredRootConnection, ConfiguredRootIdentity, EditJournalScope, NamespaceScanCursor,
        OpaqueIdentity, OpenCloudPlaceholderBackend, PlaceholderBackend,
        namespace_intent::{
            CapturedAuthorization, NamespaceAttention, NamespaceIntent, NamespaceOperation,
            NamespacePhase, NamespaceProgressSnapshot,
        },
        namespace_reconcile::{DirectoryCreateOutcome, reconcile_directory_create},
        namespace_store::{
            DirectoryIntentLease, DirectoryIntentStore, PublishedDirectoryIntent,
            StoredDirectoryIntent,
        },
        streamed_store::{StoreError, StorePolicy},
    };
    use raiun_control_windows::directory_notifications::{
        DirectoryAction, NotificationBatch, ObserverPoll,
    };
    use std::sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    };

    pub(crate) const PRODUCTION_ENABLED: bool = false;
    // Test-binary observations only. Static labels and selector presence never
    // disclose record identities, local names, paths, or error messages.
    #[cfg(test)]
    fn producer_diagnostic(stage: &'static str, selector_present: bool) {
        static COUNT: AtomicU64 = AtomicU64::new(0);
        let mut count = COUNT.load(Ordering::Relaxed);
        loop {
            if count >= 128 {
                return;
            }
            match COUNT.compare_exchange_weak(
                count,
                count + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => count = current,
            }
        }
        use std::io::Write;
        let _ = writeln!(
            std::io::stderr().lock(),
            "namespace_producer stage={stage} selector_present={selector_present}"
        );
    }
    #[cfg(test)]
    fn native_presend_error_stage(error: &raiun_cloudfiles_windows::Error) -> &'static str {
        use raiun_cloudfiles_windows::Error;
        match error {
            Error::UnsupportedPlatform => "native_presend_unsupported_platform",
            Error::Native { .. } => "native_presend_native",
            Error::Io { .. } => "native_presend_io",
            Error::SyntheticRootNotEmpty => "native_presend_synthetic_root_not_empty",
            Error::InvalidSyntheticPath => "native_presend_invalid_synthetic_path",
            Error::SyntheticRootChanged => "native_presend_synthetic_root_changed",
            Error::SyntheticCallbackFailed => "native_presend_synthetic_callback_failed",
            Error::EditRecoveryUnavailable => "native_presend_edit_recovery_unavailable",
            Error::InvalidConfiguredRoot => "native_presend_invalid_configured_root",
            Error::ConfiguredRootNotEmpty => "native_presend_configured_root_not_empty",
            Error::ConfiguredRootChanged => "native_presend_configured_root_changed",
            Error::ConnectionStateInvalid => "native_presend_connection_state_invalid",
            Error::NamespaceObserverDrainPending => "native_presend_observer_drain_pending",
            Error::ProviderUnavailable => "native_presend_provider_unavailable",
            Error::UnresolvedPlaceholderEdits => "native_presend_unresolved_placeholder_edits",
        }
    }
    macro_rules! trace_producer {
        ($stage:expr, $selector:expr) => {
            #[cfg(test)]
            producer_diagnostic($stage, $selector);
        };
    }
    /// Volatile ownership of this producer's original publication only. It is
    /// queued solely after pre-session lock Busy, never from discovered history.
    #[derive(Clone)]
    pub(super) struct PreSend {
        record: StoredDirectoryIntent,
    }
    #[derive(Debug, Eq, PartialEq)]
    enum PreSendError {
        Busy,
        Retained,
    }
    fn pristine(progress: NamespaceProgressSnapshot) -> bool {
        progress.sequence == 0
            && progress.remote == NamespacePhase::Pending
            && progress.attention.is_none()
            && !progress.local_completed
            && !progress.recorded_complete
            && progress.source_removal.is_none()
    }
    fn aliases(a: &NamespaceIntent, b: &NamespaceIntent) -> bool {
        matches!((&a.operation, &b.operation),
            (NamespaceOperation::CreateDirectory { destination: a },
             NamespaceOperation::CreateDirectory { destination: b })
            if a.local_file == b.local_file
                || (a.parent.local_file == b.parent.local_file && a.name == b.name))
    }
    fn same_fresh_intent(original: &NamespaceIntent, fresh: &NamespaceIntent) -> bool {
        fresh.schema_version == original.schema_version
            && fresh.record_generation == original.record_generation
            && fresh.operation == original.operation
    }
    impl PreSend {
        fn created(publication: &PublishedDirectoryIntent) -> Option<Self> {
            (publication.created && pristine(publication.record.progress)).then(|| Self {
                record: publication.record.clone(),
            })
        }
        fn fresh_matches(&self, fresh: &NamespaceIntent) -> bool {
            // Ignore only the store-assigned record_id in the fresh draft.
            same_fresh_intent(&self.record.intent, fresh)
        }
        fn unique_history(&self, fresh: &NamespaceIntent, prior: &[StoredDirectoryIntent]) -> bool {
            if !self.fresh_matches(fresh) {
                return false;
            }
            let mut relevant = prior.iter().filter(|r| aliases(&r.intent, fresh));
            relevant.next().is_some_and(|record| {
                record.key == self.record.key
                    && record.intent == self.record.intent
                    && record.commitment == self.record.commitment
                    && pristine(record.progress)
            }) && relevant.next().is_none()
        }
        fn acquire(
            &self,
            store: &Arc<DirectoryIntentStore>,
            fresh: &NamespaceIntent,
        ) -> Result<DirectoryIntentLease, PreSendError> {
            if !self.fresh_matches(fresh) {
                trace_producer!("acquire_fresh_mismatch", true);
                return Err(PreSendError::Retained);
            }
            let lease = store.acquire_dispatch(&self.record.key).map_err(|error| {
                if error == StoreError::Busy {
                    trace_producer!("dispatch_lease_busy", true);
                    PreSendError::Busy
                } else {
                    trace_producer!("dispatch_lease_other_error", true);
                    PreSendError::Retained
                }
            })?;
            self.check_acquired(store, fresh, lease)
        }
        fn check_acquired(
            &self,
            store: &Arc<DirectoryIntentStore>,
            fresh: &NamespaceIntent,
            lease: DirectoryIntentLease,
        ) -> Result<DirectoryIntentLease, PreSendError> {
            if lease.intent() != &self.record.intent || !pristine(lease.progress()) {
                trace_producer!("acquired_lease_not_original_pristine", true);
                return Err(PreSendError::Retained);
            }
            // Actual record lease -> short account-root quota lock. Discovery
            // authenticates staged/unknown/cross-Space history and releases its
            // quota lock before any session/HTTP. No cached Pending0 adoption.
            let prior = store.discover_account_root().map_err(|error| {
                if error == StoreError::Busy {
                    trace_producer!("leased_history_busy", true);
                    PreSendError::Busy
                } else {
                    trace_producer!("leased_history_other_error", true);
                    PreSendError::Retained
                }
            })?;
            if !self.unique_history(fresh, &prior) {
                trace_producer!("leased_history_not_unique", true);
                return Err(PreSendError::Retained);
            }
            Ok(lease)
        }
    }
    #[derive(Clone)]
    pub(crate) struct Admission {
        backend: Weak<OpenCloudPlaceholderBackend>,
        generation: Arc<AtomicU64>,
        auth: CapturedAuthorization,
        root: ConfiguredRootIdentity,
        original_cancelled: Arc<dyn Fn() -> bool + Send + Sync>,
        policy: StorePolicy,
    }
    impl Admission {
        pub(crate) fn capture(
            backend: &Arc<OpenCloudPlaceholderBackend>,
            generation: &Arc<AtomicU64>,
            expected: u64,
            root: ConfiguredRootIdentity,
            policy: impl FnOnce() -> Result<StorePolicy, String>,
        ) -> Result<Self, String> {
            // Snapshot BEFORE enqueue/wait; never refresh this epoch on resume.
            let original_cancelled = backend
                .recovery_transfer_cancellation()
                .ok_or("Directory producer cancellation is unavailable")?;
            let value = Self {
                backend: Arc::downgrade(backend),
                generation: generation.clone(),
                auth: CapturedAuthorization {
                    agent_generation: expected,
                    token_generation: backend.scope().token_generation(),
                },
                root,
                original_cancelled,
                policy: policy()?,
            };
            if !value.current(value.auth) {
                return Err("Directory producer scope changed".into());
            }
            Ok(value)
        }
        fn current(&self, auth: CapturedAuthorization) -> bool {
            auth == self.auth
                && self.auth.agent_generation != 0
                && self.generation.load(Ordering::Acquire) == self.auth.agent_generation
                && !(self.original_cancelled)()
                && self
                    .backend
                    .upgrade()
                    .is_some_and(|backend| !backend.recovery_job_revoked())
        }
    }
    #[derive(Default)]
    pub(crate) struct Controls {
        pub(crate) paused: AtomicBool,
        pub(crate) discard_hints: AtomicBool,
    }
    #[derive(Clone, Default)]
    pub(crate) struct Observation {
        pub(crate) ticks: u64,
        pub(crate) pages: u64,
        pub(crate) hints: u64,
        pub(crate) discarded_hints: u64,
        pub(crate) completed: u64,
        pub(crate) retained: u64,
        pub(crate) attention: u64,
        pub(crate) deferred: u64,
        pub(crate) retained_pre_send_deferred: u64,
        pub(crate) retained_submitted_or_uncertain: u64,
        pub(crate) continuity_lost: bool,
        pub(crate) limit_reached: bool,
    }
    pub(crate) struct Producer {
        admission: Admission,
        composite: OpaqueIdentity,
        queue: Candidates,
        cursor: Option<NamespaceScanCursor>,
        observer_attached: bool,
        observer_instance: Option<u64>,
        observer_stopped: bool,
        rescan: bool,
        next_scan: Instant,
        stores: Vec<(EditJournalScope, Arc<DirectoryIntentStore>)>,
        controls: Arc<Controls>,
        status: Arc<Mutex<Observation>>,
    }
    impl Producer {
        pub(crate) fn new(
            admission: Admission,
            composite: OpaqueIdentity,
            controls: Arc<Controls>,
            status: Arc<Mutex<Observation>>,
        ) -> Self {
            Self {
                admission,
                composite,
                queue: Candidates::default(),
                cursor: None,
                observer_attached: false,
                observer_instance: None,
                observer_stopped: false,
                rescan: true,
                next_scan: Instant::now(),
                stores: Vec::new(),
                controls,
                status,
            }
        }
        fn status(&self, update: impl FnOnce(&mut Observation)) {
            if let Ok(mut value) = self.status.lock() {
                update(&mut value);
            }
        }
        fn retained(&self, progress: NamespaceProgressSnapshot) {
            self.status(|s| {
                s.retained = s.retained.saturating_add(1);
                if progress.remote == NamespacePhase::Pending
                    && progress.attention == Some(NamespaceAttention::Deferred)
                {
                    s.retained_pre_send_deferred = s.retained_pre_send_deferred.saturating_add(1);
                } else if progress.remote == NamespacePhase::Submitted
                    || progress.attention == Some(NamespaceAttention::Uncertain)
                {
                    s.retained_submitted_or_uncertain =
                        s.retained_submitted_or_uncertain.saturating_add(1);
                }
            });
        }
        fn store(
            &mut self,
            scope: &EditJournalScope,
        ) -> Result<Arc<DirectoryIntentStore>, StoreError> {
            if let Some((_, store)) = self.stores.iter().find(|(s, _)| s == scope) {
                return Ok(store.clone());
            }
            if self.stores.len() >= 256 {
                return Err(StoreError::ScanLimit);
            }
            let store = DirectoryIntentStore::current_user(scope.clone(), self.admission.policy)?;
            self.stores.push((scope.clone(), store.clone()));
            Ok(store)
        }
        pub(crate) fn tick(
            &mut self,
            connection: &mut ConfiguredRootConnection,
            backend: &Arc<OpenCloudPlaceholderBackend>,
            root: ConfiguredRootIdentity,
        ) {
            if self.controls.paused.load(Ordering::Acquire) {
                return;
            }
            if root != self.admission.root
                || !self.admission.current(self.admission.auth)
                || !self
                    .admission
                    .backend
                    .upgrade()
                    .is_some_and(|current| Arc::ptr_eq(&current, backend))
            {
                trace_producer!(
                    "tick_admission_clear",
                    self.queue.pending.iter().any(|item| item.presend.is_some())
                );
                self.cursor = None;
                self.queue.pending.clear();
                return;
            }
            self.status(|s| s.ticks = s.ticks.saturating_add(1));
            if !self.observer_attached && !self.observer_stopped {
                match connection.attach_namespace_observer() {
                    Ok(value)
                        if value.root_identity() == root
                            && value.provider_scope() == backend.scope()
                            && value.instance() != 0 =>
                    {
                        self.observer_instance = Some(value.instance());
                        self.observer_attached = true;
                    }
                    _ => {
                        self.observer_stopped = true;
                        self.status(|s| s.continuity_lost = true);
                    }
                }
            }
            if self.observer_attached {
                match connection.poll_namespace_observer(Duration::ZERO) {
                    Ok(value)
                        if value.root_identity() == root
                            && value.provider_scope() == backend.scope()
                            && Some(value.instance()) == self.observer_instance =>
                    {
                        match value.poll() {
                            ObserverPoll::Batch(NotificationBatch::Hints(hints)) => {
                                self.status(|s| {
                                    s.hints = s.hints.saturating_add(hints.len() as u64)
                                });
                                if self.controls.discard_hints.load(Ordering::Acquire) {
                                    self.rescan = true;
                                    self.status(|s| {
                                        s.discarded_hints =
                                            s.discarded_hints.saturating_add(hints.len() as u64);
                                        s.continuity_lost = true;
                                    });
                                } else {
                                    let (bounded, discarded) = bounded_hints(hints);
                                    if discarded != 0 {
                                        self.rescan = true;
                                        self.status(|s| {
                                            s.discarded_hints =
                                                s.discarded_hints.saturating_add(discarded as u64);
                                            s.continuity_lost = true;
                                        });
                                    }
                                    for hint in bounded {
                                        match hint.action() {
                                            DirectoryAction::Added
                                            | DirectoryAction::Modified
                                            | DirectoryAction::RenamedNewName => {
                                                if !self
                                                    .queue
                                                    .push(hint.components().to_vec(), None)
                                                {
                                                    self.rescan = true;
                                                }
                                            }
                                            _ => self.rescan = true,
                                        }
                                    }
                                }
                            }
                            ObserverPoll::Batch(NotificationBatch::RescanRequired(_))
                            | ObserverPoll::Stopped => {
                                self.observer_attached = false;
                                self.observer_stopped = true;
                                self.rescan = true;
                                self.status(|s| s.continuity_lost = true);
                            }
                            _ => (),
                        }
                    }
                    _ => {
                        self.observer_attached = false;
                        self.observer_stopped = true;
                        self.rescan = true;
                        self.status(|s| s.continuity_lost = true);
                    }
                }
            }
            if self.queue.stopped {
                trace_producer!(
                    "queue_stopped_clear",
                    self.queue.pending.iter().any(|item| item.presend.is_some())
                );
                self.cursor = None;
                self.queue.pending.clear();
                self.status(|s| s.limit_reached = true);
                return;
            }
            // Exactly one candidate OR one scan page. No network inside status locks.
            if let Some(candidate) = self.queue.take() {
                self.process(candidate, connection, backend);
                return;
            }
            if self.cursor.is_none() && (self.rescan || Instant::now() >= self.next_scan) {
                match connection.begin_namespace_scan(
                    backend,
                    self.composite,
                    self.admission.auth,
                    self.admission.auth.agent_generation,
                    self.admission.policy.max_entries.min(20_000),
                ) {
                    Ok(cursor) => {
                        self.cursor = Some(cursor);
                        self.rescan = false;
                    }
                    Err(_) => {
                        self.next_scan = Instant::now() + Duration::from_secs(5);
                        self.rescan = false;
                        self.status(|s| s.attention = s.attention.saturating_add(1));
                        return;
                    }
                }
            }
            let Some(cursor) = self.cursor.as_mut() else {
                return;
            };
            match connection.advance_namespace_scan(backend, cursor) {
                Ok(page) => {
                    self.status(|s| s.pages = s.pages.saturating_add(1));
                    for candidate in page.candidates {
                        let mut parts = candidate.parent_components;
                        parts.push(candidate.name);
                        if !self.queue.push(
                            parts,
                            Some((
                                candidate.local_file.volume_serial,
                                candidate.local_file.file_index,
                            )),
                        ) {
                            self.status(|s| s.limit_reached = true);
                        }
                    }
                    if page.finished || page.limit_reached {
                        self.cursor = None;
                        self.next_scan = Instant::now() + Duration::from_secs(5);
                        if page.limit_reached {
                            self.status(|s| {
                                s.limit_reached = true;
                                s.attention = s.attention.saturating_add(1);
                            });
                        }
                    }
                }
                Err(_) => {
                    self.cursor = None;
                    self.rescan = false;
                    self.next_scan = Instant::now() + Duration::from_secs(5);
                    self.status(|s| s.attention = s.attention.saturating_add(1));
                }
            }
        }
        fn defer(&mut self, candidate: Candidate) {
            #[cfg(test)]
            let selector_present = candidate.presend.is_some();
            if self.queue.defer(candidate) {
                trace_producer!("candidate_deferred", selector_present);
                self.status(|s| s.deferred = s.deferred.saturating_add(1));
            } else {
                trace_producer!("candidate_defer_exhausted", selector_present);
                self.status(|s| s.attention = s.attention.saturating_add(1));
            }
        }
        fn process(
            &mut self,
            mut candidate: Candidate,
            connection: &ConfiguredRootConnection,
            backend: &Arc<OpenCloudPlaceholderBackend>,
        ) {
            trace_producer!("process_enter", candidate.presend.is_some());
            if !self.admission.current(self.admission.auth) {
                trace_producer!("initial_admission_stale", candidate.presend.is_some());
                return;
            }
            let admission = self.admission.clone();
            let Some((name, parents)) = candidate.components.split_last() else {
                trace_producer!("components_empty", candidate.presend.is_some());
                return;
            };
            let refs = parents.iter().map(String::as_str).collect::<Vec<_>>();
            let mut prepared = match connection.prepare_namespace_directory(
                backend,
                &refs,
                name,
                admission.auth,
                admission.auth.agent_generation,
            ) {
                Ok(value) => value,
                Err(_) => {
                    trace_producer!("prepare_error", candidate.presend.is_some());
                    if candidate.presend.is_some() {
                        trace_producer!("prepare_error_retire", true);
                        self.queue.retire(candidate);
                        self.status(|s| s.attention = s.attention.saturating_add(1));
                    } else {
                        self.defer(candidate);
                    }
                    return;
                }
            };
            let file = prepared.entry().local_file;
            if candidate
                .expected_file
                .is_some_and(|id| id != (file.volume_serial, file.file_index))
            {
                trace_producer!("expected_file_mismatch", candidate.presend.is_some());
                self.status(|s| s.attention = s.attention.saturating_add(1));
                return;
            }
            let store = match self.store(&prepared.entry().parent.scope) {
                Ok(value) => value,
                Err(StoreError::Busy) => {
                    trace_producer!("store_busy", candidate.presend.is_some());
                    self.defer(candidate);
                    return;
                }
                Err(_) => {
                    trace_producer!("store_other_error", candidate.presend.is_some());
                    self.status(|s| s.attention = s.attention.saturating_add(1));
                    return;
                }
            };
            let prior = match store.discover_account_root() {
                Ok(value) => value,
                Err(StoreError::Busy) => {
                    trace_producer!("history_busy", candidate.presend.is_some());
                    self.defer(candidate);
                    return;
                }
                Err(_) => {
                    trace_producer!("history_other_error", candidate.presend.is_some());
                    self.status(|s| s.attention = s.attention.saturating_add(1));
                    return;
                }
            };
            let fresh = prepared.intent();
            let presend = if let Some(owned) = candidate.presend.take() {
                if !owned.unique_history(&fresh, &prior) {
                    trace_producer!("owned_history_not_unique", true);
                    self.retained(owned.record.progress);
                    self.status(|s| s.attention = s.attention.saturating_add(1));
                    return;
                }
                owned
            } else {
                if let Some(record) = prior.iter().find(|record| aliases(&record.intent, &fresh)) {
                    trace_producer!("historical_alias_fence", false);
                    // Discovery, including pristine Pending0, never mints a
                    // selector. Restart and created=false keep this fence.
                    self.retained(record.progress);
                    return;
                }
                let published = match store.publish_intent(fresh.clone()) {
                    Ok(value) => value,
                    Err(StoreError::Busy) => {
                        trace_producer!("publish_busy", false);
                        // reserve-before-write Busy; next turn must rediscover.
                        self.defer(candidate);
                        return;
                    }
                    Err(_) => {
                        trace_producer!("publish_other_error_block", false);
                        // Never republish blindly after Io/uncertain publication.
                        self.queue.block_publication(candidate);
                        self.status(|s| s.attention = s.attention.saturating_add(1));
                        return;
                    }
                };
                let Some(owned) = PreSend::created(&published) else {
                    trace_producer!("publication_not_owned_pristine", false);
                    self.retained(published.record.progress);
                    return;
                };
                trace_producer!("publication_owned_pristine", true);
                owned
            };
            let mut lease = match presend.acquire(&store, &fresh) {
                Ok(value) => value,
                Err(PreSendError::Busy) => {
                    trace_producer!("owned_acquire_busy", true);
                    candidate.presend = Some(presend);
                    self.defer(candidate);
                    return;
                }
                Err(PreSendError::Retained) => {
                    trace_producer!("owned_acquire_retained", true);
                    self.status(|s| s.attention = s.attention.saturating_add(1));
                    return;
                }
            };
            let final_guard_reason = if !admission.current(admission.auth) {
                Some("final_guard_before_current_failed")
            } else if let Err(_error) = prepared.validate_presend(lease.intent()) {
                trace_producer!(native_presend_error_stage(&_error), true);
                Some("final_guard_native_validation_failed")
            } else if !admission.current(admission.auth) {
                Some("final_guard_after_current_failed")
            } else {
                None
            };
            #[cfg(test)]
            if let Some(reason) = final_guard_reason {
                producer_diagnostic("final_admission_or_native_validation_failed", true);
                producer_diagnostic(reason, true);
            }
            if final_guard_reason.is_some() {
                self.retained(lease.progress());
                self.status(|s| s.attention = s.attention.saturating_add(1));
                return;
            }
            // The selector is consumed before session entry, even if the
            // session or reconciler fails before its durable Submitted event.
            trace_producer!("session_entry_selector_consumed", false);
            let result = backend.with_directory_publication_session(
                &presend.record.intent,
                prepared.parent_identity(),
                &|auth| admission.current(auth),
                |session| {
                    trace_producer!("reconcile_enter", false);
                    let mut local = prepared.local(session);
                    reconcile_directory_create(&mut lease, session.remote(), &mut local)
                },
            );
            #[cfg(test)]
            producer_diagnostic(
                match &result {
                    Ok(Ok(DirectoryCreateOutcome::LocalCompleted)) => "result_local_completed",
                    Ok(Ok(DirectoryCreateOutcome::RemoteVerifiedLocalPending)) => {
                        "result_remote_verified_local_pending"
                    }
                    Ok(Ok(DirectoryCreateOutcome::Deferred)) => "result_deferred",
                    Ok(Ok(DirectoryCreateOutcome::Conflict)) => "result_conflict",
                    Ok(Ok(DirectoryCreateOutcome::Uncertain)) => "result_uncertain",
                    Ok(Ok(DirectoryCreateOutcome::Retained)) => "result_retained",
                    Ok(Err(_)) => "result_reconcile_store_error",
                    Err(_) => "result_session_error",
                },
                false,
            );
            match result {
                Ok(Ok(DirectoryCreateOutcome::LocalCompleted)) => {
                    self.rescan = true;
                    self.cursor = None;
                    self.queue.exhausted_paths.clear();
                    self.status(|s| s.completed = s.completed.saturating_add(1));
                }
                _ => {
                    self.retained(lease.progress());
                    self.status(|s| s.attention = s.attention.saturating_add(1));
                }
            }
        }
    }
    #[cfg(test)]
    mod admission_tests {
        use super::*;
        use raiun_cloudfiles_windows::{
            LocalFileIdentity, RemoteEditBaseline,
            namespace_intent::{
                LocalNamespaceEntry, NamespaceObjectKind, NamespaceParent, StorageClassification,
            },
        };
        use serde_json::json;
        fn draft(scope: EditJournalScope) -> NamespaceIntent {
            NamespaceIntent {
                schema_version: 1,
                record_id: "0".repeat(32),
                record_generation: 7,
                operation: NamespaceOperation::CreateDirectory {
                    destination: LocalNamespaceEntry {
                        parent: NamespaceParent {
                            local_file: LocalFileIdentity {
                                volume_serial: scope.root_volume_serial,
                                file_index: 3,
                            },
                            scope,
                            authorization: CapturedAuthorization {
                                agent_generation: 7,
                                token_generation: 2,
                            },
                            classification: StorageClassification::Ordinary,
                            local_components: vec!["Personal".into()],
                            remote: RemoteEditBaseline {
                                resource_id: "parent".into(),
                                etag: "\"etag\"".into(),
                                byte_len: 0,
                            },
                        },
                        name: "new".into(),
                        local_file: LocalFileIdentity {
                            volume_serial: 1,
                            file_index: 4,
                        },
                        object_kind: NamespaceObjectKind::Directory,
                    },
                },
            }
        }
        fn scope() -> EditJournalScope {
            EditJournalScope {
                profile_id: "synthetic".into(),
                server_origin: "https://synthetic.invalid".into(),
                account_subject: "synthetic".into(),
                space_id: "personal".into(),
                root_resource_id: "root".into(),
                root_volume_serial: 1,
                root_file_index: 2,
            }
        }
        #[test]
        fn presend_fresh_intent_ignores_only_store_assigned_record_id() {
            let original = draft(scope());
            let mut fresh = original.clone();
            fresh.record_id = "a".repeat(32);
            assert!(same_fresh_intent(&original, &fresh));
            // Mutate every captured binding independently, including ordinary
            // classification and remote metadata which must never be rebased.
            let value = serde_json::to_value(&original).unwrap();
            let mutations = [
                ("/schema_version", json!(2)),
                ("/record_generation", json!(8)),
                ("/operation/destination/name", json!("other")),
                ("/operation/destination/object_kind", json!("file")),
                ("/operation/destination/local_file/volume_serial", json!(2)),
                ("/operation/destination/local_file/file_index", json!(5)),
                (
                    "/operation/destination/parent/local_file/volume_serial",
                    json!(2),
                ),
                (
                    "/operation/destination/parent/local_file/file_index",
                    json!(5),
                ),
                (
                    "/operation/destination/parent/local_components",
                    json!(["Spaces", "other"]),
                ),
                (
                    "/operation/destination/parent/classification",
                    json!("encrypted"),
                ),
                (
                    "/operation/destination/parent/authorization/agent_generation",
                    json!(8),
                ),
                (
                    "/operation/destination/parent/authorization/token_generation",
                    json!(3),
                ),
                (
                    "/operation/destination/parent/remote/resource_id",
                    json!("other"),
                ),
                (
                    "/operation/destination/parent/remote/etag",
                    json!("\"other\""),
                ),
                ("/operation/destination/parent/remote/byte_len", json!(1)),
                (
                    "/operation/destination/parent/scope/profile_id",
                    json!("other"),
                ),
                (
                    "/operation/destination/parent/scope/server_origin",
                    json!("https://other.invalid"),
                ),
                (
                    "/operation/destination/parent/scope/account_subject",
                    json!("other"),
                ),
                (
                    "/operation/destination/parent/scope/space_id",
                    json!("other"),
                ),
                (
                    "/operation/destination/parent/scope/root_resource_id",
                    json!("other"),
                ),
                (
                    "/operation/destination/parent/scope/root_volume_serial",
                    json!(2),
                ),
                (
                    "/operation/destination/parent/scope/root_file_index",
                    json!(3),
                ),
            ];
            for (path, changed) in mutations {
                let mut input = value.clone();
                *input.pointer_mut(path).unwrap() = changed;
                let fresh = serde_json::from_value(input).unwrap();
                assert!(!same_fresh_intent(&original, &fresh), "{path}");
            }
        }
        #[test]
        fn presend_pristine_requires_every_progress_fence_and_broad_aliases() {
            let initial = NamespaceProgressSnapshot {
                local_completed: false,
                remote: NamespacePhase::Pending,
                source_removal: None,
                attention: None,
                recorded_complete: false,
                sequence: 0,
            };
            assert!(pristine(initial));
            let variants = [
                NamespaceProgressSnapshot {
                    sequence: 1,
                    ..initial
                },
                NamespaceProgressSnapshot {
                    local_completed: true,
                    ..initial
                },
                NamespaceProgressSnapshot {
                    recorded_complete: true,
                    ..initial
                },
                NamespaceProgressSnapshot {
                    source_removal: Some(NamespacePhase::Pending),
                    ..initial
                },
                NamespaceProgressSnapshot {
                    remote: NamespacePhase::Submitted,
                    ..initial
                },
                NamespaceProgressSnapshot {
                    remote: NamespacePhase::Verified,
                    ..initial
                },
                NamespaceProgressSnapshot {
                    attention: Some(NamespaceAttention::Deferred),
                    ..initial
                },
                NamespaceProgressSnapshot {
                    attention: Some(NamespaceAttention::Conflict),
                    ..initial
                },
                NamespaceProgressSnapshot {
                    attention: Some(NamespaceAttention::Uncertain),
                    ..initial
                },
            ];
            assert!(variants.into_iter().all(|value| !pristine(value)));
            let original = draft(scope());
            let mut other = original.clone();
            let NamespaceOperation::CreateDirectory { destination } = &mut other.operation else {
                unreachable!()
            };
            destination.parent.scope.space_id = "different-space".into();
            destination.parent.local_file.file_index += 10;
            destination.name = "moved".into();
            assert!(
                aliases(&original, &other),
                "same physical leaf fences cross-Space moves"
            );
            let NamespaceOperation::CreateDirectory { destination } = &mut other.operation else {
                unreachable!()
            };
            destination.local_file.file_index += 10;
            destination.parent.local_file.file_index = 3;
            destination.name = "new".into();
            assert!(
                aliases(&original, &other),
                "same parent+name fences replacement"
            );
        }
        #[test]
        #[ignore = "explicit fresh-owned private storage fixture; no Cloud Files, network, DPAPI, default state or installed app"]
        fn presend_private_store_contention_and_history_fences() {
            use raiun_cloudfiles_windows::namespace_intent::{
                NamespaceDestinationReport, NamespaceEventKind,
            };
            use raiun_cloudfiles_windows::namespace_reconcile::{
                DirectoryCompletionError, DirectoryCreateDispatch, DirectoryCreateLocal,
                DirectoryCreateReadback, DirectoryCreateRemote,
            };
            use raiun_cloudfiles_windows::{EditRecordProtector, JournalError};
            use raiun_control_windows::{PinnedDirectory, PrivateDirectory};
            use raiun_core::backend::{CloudError, ErrorKind};
            use raiun_opencloud::DirectoryCreateResponse;
            use sha2::{Digest, Sha256};
            use std::{ffi::OsStr, path::Path};
            assert_eq!(
                std::env::var("RAIUN_RUN_NAMESPACE_PRESEND").as_deref(),
                Ok("fresh-owned-state")
            );
            let root = std::path::PathBuf::from(
                std::env::var_os("RAIUN_NAMESPACE_PRESEND_ROOT")
                    .expect("explicit fresh evidence root"),
            );
            assert!(root.is_absolute());
            std::fs::create_dir(&root).expect("never reuse or overwrite a fixture root");
            struct SyntheticProtector;
            impl EditRecordProtector for SyntheticProtector {
                fn seal(&self, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, JournalError> {
                    let mut hash = Sha256::new();
                    hash.update(aad);
                    hash.update(plain);
                    let mut result = hash.finalize().to_vec();
                    result.extend_from_slice(plain);
                    Ok(result)
                }
                fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, JournalError> {
                    if sealed.len() < 32 {
                        return Err(JournalError::ProtectionFailed);
                    }
                    let mut hash = Sha256::new();
                    hash.update(aad);
                    hash.update(&sealed[32..]);
                    if hash.finalize().as_slice() != &sealed[..32] {
                        return Err(JournalError::ProtectionFailed);
                    }
                    Ok(sealed[32..].to_vec())
                }
            }
            fn store_at(
                root: &Path,
                name: &str,
            ) -> (
                Arc<PrivateDirectory>,
                Arc<DirectoryIntentStore>,
                NamespaceIntent,
            ) {
                let parent = PinnedDirectory::open(root).unwrap();
                let state = Arc::new(
                    PrivateDirectory::create_or_open_under(&parent, OsStr::new(name)).unwrap(),
                );
                let store = DirectoryIntentStore::create_or_open(
                    state.clone(),
                    scope(),
                    Arc::new(SyntheticProtector),
                    StorePolicy {
                        max_content_bytes: 32 * 1024 * 1024,
                        max_state_bytes: 64 * 1024 * 1024,
                        max_entries: 2000,
                        max_metadata_bytes_per_scan: 8 * 1024 * 1024,
                    },
                )
                .unwrap();
                (state, store, draft(scope()))
            }
            struct Remote(AtomicU64);
            impl DirectoryCreateRemote for Remote {
                fn ensure_authorized(&self, _: &NamespaceIntent) -> Result<(), CloudError> {
                    Ok(())
                }
                fn preflight(&self, _: &NamespaceIntent) -> Result<(), CloudError> {
                    Ok(())
                }
                fn create(
                    &self,
                    _: &DirectoryCreateDispatch<'_>,
                ) -> Result<DirectoryCreateResponse, CloudError> {
                    self.0.fetch_add(1, Ordering::AcqRel);
                    Ok(DirectoryCreateResponse::Uncertain(CloudError::new(
                        ErrorKind::Offline,
                        "synthetic uncertain send",
                    )))
                }
                fn observe(
                    &self,
                    _: &NamespaceIntent,
                ) -> Result<NamespaceDestinationReport, CloudError> {
                    panic!("no readback after uncertainty")
                }
            }
            struct Local;
            impl DirectoryCreateLocal for Local {
                fn admit(&mut self, _: &NamespaceIntent) -> Result<(), CloudError> {
                    Ok(())
                }
                fn publish(
                    &mut self,
                    _: &NamespaceIntent,
                    _: &DirectoryCreateReadback,
                ) -> Result<(), CloudError> {
                    panic!("no native publication")
                }
                fn record_completion<F>(
                    &mut self,
                    _: &NamespaceIntent,
                    _: &DirectoryCreateReadback,
                    _: F,
                ) -> Result<(), DirectoryCompletionError>
                where
                    F: FnOnce() -> Result<(), StoreError>,
                {
                    panic!("no native completion")
                }
            }
            let mut receipts = Vec::new();
            for kind in ["quota-busy", "record-busy", "history-quota-busy"] {
                let (state, store, fresh) = store_at(&root, kind);
                let published = store.publish_intent(fresh.clone()).unwrap();
                let owned = PreSend::created(&published).unwrap();
                let duplicate = store.publish_intent(fresh.clone()).unwrap();
                assert!(!duplicate.created && PreSend::created(&duplicate).is_none());
                let parent = PinnedDirectory::open(state.path()).unwrap();
                let v2 = Arc::new(
                    PrivateDirectory::open_under(
                        &parent,
                        OsStr::new("cloud-files-edit-journal-v2"),
                    )
                    .unwrap(),
                );
                let mut quota = None;
                let mut record = None;
                let first = if kind == "history-quota-busy" {
                    // Hold the actual record lease before introducing quota
                    // contention at the authenticated under-lease history scan.
                    let lease = store.acquire_dispatch(&published.record.key).unwrap();
                    let mut lock = v2
                        .open_owned_immutable_file(OsStr::new("quota.lock"))
                        .unwrap();
                    lock.try_lock_exclusive().unwrap();
                    quota = Some(lock);
                    owned.check_acquired(&store, &fresh, lease)
                } else if kind == "quota-busy" {
                    let mut lock = v2
                        .open_owned_immutable_file(OsStr::new("quota.lock"))
                        .unwrap();
                    lock.try_lock_exclusive().unwrap();
                    quota = Some(lock);
                    owned.acquire(&store, &fresh)
                } else {
                    record = Some(store.acquire_dispatch(&published.record.key).unwrap());
                    owned.acquire(&store, &fresh)
                };
                assert!(matches!(first, Err(PreSendError::Busy)));
                let mut queue = Candidates::default();
                let candidate = Candidate {
                    components: vec!["Personal".into(), "new".into()],
                    expected_file: Some((1, 4)),
                    attempts: 0,
                    ready: Instant::now(),
                    presend: Some(owned.clone()),
                };
                assert!(queue.defer(candidate));
                drop(record);
                drop(quota);
                queue.pending.front_mut().unwrap().ready = Instant::now();
                let mut candidate = queue.take().unwrap();
                assert_eq!(candidate.attempts, 1);
                let resumed = candidate.presend.take().unwrap();
                let mut lease = resumed.acquire(&store, &fresh).unwrap();
                assert!(lease.intent() == &published.record.intent);
                let remote = Remote(AtomicU64::new(0));
                assert_eq!(
                    reconcile_directory_create(&mut lease, &remote, &mut Local).unwrap(),
                    DirectoryCreateOutcome::Uncertain
                );
                drop(lease);
                assert!(matches!(
                    resumed.acquire(&store, &fresh),
                    Err(PreSendError::Retained)
                ));
                let records = store.discover_account_root().unwrap();
                assert_eq!(records.len(), 1);
                assert!(
                    records[0].key == published.record.key
                        && records[0].intent == published.record.intent
                );
                assert_eq!(remote.0.load(Ordering::Acquire), 1);
                receipts.push(json!({"case":kind,"intent_count":records.len(),"same_original_key_intent":true,"simulated_remote_callbacks":1,"uncertain_history_not_replayed":true}));
            }
            for (name, event) in [
                ("submitted", NamespaceEventKind::RemoteSubmitted),
                ("deferred", NamespaceEventKind::Deferred),
                ("conflict", NamespaceEventKind::Conflict),
            ] {
                let (_, store, fresh) = store_at(&root, name);
                let published = store.publish_intent(fresh.clone()).unwrap();
                let owned = PreSend::created(&published).unwrap();
                let mut contender = store.acquire_dispatch(&published.record.key).unwrap();
                contender.append_event(event).unwrap();
                drop(contender);
                assert!(matches!(
                    owned.acquire(&store, &fresh),
                    Err(PreSendError::Retained)
                ));
                receipts.push(
                    json!({"case":name,"continuation_refused":true,"simulated_remote_callbacks":0}),
                );
            }
            let (state, store, fresh) = store_at(&root, "duplicate-space");
            let published = store.publish_intent(fresh.clone()).unwrap();
            let owned = PreSend::created(&published).unwrap();
            let mut changed = owned.clone();
            changed.record.commitment[0] ^= 1;
            assert!(matches!(
                changed.acquire(&store, &fresh),
                Err(PreSendError::Retained)
            ));
            let mut other_scope = scope();
            other_scope.space_id = "other-space".into();
            other_scope.root_resource_id = "other-root".into();
            let other = DirectoryIntentStore::create_or_open(
                state,
                other_scope.clone(),
                Arc::new(SyntheticProtector),
                StorePolicy {
                    max_content_bytes: 32 * 1024 * 1024,
                    max_state_bytes: 64 * 1024 * 1024,
                    max_entries: 2000,
                    max_metadata_bytes_per_scan: 8 * 1024 * 1024,
                },
            )
            .unwrap();
            other.publish_intent(draft(other_scope)).unwrap();
            assert!(matches!(
                owned.acquire(&store, &fresh),
                Err(PreSendError::Retained)
            ));
            receipts.push(json!({"case":"commitment-and-cross-space-alias","continuation_refused":true,"simulated_remote_callbacks":0}));
            let (state, store, fresh) = store_at(&root, "staged-evidence");
            let published = store.publish_intent(fresh.clone()).unwrap();
            let owned = PreSend::created(&published).unwrap();
            let namespace_path = state
                .path()
                .join("cloud-files-edit-journal-v2")
                .join("namespace-v1");
            let folders = std::fs::read_dir(&namespace_path)
                .unwrap()
                .map(|entry| entry.unwrap())
                .filter(|entry| entry.file_type().unwrap().is_dir())
                .collect::<Vec<_>>();
            assert_eq!(folders.len(), 1);
            let parent = PinnedDirectory::open(&namespace_path).unwrap();
            let directory = PrivateDirectory::open_under(&parent, &folders[0].file_name()).unwrap();
            let stage = format!(
                "{}.event.{:020}.stage",
                published.record.intent.record_id, 1
            );
            let (mut file, _) = directory.create_new_file(OsStr::new(&stage)).unwrap();
            use std::io::Write;
            file.write_all(b"synthetic-partial-event").unwrap();
            file.sync_all().unwrap();
            drop(file);
            assert!(matches!(
                owned.acquire(&store, &fresh),
                Err(PreSendError::Retained)
            ));
            assert_eq!(
                std::fs::read(directory.path().join(stage)).unwrap(),
                b"synthetic-partial-event"
            );
            receipts.push(json!({"case":"staged-evidence","continuation_refused":true,"stage_preserved":true,"simulated_remote_callbacks":0}));
            let (_, store, fresh) = store_at(&root, "bounded-busy");
            let owned = PreSend::created(&store.publish_intent(fresh).unwrap()).unwrap();
            let mut queue = Candidates::default();
            queue.push(vec!["Personal".into(), "new".into()], Some((1, 4)));
            let mut item = queue.take().unwrap();
            item.presend = Some(owned);
            for _ in 0..2 {
                assert!(queue.defer(item));
                queue.pending.front_mut().unwrap().ready = Instant::now();
                item = queue.take().unwrap();
                assert!(item.presend.is_some());
            }
            assert!(!queue.defer(item));
            assert!(queue.push(vec!["Personal".into(), "new".into()], Some((1, 4))));
            assert!(queue.take().is_none());
            receipts.push(json!({"case":"bounded-busy","deferrals":2,"selector_dropped_on_exhaustion":true,"inventory_does_not_refresh_budget":true}));
            let report = json!({"scope":"fresh-owned private storage and mock reconciliation only; no Cloud Files/network/DPAPI/default state","cases":receipts,"evidence_retained":true,"cleanup_performed":false});
            std::fs::write(
                root.join("RESULTS.json"),
                serde_json::to_vec_pretty(&report).unwrap(),
            )
            .unwrap();
        }
        fn fixture() -> (
            Arc<OpenCloudPlaceholderBackend>,
            Arc<AtomicU64>,
            raiun_opencloud::transfer_budget::TransferBudget,
        ) {
            let client = Arc::new(
                raiun_opencloud::OpenCloudClient::new(
                    "https://fixture.invalid",
                    "synthetic-token".into(),
                )
                .unwrap(),
            );
            let budget = client.transfer_budget();
            let scope = raiun_cloudfiles_windows::ProviderScope::new(
                &client,
                "default".into(),
                "synthetic-account".into(),
                "https://fixture.invalid".into(),
            )
            .unwrap();
            (
                Arc::new(OpenCloudPlaceholderBackend::new(client, scope).unwrap()),
                Arc::new(AtomicU64::new(7)),
                budget,
            )
        }
        fn policy() -> Result<StorePolicy, String> {
            Ok(StorePolicy {
                max_content_bytes: 1024 * 1024,
                max_state_bytes: 16 * 1024 * 1024,
                max_entries: 64,
                max_metadata_bytes_per_scan: 1024 * 1024,
            })
        }
        fn root() -> ConfiguredRootIdentity {
            ConfiguredRootIdentity {
                volume_serial: 1,
                file_index: 2,
            }
        }
        #[test]
        fn original_cancellation_epoch_precedes_policy_wait_and_cannot_resume() {
            let (backend, generation, budget) = fixture();
            let result = Admission::capture(&backend, &generation, 7, root(), || {
                budget.set_paused(true);
                budget.cancel_waiters();
                budget.set_paused(false);
                policy()
            });
            assert!(result.is_err());
        }
        #[test]
        fn owner_generation_revocation_is_atomic_and_old_admission_stays_revoked() {
            let (backend, generation, _) = fixture();
            let admission = Admission::capture(&backend, &generation, 7, root(), policy).unwrap();
            assert!(admission.current(admission.auth));
            generation.store(8, Ordering::Release);
            assert!(!admission.current(admission.auth));
            assert!(Admission::capture(&backend, &generation, 7, root(), policy).is_err());
        }
    }
}
#[cfg(windows)]
pub(crate) use connected::*;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn uncertain_publication_is_not_refreshed_by_unrelated_parent_completion() {
        let mut queue = Candidates::default();
        queue.push(vec!["Personal".into(), "uncertain".into()], None);
        let item = queue.take().unwrap();
        queue.block_publication(item);
        queue.exhausted_paths.clear();
        assert!(queue.push(vec!["Personal".into(), "uncertain".into()], None));
        assert!(queue.take().is_none());
        assert!(queue.push(vec!["Personal".into(), "independent".into()], None));
        assert_eq!(queue.take().unwrap().components[1], "independent");
    }
    #[test]
    fn hint_prefix_is_bounded_and_reports_every_discarded_hint() {
        for count in [0, 63, 64, 65, 1024] {
            let hints = (0..count).collect::<Vec<_>>();
            let (prefix, discarded) = bounded_hints(&hints);
            assert_eq!(prefix.len(), count.min(64));
            assert_eq!(discarded, count.saturating_sub(64));
            assert_eq!(prefix, &hints[..count.min(64)]);
            assert_eq!(prefix.len() + discarded, hints.len());
        }
    }
    #[test]
    fn queue_is_bounded_deduplicates_and_never_admits_root_or_traversal() {
        let mut q = Candidates::default();
        assert!(!q.push(vec!["Personal".into()], None));
        assert!(!q.push(vec!["Personal".into(), "..".into()], None));
        for n in 0..MAX_PENDING {
            assert!(q.push(vec!["Personal".into(), n.to_string()], None));
        }
        assert!(q.push(vec!["Personal".into(), "0".into()], None));
        assert!(!q.push(vec!["Personal".into(), "extra".into()], None));
        assert_eq!(q.pending.len(), MAX_PENDING);
        let first = q.take().unwrap();
        assert_eq!(first.components[1], "0");
    }
    #[test]
    fn not_ready_retry_does_not_starve_an_independent_candidate() {
        let mut q = Candidates::default();
        assert!(q.push(vec!["Personal".into(), "busy".into()], None));
        let busy = q.take().unwrap();
        assert!(q.defer(busy));
        assert!(q.push(vec!["Space".into(), "ready".into()], Some((1, 3))));
        assert_eq!(q.take().unwrap().components[1], "ready");
        assert!(q.take().is_none());
    }
    #[test]
    fn exhausted_retry_inventory_has_a_finite_failclosed_capacity() {
        let mut q = Candidates::default();
        for n in 0..=MAX_PENDING {
            let item = Candidate {
                components: vec!["Personal".into(), n.to_string()],
                expected_file: None,
                attempts: 2,
                ready: Instant::now(),
                #[cfg(windows)]
                presend: None,
            };
            assert!(!q.defer(item));
        }
        assert_eq!(q.exhausted_paths.len(), MAX_PENDING);
        assert!(q.stopped);
        assert!(!q.push(vec!["Personal".into(), "new".into()], None));
    }
    #[cfg(all(windows, debug_assertions))]
    #[test]
    fn manager_producer_opt_in_is_private_and_defaults_off() {
        let manager = super::super::ProviderManager::new();
        assert!(!std::hint::black_box(PRODUCTION_ENABLED));
        assert!(
            !manager
                .namespace_test_activation
                .load(std::sync::atomic::Ordering::Acquire)
        );
        assert!(
            !manager
                .namespace_controls
                .paused
                .load(std::sync::atomic::Ordering::Acquire)
        );
        assert!(
            !manager
                .namespace_controls
                .discard_hints
                .load(std::sync::atomic::Ordering::Acquire)
        );
        assert_eq!(manager.namespace_status.lock().unwrap().ticks, 0);
    }
    #[test]
    fn volatile_retry_is_finite_and_retains_physical_expectation() {
        let mut q = Candidates::default();
        q.push(vec!["Personal".into(), "new".into()], Some((1, 2)));
        let mut item = q.take().unwrap();
        assert_eq!(item.expected_file, Some((1, 2)));
        item.attempts = 2;
        assert!(!q.defer(item));
        assert!(q.pending.is_empty());
        assert!(q.push(vec!["Personal".into(), "new".into()], Some((1, 2))));
        assert!(q.take().is_none(), "rescan cannot refresh retry allowance");
    }
}
