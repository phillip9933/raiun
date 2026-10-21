//! Bounded, scope-bound jobs for retrying durable encrypted file edits.
//!
//! These jobs never unlock a vault or load credentials. The caller must build
//! an online backend for an already-unlocked exact scope. Remote work shares
//! the per-profile gate with encrypted pin/refresh jobs.

use crate::vault_pin_jobs::VaultPinJobs;
use raiun_opencloud::vault_cache::VaultPendingEditMetadata;
use raiun_vault::session::VaultSessionScope;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const MAX_RETAINED_JOBS: usize = 32;
const MAX_BATCH: usize = 32;
const MAX_AUTO_RETRY_SCOPES: usize = 128;
const AUTO_RETRY_COOLDOWN: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Debug)]
pub(super) struct VaultEditReconcileReport {
    pub processed: u64,
    pub uploaded: u64,
    pub conflicts: u64,
    pub remaining: u64,
}

pub(super) enum ReconcileFailure {
    Conflict,
    Stop(Option<VaultEditFailureClass>),
}

#[derive(Clone, Debug, serde::Serialize)]
pub(super) struct VaultEditReconcileStatus {
    #[serde(skip_serializing)]
    pub(super) generation: u64,
    pub job_id: String,
    pub space_id: String,
    pub root_resource_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_revision: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_generation: Option<u64>,
    pub automatic: bool,
    pub state: String,
    pub processed: u64,
    pub uploaded: u64,
    pub conflicts: u64,
    pub remaining: u64,
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_class: Option<VaultEditFailureClass>,
    pub cancel_requested: bool,
}

#[derive(Clone, Copy, Debug, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum VaultEditFailureClass {
    TransportUnavailable,
    AuthenticationRequired,
    CopyNeedsReview(CopyVerifyReviewReason),
}

#[derive(Clone, Copy, Debug, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum CopyVerifyReviewReason {
    LegacyBindingUnavailable,
    NeverAttempted,
    SourceScopeMismatch,
    SourceChanged,
    DestinationChanged,
    ContentMismatch,
    AuthenticationGenerationChanged,
    VerificationUnavailable,
}

pub(super) fn reconcile_failure_class(
    kind: raiun_core::backend::ErrorKind,
) -> Option<VaultEditFailureClass> {
    match kind {
        raiun_core::backend::ErrorKind::Offline => {
            Some(VaultEditFailureClass::TransportUnavailable)
        }
        raiun_core::backend::ErrorKind::Unauthorized => {
            Some(VaultEditFailureClass::AuthenticationRequired)
        }
        _ => None,
    }
}

pub(super) fn interrupted_create_failure_class(
    kind: raiun_core::backend::ErrorKind,
) -> Option<VaultEditFailureClass> {
    // Do not infer more specific causes from Conflict, NotFound, or Io: this
    // API can surface each from multiple verification stages.
    reconcile_failure_class(kind)
}

#[derive(Clone, Debug)]
pub(super) struct VaultEditJobFailure {
    message: String,
    failure_class: Option<VaultEditFailureClass>,
}

impl VaultEditJobFailure {
    pub fn unclassified(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            failure_class: None,
        }
    }

    pub fn classified(message: impl Into<String>, failure_class: VaultEditFailureClass) -> Self {
        Self {
            message: message.into(),
            failure_class: Some(failure_class),
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct VaultEditOperationBinding {
    pub operation: String,
    pub write_id: String,
    pub revision: u64,
    pub retry_generation: Option<u64>,
}

struct Job {
    scope_key: String,
    related_scope_keys: Vec<String>,
    related_space_ids: Vec<String>,
    status: Mutex<VaultEditReconcileStatus>,
    cancelled: AtomicBool,
    changed: Condvar,
}

pub(super) struct CopyVerificationJobSpec<'a> {
    pub destination: &'a VaultSessionScope,
    pub source: Option<&'a VaultSessionScope>,
    pub auth_generation: Arc<AtomicU64>,
    pub expected_generation: u64,
    pub pin_jobs: Arc<VaultPinJobs>,
    pub binding: VaultEditOperationBinding,
}

pub(super) struct CopyProducerJobSpec<'a> {
    pub destination: &'a VaultSessionScope,
    pub source: &'a VaultSessionScope,
    pub auth_generation: Arc<AtomicU64>,
    pub expected_generation: u64,
    pub pin_jobs: Arc<VaultPinJobs>,
    /// Runtime admission barrier. The caller releases this only after it drops
    /// the sync gate protecting both scopes.
    pub start_gate: std::sync::mpsc::Receiver<()>,
}

#[derive(Default)]
struct Store {
    jobs: HashMap<String, Arc<Job>>,
    order: VecDeque<String>,
    last_auto_attempt: HashMap<String, Instant>,
}

/// One bounded registry belongs to one Runtime/profile.
#[derive(Default)]
pub(super) struct VaultEditReconcileJobs {
    store: Mutex<Store>,
    next_id: AtomicU64,
}

impl VaultEditReconcileJobs {
    /// Cheap, non-mutating scheduler check. It avoids cache/session work when
    /// the scope is cooling down or another reconciliation is already active;
    /// `start` remains the authoritative atomic admission check.
    pub fn automatic_due(&self, scope: &VaultSessionScope) -> Result<bool, String> {
        let mut store = self
            .store
            .lock()
            .map_err(|_| "Encrypted edit job registry is poisoned")?;
        prune_finished(&mut store);
        if store
            .jobs
            .values()
            .any(|job| job.status.lock().map(|s| active(&s.state)).unwrap_or(true))
        {
            return Ok(false);
        }
        store
            .last_auto_attempt
            .retain(|_, at| at.elapsed() < AUTO_RETRY_COOLDOWN * 2);
        let key = scope_key(scope);
        if store
            .last_auto_attempt
            .get(&key)
            .is_some_and(|at| at.elapsed() < AUTO_RETRY_COOLDOWN)
        {
            return Ok(false);
        }
        if !store.last_auto_attempt.contains_key(&key)
            && store.last_auto_attempt.len() >= MAX_AUTO_RETRY_SCOPES
        {
            return Ok(false);
        }
        Ok(true)
    }

    #[cfg(test)]
    pub fn start(
        this: &Arc<Self>,
        scope: &VaultSessionScope,
        auth_generation: Arc<AtomicU64>,
        expected_generation: u64,
        pin_jobs: Arc<VaultPinJobs>,
        automatic: bool,
        operation: impl FnOnce(
            &AtomicBool,
            &mut dyn FnMut(u64, u64, u64, u64),
        ) -> Result<VaultEditReconcileReport, String>
        + Send
        + 'static,
    ) -> Result<VaultEditReconcileStatus, String> {
        Self::start_inner(
            this,
            scope,
            auth_generation,
            expected_generation,
            pin_jobs,
            automatic,
            None,
            Arc::new(Mutex::new(None)),
            Vec::new(),
            Vec::new(),
            operation,
        )
    }

    #[cfg(test)]
    pub fn start_operation(
        this: &Arc<Self>,
        scope: &VaultSessionScope,
        auth_generation: Arc<AtomicU64>,
        expected_generation: u64,
        pin_jobs: Arc<VaultPinJobs>,
        binding: VaultEditOperationBinding,
        operation: impl FnOnce(
            &AtomicBool,
            &mut dyn FnMut(u64, u64, u64, u64),
        ) -> Result<VaultEditReconcileReport, String>
        + Send
        + 'static,
    ) -> Result<VaultEditReconcileStatus, String> {
        Self::start_inner(
            this,
            scope,
            auth_generation,
            expected_generation,
            pin_jobs,
            false,
            Some(binding),
            Arc::new(Mutex::new(None)),
            Vec::new(),
            Vec::new(),
            operation,
        )
    }

    pub fn start_operation_with_failure_class(
        this: &Arc<Self>,
        scope: &VaultSessionScope,
        auth_generation: Arc<AtomicU64>,
        expected_generation: u64,
        pin_jobs: Arc<VaultPinJobs>,
        binding: VaultEditOperationBinding,
        operation: impl FnOnce(
            &AtomicBool,
            &mut dyn FnMut(u64, u64, u64, u64),
        ) -> Result<VaultEditReconcileReport, VaultEditJobFailure>
        + Send
        + 'static,
    ) -> Result<VaultEditReconcileStatus, String> {
        let failure_class = Arc::new(Mutex::new(None));
        let worker_failure_class = Arc::clone(&failure_class);
        Self::start_inner(
            this,
            scope,
            auth_generation,
            expected_generation,
            pin_jobs,
            false,
            Some(binding),
            failure_class,
            Vec::new(),
            Vec::new(),
            move |cancelled, progress| {
                operation(cancelled, progress).map_err(|error| {
                    if let Ok(mut slot) = worker_failure_class.lock() {
                        *slot = error.failure_class;
                    }
                    error.message
                })
            },
        )
    }

    pub fn start_with_failure_class(
        this: &Arc<Self>,
        scope: &VaultSessionScope,
        auth_generation: Arc<AtomicU64>,
        expected_generation: u64,
        pin_jobs: Arc<VaultPinJobs>,
        automatic: bool,
        operation: impl FnOnce(
            &AtomicBool,
            &mut dyn FnMut(u64, u64, u64, u64),
        ) -> Result<VaultEditReconcileReport, VaultEditJobFailure>
        + Send
        + 'static,
    ) -> Result<VaultEditReconcileStatus, String> {
        let failure_class = Arc::new(Mutex::new(None));
        let worker_failure_class = Arc::clone(&failure_class);
        Self::start_inner(
            this,
            scope,
            auth_generation,
            expected_generation,
            pin_jobs,
            automatic,
            None,
            failure_class,
            Vec::new(),
            Vec::new(),
            move |cancelled, progress| {
                operation(cancelled, progress).map_err(|error| {
                    if let Ok(mut slot) = worker_failure_class.lock() {
                        *slot = error.failure_class;
                    }
                    error.message
                })
            },
        )
    }

    /// Start a verification job invalidated by lock of either exact scope.
    /// The destination remains the caller-visible job scope; source routing
    /// metadata is retained only in this in-memory cancellation registry.
    pub fn start_copy_verification(
        this: &Arc<Self>,
        spec: CopyVerificationJobSpec<'_>,
        operation: impl FnOnce(
            &AtomicBool,
            &mut dyn FnMut(u64, u64, u64, u64),
        ) -> Result<VaultEditReconcileReport, VaultEditJobFailure>
        + Send
        + 'static,
    ) -> Result<VaultEditReconcileStatus, String> {
        if spec.source.is_some_and(|source| spec.destination == source) {
            return Err("Copy verification requires two distinct vault scopes".into());
        }
        let failure_class = Arc::new(Mutex::new(None));
        let worker_failure_class = Arc::clone(&failure_class);
        Self::start_inner(
            this,
            spec.destination,
            spec.auth_generation,
            spec.expected_generation,
            spec.pin_jobs,
            false,
            Some(spec.binding),
            failure_class,
            spec.source.map(scope_key).into_iter().collect(),
            spec.source
                .map(|source| source.space_id().to_owned())
                .into_iter()
                .collect(),
            move |cancelled, progress| {
                operation(cancelled, progress).map_err(|error| {
                    if let Ok(mut slot) = worker_failure_class.lock() {
                        *slot = error.failure_class;
                    }
                    error.message
                })
            },
        )
    }

    /// Start a copy producer whose durable journal identity is published only
    /// after the backend has created the real row. The caller admits under its
    /// runtime gate, then releases the required start gate after dropping it.
    pub fn start_copy_producer(
        this: &Arc<Self>,
        spec: CopyProducerJobSpec<'_>,
        operation: impl FnOnce(
            &AtomicBool,
            &mut dyn FnMut(u64, u64, u64, u64),
            &mut dyn FnMut(&str, u64) -> Result<(), VaultEditJobFailure>,
        ) -> Result<VaultEditReconcileReport, VaultEditJobFailure>
        + Send
        + 'static,
    ) -> Result<VaultEditReconcileStatus, String> {
        if spec.destination == spec.source
            || spec.destination.account_id() != spec.source.account_id()
            || spec.destination.server_origin() != spec.source.server_origin()
        {
            return Err(
                "Copy producer requires two distinct vault scopes in one account and origin".into(),
            );
        }
        let failure_class = Arc::new(Mutex::new(None));
        let worker_failure_class = Arc::clone(&failure_class);
        Self::start_inner_with_binding_publisher(
            this,
            spec.destination,
            spec.auth_generation,
            spec.expected_generation,
            spec.pin_jobs,
            false,
            None,
            Some("copy_file".into()),
            failure_class,
            vec![scope_key(spec.source)],
            vec![spec.source.space_id().to_owned()],
            Some(spec.start_gate),
            move |cancelled, progress, publish_binding| {
                operation(cancelled, progress, publish_binding).map_err(|error| {
                    if let Ok(mut slot) = worker_failure_class.lock() {
                        *slot = error.failure_class;
                    }
                    error.message
                })
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn start_inner(
        this: &Arc<Self>,
        scope: &VaultSessionScope,
        auth_generation: Arc<AtomicU64>,
        expected_generation: u64,
        pin_jobs: Arc<VaultPinJobs>,
        automatic: bool,
        binding: Option<VaultEditOperationBinding>,
        failure_class: Arc<Mutex<Option<VaultEditFailureClass>>>,
        related_scope_keys: Vec<String>,
        related_space_ids: Vec<String>,
        operation: impl FnOnce(
            &AtomicBool,
            &mut dyn FnMut(u64, u64, u64, u64),
        ) -> Result<VaultEditReconcileReport, String>
        + Send
        + 'static,
    ) -> Result<VaultEditReconcileStatus, String> {
        Self::start_inner_with_binding_publisher(
            this,
            scope,
            auth_generation,
            expected_generation,
            pin_jobs,
            automatic,
            binding,
            None,
            failure_class,
            related_scope_keys,
            related_space_ids,
            None,
            move |cancelled, progress, _publish_binding| operation(cancelled, progress),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn start_inner_with_binding_publisher(
        this: &Arc<Self>,
        scope: &VaultSessionScope,
        auth_generation: Arc<AtomicU64>,
        expected_generation: u64,
        pin_jobs: Arc<VaultPinJobs>,
        automatic: bool,
        binding: Option<VaultEditOperationBinding>,
        initial_operation: Option<String>,
        failure_class: Arc<Mutex<Option<VaultEditFailureClass>>>,
        related_scope_keys: Vec<String>,
        related_space_ids: Vec<String>,
        start_gate: Option<std::sync::mpsc::Receiver<()>>,
        operation: impl FnOnce(
            &AtomicBool,
            &mut dyn FnMut(u64, u64, u64, u64),
            &mut dyn FnMut(&str, u64) -> Result<(), VaultEditJobFailure>,
        ) -> Result<VaultEditReconcileReport, String>
        + Send
        + 'static,
    ) -> Result<VaultEditReconcileStatus, String> {
        let job = {
            let mut store = this
                .store
                .lock()
                .map_err(|_| "Encrypted edit job registry is poisoned")?;
            prune_finished(&mut store);
            if store
                .jobs
                .values()
                .any(|job| job.status.lock().map(|s| active(&s.state)).unwrap_or(true))
            {
                return Err("An encrypted edit reconciliation is already running".into());
            }
            let key = scope_key(scope);
            if automatic {
                store
                    .last_auto_attempt
                    .retain(|_, at| at.elapsed() < AUTO_RETRY_COOLDOWN * 2);
                if store
                    .last_auto_attempt
                    .get(&key)
                    .is_some_and(|at| at.elapsed() < AUTO_RETRY_COOLDOWN)
                {
                    return Err("Automatic encrypted edit retry is cooling down".into());
                }
                if !store.last_auto_attempt.contains_key(&key)
                    && store.last_auto_attempt.len() >= MAX_AUTO_RETRY_SCOPES
                {
                    return Err("Automatic encrypted edit retry limit reached".into());
                }
            }
            if store.jobs.len() >= MAX_RETAINED_JOBS {
                return Err("Too many recent encrypted edit jobs".into());
            }
            if automatic {
                store.last_auto_attempt.insert(key, Instant::now());
            }
            let id = format!(
                "vault-edits-{}-{}",
                expected_generation,
                this.next_id.fetch_add(1, Ordering::Relaxed)
            );
            let job = Arc::new(Job {
                scope_key: scope_key(scope),
                related_scope_keys,
                related_space_ids,
                status: Mutex::new(VaultEditReconcileStatus {
                    generation: expected_generation,
                    job_id: id.clone(),
                    space_id: scope.space_id().to_owned(),
                    root_resource_id: scope.resource_id().to_owned(),
                    operation: binding
                        .as_ref()
                        .map(|binding| binding.operation.clone())
                        .or(initial_operation),
                    write_id: binding.as_ref().map(|binding| binding.write_id.clone()),
                    operation_revision: binding.as_ref().map(|binding| binding.revision),
                    retry_generation: binding
                        .as_ref()
                        .and_then(|binding| binding.retry_generation),
                    automatic,
                    state: "queued".into(),
                    processed: 0,
                    uploaded: 0,
                    conflicts: 0,
                    remaining: 0,
                    error: None,
                    failure_class: None,
                    cancel_requested: false,
                }),
                cancelled: AtomicBool::new(false),
                changed: Condvar::new(),
            });
            store.order.push_back(id.clone());
            store.jobs.insert(id.clone(), Arc::clone(&job));
            job
        };

        let worker = Arc::clone(&job);
        if let Err(error) = thread::Builder::new()
            .name("raiun-vault-edit-reconcile".into())
            .spawn(move || {
                // Producer admission may happen while the runtime sync gate is
                // held. Wait before entering the shared pin/remote-operation
                // gate so a lock can cancel this registered job without
                // starting backend work or occupying that gate.
                let start_released = match start_gate {
                    Some(gate) => gate.recv().is_ok(),
                    None => true,
                };
                if !start_released {
                    worker.cancelled.store(true, Ordering::Release);
                }
                let result = if start_released {
                    pin_jobs.run_serialized(&worker.cancelled, || {
                        if auth_generation.load(Ordering::Acquire) != expected_generation {
                            worker.cancelled.store(true, Ordering::Release);
                            return Err(
                                "Encrypted edit job was invalidated by an account change".into()
                            );
                        }
                        if worker.cancelled.load(Ordering::Acquire) {
                            return Err("Encrypted edit job was cancelled".into());
                        }
                        if let Ok(mut status) = worker.status.lock() {
                            status.state = "running".into();
                            worker.changed.notify_all();
                        } else {
                            return Err("Encrypted edit job state is poisoned".into());
                        }
                        let mut progress = |processed, uploaded, conflicts, remaining| {
                            if let Ok(mut status) = worker.status.lock() {
                                status.processed = processed;
                                status.uploaded = uploaded;
                                status.conflicts = conflicts;
                                status.remaining = remaining;
                                worker.changed.notify_all();
                            }
                        };
                        let mut publish_binding =
                            |write_id: &str, revision: u64| -> Result<(), VaultEditJobFailure> {
                                if write_id.len() != 32
                                    || !write_id.bytes().all(|byte| {
                                        byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                                    })
                                    || revision == 0
                                {
                                    return Err(VaultEditJobFailure::unclassified(
                                        "Copy producer returned an invalid journal binding",
                                    ));
                                }
                                let mut status = worker.status.lock().map_err(|_| {
                                    VaultEditJobFailure::unclassified(
                                        "Encrypted edit job state is poisoned",
                                    )
                                })?;
                                if status.operation.as_deref() != Some("copy_file")
                                    || status.write_id.is_some()
                                    || status.operation_revision.is_some()
                                    || !active(&status.state)
                                {
                                    return Err(VaultEditJobFailure::unclassified(
                                        "Copy producer journal binding was already published",
                                    ));
                                }
                                status.write_id = Some(write_id.to_owned());
                                status.operation_revision = Some(revision);
                                worker.changed.notify_all();
                                Ok(())
                            };
                        catch_unwind(AssertUnwindSafe(|| {
                            operation(&worker.cancelled, &mut progress, &mut publish_binding)
                        }))
                        .map_err(|_| "Encrypted edit worker failed safely".to_owned())?
                    })
                } else {
                    Err("Copy producer start gate was disconnected".into())
                };

                if auth_generation.load(Ordering::Acquire) != expected_generation {
                    worker.cancelled.store(true, Ordering::Release);
                }
                if let Ok(mut status) = worker.status.lock() {
                    match result {
                        Ok(report) => {
                            status.processed = report.processed;
                            status.uploaded = report.uploaded;
                            status.conflicts = report.conflicts;
                            status.remaining = report.remaining;
                            if status.operation.as_deref() == Some("copy_file")
                                && (status.write_id.is_none()
                                    || status.operation_revision.is_none())
                            {
                                status.state = "failed".into();
                                status.error = Some(
                                    "Copy producer completed without publishing its journal binding"
                                        .into(),
                                );
                            } else {
                                // Copy verification retires its row only after
                                // guarded completion admission; a producer
                                // returns success only after its own operation
                                // has reached its completion point. A later
                                // cancel/account transition must not rewrite
                                // either admitted result as cancelled.
                                status.state = if matches!(
                                    status.operation.as_deref(),
                                    Some("copy_verify" | "copy_file")
                                ) || !worker.cancelled.load(Ordering::Acquire)
                                {
                                    "complete"
                                } else {
                                    "cancelled"
                                }
                                .into();
                            }
                        }
                        Err(error) => {
                            status.state = if worker.cancelled.load(Ordering::Acquire) {
                                "cancelled"
                            } else {
                                "failed"
                            }
                            .into();
                            status.error = Some(bounded_error(error));
                            status.failure_class = failure_class
                                .lock()
                                .ok()
                                .and_then(|failure_class| *failure_class);
                        }
                    }
                    status.cancel_requested = worker.cancelled.load(Ordering::Acquire);
                    worker.changed.notify_all();
                }
            })
        {
            finish_failed(
                &job,
                format!("Could not start encrypted edit worker: {error}"),
            );
            return Err("Could not start encrypted edit worker".into());
        }
        job.status
            .lock()
            .map(|status| status.clone())
            .map_err(|_| "Encrypted edit job state is poisoned".into())
    }

    pub fn status(
        &self,
        scope: &VaultSessionScope,
        job_id: &str,
        generation: u64,
    ) -> Result<VaultEditReconcileStatus, String> {
        let store = self
            .store
            .lock()
            .map_err(|_| "Encrypted edit job registry is poisoned")?;
        let job = store
            .jobs
            .get(job_id)
            .filter(|job| job.scope_key == scope_key(scope))
            .ok_or("Encrypted edit job was not found")?;
        let status = job
            .status
            .lock()
            .map_err(|_| "Encrypted edit job state is poisoned")?;
        if status.generation != generation {
            return Err("Encrypted edit job was not found".into());
        }
        Ok(status.clone())
    }

    pub fn latest(
        &self,
        scope: &VaultSessionScope,
        generation: u64,
    ) -> Result<Option<VaultEditReconcileStatus>, String> {
        let store = self
            .store
            .lock()
            .map_err(|_| "Encrypted edit job registry is poisoned")?;
        for job_id in store.order.iter().rev() {
            let Some(job) = store.jobs.get(job_id) else {
                continue;
            };
            if job.scope_key != scope_key(scope) {
                continue;
            }
            let status = job
                .status
                .lock()
                .map_err(|_| "Encrypted edit job state is poisoned")?;
            if status.generation == generation {
                return Ok(Some(status.clone()));
            }
        }
        Ok(None)
    }

    pub fn cancel(
        &self,
        scope: &VaultSessionScope,
        job_id: &str,
        generation: u64,
    ) -> Result<VaultEditReconcileStatus, String> {
        let job = self.find_job(scope, job_id, generation)?;
        let mut status = job
            .status
            .lock()
            .map_err(|_| "Encrypted edit job state is poisoned")?;
        if !active(&status.state) {
            return Err("Encrypted edit job is no longer running".into());
        }
        job.cancelled.store(true, Ordering::Release);
        status.cancel_requested = true;
        Ok(status.clone())
    }

    pub fn cancel_scope_and_wait(&self, scope: &VaultSessionScope) -> Result<(), String> {
        self.cancel_matching_and_wait(Some(&scope_key(scope)))
    }

    pub fn cancel_all_and_wait(&self) -> Result<(), String> {
        self.cancel_matching_and_wait(None)
    }

    pub fn cancel_space_and_wait(&self, space_id: &str) -> Result<(), String> {
        let store = self
            .store
            .lock()
            .map_err(|_| "Encrypted edit job registry is poisoned")?;
        let jobs = store
            .jobs
            .values()
            .filter(|job| {
                job.related_space_ids.iter().any(|space| space == space_id)
                    || job
                        .status
                        .lock()
                        .map(|status| status.space_id == space_id && active(&status.state))
                        .unwrap_or(true)
            })
            .cloned()
            .collect::<Vec<_>>();
        drop(store);
        wait_cancelled(jobs)
    }

    fn find_job(
        &self,
        scope: &VaultSessionScope,
        job_id: &str,
        generation: u64,
    ) -> Result<Arc<Job>, String> {
        let store = self
            .store
            .lock()
            .map_err(|_| "Encrypted edit job registry is poisoned")?;
        let job = store
            .jobs
            .get(job_id)
            .filter(|job| job.scope_key == scope_key(scope))
            .cloned()
            .ok_or("Encrypted edit job was not found")?;
        if job
            .status
            .lock()
            .map_err(|_| "Encrypted edit job state is poisoned")?
            .generation
            != generation
        {
            return Err("Encrypted edit job was not found".into());
        }
        Ok(job)
    }

    fn cancel_matching_and_wait(&self, scope: Option<&str>) -> Result<(), String> {
        let jobs = {
            let store = self
                .store
                .lock()
                .map_err(|_| "Encrypted edit job registry is poisoned")?;
            store
                .jobs
                .values()
                .filter(|job| {
                    scope.is_none_or(|key| {
                        job.scope_key == key
                            || job.related_scope_keys.iter().any(|other| other == key)
                    })
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        wait_cancelled(jobs)
    }
}

fn wait_cancelled(jobs: Vec<Arc<Job>>) -> Result<(), String> {
    for job in &jobs {
        if let Ok(status) = job.status.lock()
            && active(&status.state)
        {
            job.cancelled.store(true, Ordering::Release);
        }
    }
    for job in jobs {
        let mut status = job
            .status
            .lock()
            .map_err(|_| "Encrypted edit job state is poisoned")?;
        while active(&status.state) {
            status.cancel_requested = true;
            status = job
                .changed
                .wait(status)
                .map_err(|_| "Encrypted edit job state is poisoned")?;
        }
    }
    Ok(())
}

fn active(state: &str) -> bool {
    matches!(state, "queued" | "running")
}

fn finish_failed(job: &Job, error: String) {
    if let Ok(mut status) = job.status.lock() {
        status.state = "failed".into();
        status.error = Some(bounded_error(error));
        status.failure_class = None;
        job.changed.notify_all();
    }
}

fn bounded_error(error: String) -> String {
    error
        .chars()
        .filter(|character| !character.is_control())
        .take(256)
        .collect()
}

fn scope_key(scope: &VaultSessionScope) -> String {
    format!(
        "{}\n{}\n{}\n{}",
        scope.account_id(),
        scope.server_origin(),
        scope.space_id(),
        scope.resource_id()
    )
}

fn prune_finished(store: &mut Store) {
    while store.jobs.len() >= MAX_RETAINED_JOBS {
        let Some(oldest) = store.order.pop_front() else {
            break;
        };
        let Some(job) = store.jobs.get(&oldest) else {
            continue;
        };
        if job
            .status
            .lock()
            .map(|status| !active(&status.state))
            .unwrap_or(false)
        {
            store.jobs.remove(&oldest);
        } else {
            store.order.push_front(oldest);
            break;
        }
    }
}

pub(super) fn maximum_batch() -> usize {
    MAX_BATCH
}

pub(super) trait PendingEditIdentity {
    fn edit_id(&self) -> &str;
    fn edit_revision(&self) -> u64;
}

impl PendingEditIdentity for VaultPendingEditMetadata {
    fn edit_id(&self) -> &str {
        &self.id
    }

    fn edit_revision(&self) -> u64 {
        self.revision
    }
}

#[allow(clippy::too_many_arguments)] // The callbacks keep transport/cache access outside the job registry.
pub(super) fn reconcile_batch<T: PendingEditIdentity>(
    edits: Vec<T>,
    cancelled: &AtomicBool,
    auth_generation: &AtomicU64,
    expected_generation: u64,
    mut reconcile: impl FnMut(&T) -> Result<(), ReconcileFailure>,
    mut remaining_count: impl FnMut() -> Result<u64, String>,
    progress: &mut dyn FnMut(u64, u64, u64, u64),
) -> Result<VaultEditReconcileReport, VaultEditJobFailure> {
    let mut processed = 0_u64;
    let mut uploaded = 0_u64;
    let mut conflicts = 0_u64;
    let total = edits.len() as u64;

    for edit in edits {
        if cancelled.load(Ordering::Acquire)
            || auth_generation.load(Ordering::Acquire) != expected_generation
        {
            break;
        }

        match reconcile(&edit) {
            Ok(()) => uploaded += 1,
            Err(ReconcileFailure::Conflict) => conflicts += 1,
            Err(ReconcileFailure::Stop(failure_class)) => {
                processed += 1;
                progress(
                    processed,
                    uploaded,
                    conflicts,
                    total.saturating_sub(processed),
                );
                let message =
                    "The encrypted edit retry stopped. Saved local edits remain available.";
                return Err(match failure_class {
                    Some(class) => VaultEditJobFailure::classified(message, class),
                    None => VaultEditJobFailure::unclassified(message),
                });
            }
        }
        processed += 1;
        progress(
            processed,
            uploaded,
            conflicts,
            total.saturating_sub(processed),
        );
    }

    Ok(VaultEditReconcileReport {
        processed,
        uploaded,
        conflicts,
        remaining: remaining_count().map_err(VaultEditJobFailure::unclassified)?,
    })
}

/// Re-query retryable operations after each bounded page so an exact parent
/// directory receipt can make its children eligible in the same user-requested
/// run. The loader must return only operations currently authorized for retry;
/// durable conflicts and children whose parent has no verified receipt stay out.
#[allow(clippy::too_many_arguments)]
pub(super) fn reconcile_dependency_batches<T: PendingEditIdentity>(
    cancelled: &AtomicBool,
    auth_generation: &AtomicU64,
    expected_generation: u64,
    maximum_operations: usize,
    mut load: impl FnMut(usize) -> Result<Vec<T>, String>,
    mut reconcile: impl FnMut(&T) -> Result<(), ReconcileFailure>,
    mut remaining_count: impl FnMut() -> Result<u64, String>,
    progress: &mut dyn FnMut(u64, u64, u64, u64),
) -> Result<VaultEditReconcileReport, VaultEditJobFailure> {
    let cap = maximum_operations.min(MAX_BATCH);
    let mut seen = HashSet::new();
    let (mut processed, mut uploaded, mut conflicts) = (0_u64, 0_u64, 0_u64);
    while (processed as usize) < cap
        && !cancelled.load(Ordering::Acquire)
        && auth_generation.load(Ordering::Acquire) == expected_generation
    {
        let limit = (cap - processed as usize).min(MAX_BATCH);
        let rows = load(limit).map_err(VaultEditJobFailure::unclassified)?;
        let batch = rows
            .into_iter()
            .filter(|row| seen.insert((row.edit_id().to_owned(), row.edit_revision())))
            .take(limit)
            .collect::<Vec<_>>();
        if batch.is_empty() {
            break;
        }
        let mut batch_progress = |batch_processed, batch_uploaded, batch_conflicts, remaining| {
            progress(
                processed + batch_processed,
                uploaded + batch_uploaded,
                conflicts + batch_conflicts,
                remaining,
            );
        };
        let result = reconcile_batch(
            batch,
            cancelled,
            auth_generation,
            expected_generation,
            &mut reconcile,
            &mut remaining_count,
            &mut batch_progress,
        )?;
        processed += result.processed;
        uploaded += result.uploaded;
        conflicts += result.conflicts;
        if result.processed == 0 {
            break;
        }
    }
    Ok(VaultEditReconcileReport {
        processed,
        uploaded,
        conflicts,
        remaining: remaining_count().map_err(VaultEditJobFailure::unclassified)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use raiun_cache::CiphertextWriteState;
    use raiun_opencloud::vault_cache::VaultPendingParentRef;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    fn make_scope(account: &str, space: &str, root: &str) -> VaultSessionScope {
        VaultSessionScope::new(account, "https://cloud.example", space, root).unwrap()
    }

    fn released_copy_start_gate() -> mpsc::Receiver<()> {
        let (release, gate) = mpsc::channel();
        release.send(()).unwrap();
        gate
    }

    fn wait_for_state(
        jobs: &VaultEditReconcileJobs,
        scope: &VaultSessionScope,
        job_id: &str,
        generation: u64,
        expected: &str,
    ) -> VaultEditReconcileStatus {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let status = jobs.status(scope, job_id, generation).unwrap();
            if status.state == expected {
                return status;
            }
            assert!(Instant::now() < deadline, "job did not reach {expected}");
            thread::yield_now();
        }
    }

    #[derive(Clone)]
    struct TestEdit {
        id: String,
        revision: u64,
        state: CiphertextWriteState,
    }

    impl PendingEditIdentity for TestEdit {
        fn edit_id(&self) -> &str {
            &self.id
        }

        fn edit_revision(&self) -> u64 {
            self.revision
        }
    }

    #[derive(Clone)]
    struct TestOperation {
        id: String,
        revision: u64,
        parent_ref: Option<VaultPendingParentRef>,
    }

    impl PendingEditIdentity for TestOperation {
        fn edit_id(&self) -> &str {
            &self.id
        }

        fn edit_revision(&self) -> u64 {
            self.revision
        }
    }

    #[test]
    fn completed_job_is_scope_and_generation_bound() {
        let jobs = Arc::new(VaultEditReconcileJobs::default());
        let pin_jobs = Arc::new(VaultPinJobs::default());
        let scope = make_scope("profile-a", "space-a", "root-a");
        let auth_generation = Arc::new(AtomicU64::new(7));
        let queued = VaultEditReconcileJobs::start(
            &jobs,
            &scope,
            Arc::clone(&auth_generation),
            7,
            Arc::clone(&pin_jobs),
            false,
            |_, progress| {
                progress(1, 1, 0, 2);
                Ok(VaultEditReconcileReport {
                    processed: 1,
                    uploaded: 1,
                    conflicts: 0,
                    remaining: 2,
                })
            },
        )
        .unwrap();
        let done = wait_for_state(&jobs, &scope, &queued.job_id, 7, "complete");
        assert_eq!(done.processed, 1);
        assert_eq!(done.uploaded, 1);
        assert_eq!(done.conflicts, 0);
        assert_eq!(done.remaining, 2);
        assert!(
            jobs.status(
                &make_scope("profile-b", "space-a", "root-a"),
                &queued.job_id,
                7
            )
            .is_err()
        );
        assert!(jobs.status(&scope, &queued.job_id, 8).is_err());
        assert_eq!(maximum_batch(), 32);
    }

    #[test]
    fn locking_copy_source_cancels_the_exact_destination_job() {
        let jobs = Arc::new(VaultEditReconcileJobs::default());
        let pin_jobs = Arc::new(VaultPinJobs::default());
        let destination = make_scope("profile-a", "space-d", "root-d");
        let source = make_scope("profile-a", "space-s", "root-s");
        let auth_generation = Arc::new(AtomicU64::new(9));
        let (started_tx, started_rx) = mpsc::channel();
        let queued = VaultEditReconcileJobs::start_copy_verification(
            &jobs,
            CopyVerificationJobSpec {
                destination: &destination,
                source: Some(&source),
                auth_generation: Arc::clone(&auth_generation),
                expected_generation: 9,
                pin_jobs,
                binding: VaultEditOperationBinding {
                    operation: "copy_verify".into(),
                    write_id: "ab".repeat(16),
                    revision: 5,
                    retry_generation: None,
                },
            },
            move |cancelled, _progress| {
                started_tx.send(()).unwrap();
                while !cancelled.load(Ordering::Acquire) {
                    thread::yield_now();
                }
                Err(VaultEditJobFailure::unclassified("cancelled"))
            },
        )
        .unwrap();
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        jobs.cancel_scope_and_wait(&source).unwrap();
        let status = jobs.status(&destination, &queued.job_id, 9).unwrap();
        assert_eq!(status.state, "cancelled");
        assert!(status.cancel_requested);
        assert!(jobs.status(&source, &queued.job_id, 9).is_err());
    }

    #[test]
    fn copy_producer_starts_without_placeholder_binding_and_source_lock_cancels_it() {
        let jobs = Arc::new(VaultEditReconcileJobs::default());
        let destination = make_scope("profile-a", "space-d", "root-d");
        let source = make_scope("profile-a", "space-s", "root-s");
        let (started_tx, started_rx) = mpsc::channel();
        let queued = VaultEditReconcileJobs::start_copy_producer(
            &jobs,
            CopyProducerJobSpec {
                destination: &destination,
                source: &source,
                auth_generation: Arc::new(AtomicU64::new(9)),
                expected_generation: 9,
                pin_jobs: Arc::new(VaultPinJobs::default()),
                start_gate: released_copy_start_gate(),
            },
            move |cancelled, _progress, _publish_binding| {
                started_tx.send(()).unwrap();
                while !cancelled.load(Ordering::Acquire) {
                    thread::yield_now();
                }
                Err(VaultEditJobFailure::unclassified(
                    "cancelled before durable queue",
                ))
            },
        )
        .unwrap();
        assert_eq!(queued.operation.as_deref(), Some("copy_file"));
        assert_eq!(queued.write_id, None);
        assert_eq!(queued.operation_revision, None);
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let running = jobs.status(&destination, &queued.job_id, 9).unwrap();
        assert_eq!(running.operation.as_deref(), Some("copy_file"));
        assert_eq!(running.write_id, None);
        assert_eq!(running.operation_revision, None);

        jobs.cancel_scope_and_wait(&source).unwrap();
        let cancelled = jobs.status(&destination, &queued.job_id, 9).unwrap();
        assert_eq!(cancelled.state, "cancelled");
        assert!(cancelled.cancel_requested);
        assert_eq!(cancelled.write_id, None);
        assert_eq!(cancelled.operation_revision, None);
    }

    #[test]
    fn copy_producer_waits_for_start_gate_before_entering_operation() {
        let jobs = Arc::new(VaultEditReconcileJobs::default());
        let destination = make_scope("profile-a", "space-d", "root-d");
        let source = make_scope("profile-a", "space-s", "root-s");
        let (release_tx, release_rx) = mpsc::channel();
        let (entered_tx, entered_rx) = mpsc::channel();
        let queued = VaultEditReconcileJobs::start_copy_producer(
            &jobs,
            CopyProducerJobSpec {
                destination: &destination,
                source: &source,
                auth_generation: Arc::new(AtomicU64::new(9)),
                expected_generation: 9,
                pin_jobs: Arc::new(VaultPinJobs::default()),
                start_gate: release_rx,
            },
            move |_cancelled, _progress, publish_binding| {
                entered_tx.send(()).unwrap();
                publish_binding(&"ab".repeat(16), 1)?;
                Ok(VaultEditReconcileReport {
                    processed: 1,
                    uploaded: 1,
                    conflicts: 0,
                    remaining: 0,
                })
            },
        )
        .unwrap();

        assert_eq!(queued.state, "queued");
        assert!(entered_rx.recv_timeout(Duration::from_millis(50)).is_err());
        let registered = jobs.status(&destination, &queued.job_id, 9).unwrap();
        assert_eq!(registered.state, "queued");
        assert_eq!(registered.write_id, None);
        release_tx.send(()).unwrap();
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let complete = wait_for_state(&jobs, &destination, &queued.job_id, 9, "complete");
        assert_eq!(
            complete.write_id.as_deref(),
            Some("abababababababababababababababab")
        );
        assert_eq!(complete.operation_revision, Some(1));
    }

    #[test]
    fn copy_producer_cancel_before_gate_release_never_enters_operation() {
        let jobs = Arc::new(VaultEditReconcileJobs::default());
        let destination = make_scope("profile-a", "space-d", "root-d");
        let source = make_scope("profile-a", "space-s", "root-s");
        let (release_tx, release_rx) = mpsc::channel();
        let entered = Arc::new(AtomicBool::new(false));
        let worker_entered = Arc::clone(&entered);
        let queued = VaultEditReconcileJobs::start_copy_producer(
            &jobs,
            CopyProducerJobSpec {
                destination: &destination,
                source: &source,
                auth_generation: Arc::new(AtomicU64::new(9)),
                expected_generation: 9,
                pin_jobs: Arc::new(VaultPinJobs::default()),
                start_gate: release_rx,
            },
            move |_cancelled, _progress, _publish_binding| {
                worker_entered.store(true, Ordering::Release);
                Err(VaultEditJobFailure::unclassified(
                    "must not enter before cancellation",
                ))
            },
        )
        .unwrap();

        let cancelled = jobs.cancel(&destination, &queued.job_id, 9).unwrap();
        assert!(cancelled.cancel_requested);
        release_tx.send(()).unwrap();
        jobs.cancel_scope_and_wait(&destination).unwrap();
        let terminal = jobs.status(&destination, &queued.job_id, 9).unwrap();
        assert_eq!(terminal.state, "cancelled");
        assert!(terminal.cancel_requested);
        assert!(!entered.load(Ordering::Acquire));
    }

    #[test]
    fn copy_producer_dropped_start_gate_finishes_without_operation_or_pin_entry() {
        let jobs = Arc::new(VaultEditReconcileJobs::default());
        let destination = make_scope("profile-a", "space-d", "root-d");
        let source = make_scope("profile-a", "space-s", "root-s");
        let pin_jobs = Arc::new(VaultPinJobs::default());
        let (pin_entered_tx, pin_entered_rx) = mpsc::channel();
        let (release_pin_tx, release_pin_rx) = mpsc::channel();
        let pin_gate_owner = Arc::clone(&pin_jobs);
        let pin_holder = thread::spawn(move || {
            pin_gate_owner.run_serialized(&AtomicBool::new(false), || {
                pin_entered_tx.send(()).unwrap();
                release_pin_rx.recv().unwrap();
                Ok::<(), String>(())
            })
        });
        pin_entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        let (release_tx, release_rx) = mpsc::channel();
        let entered = Arc::new(AtomicBool::new(false));
        let worker_entered = Arc::clone(&entered);
        let queued = VaultEditReconcileJobs::start_copy_producer(
            &jobs,
            CopyProducerJobSpec {
                destination: &destination,
                source: &source,
                auth_generation: Arc::new(AtomicU64::new(9)),
                expected_generation: 9,
                pin_jobs,
                start_gate: release_rx,
            },
            move |_cancelled, _progress, _publish_binding| {
                worker_entered.store(true, Ordering::Release);
                Err(VaultEditJobFailure::unclassified(
                    "must not enter after a dropped start gate",
                ))
            },
        )
        .unwrap();

        drop(release_tx);
        let terminal = wait_for_state(&jobs, &destination, &queued.job_id, 9, "cancelled");
        assert!(terminal.cancel_requested);
        assert!(terminal.error.as_deref().unwrap().contains("start gate"));
        assert!(!entered.load(Ordering::Acquire));
        release_pin_tx.send(()).unwrap();
        pin_holder.join().unwrap().unwrap();
    }

    #[test]
    fn copy_producer_retains_exact_published_binding_on_source_and_destination_cancel() {
        for cancel_source in [true, false] {
            let jobs = Arc::new(VaultEditReconcileJobs::default());
            let destination = make_scope("profile-a", "space-d", "root-d");
            let source = make_scope("profile-a", "space-s", "root-s");
            let (published_tx, published_rx) = mpsc::channel();
            let queued = VaultEditReconcileJobs::start_copy_producer(
                &jobs,
                CopyProducerJobSpec {
                    destination: &destination,
                    source: &source,
                    auth_generation: Arc::new(AtomicU64::new(9)),
                    expected_generation: 9,
                    pin_jobs: Arc::new(VaultPinJobs::default()),
                    start_gate: released_copy_start_gate(),
                },
                move |cancelled, _progress, publish_binding| {
                    publish_binding(&"ab".repeat(16), 7)?;
                    published_tx.send(()).unwrap();
                    while !cancelled.load(Ordering::Acquire) {
                        thread::yield_now();
                    }
                    Err(VaultEditJobFailure::unclassified(
                        "cancelled with durable copy row",
                    ))
                },
            )
            .unwrap();
            assert_eq!(queued.operation.as_deref(), Some("copy_file"));
            assert_eq!(queued.write_id, None);
            assert_eq!(queued.operation_revision, None);
            published_rx.recv_timeout(Duration::from_secs(2)).unwrap();

            if cancel_source {
                jobs.cancel_scope_and_wait(&source).unwrap();
            } else {
                jobs.cancel_space_and_wait(destination.space_id()).unwrap();
            }
            let cancelled = jobs.status(&destination, &queued.job_id, 9).unwrap();
            assert_eq!(cancelled.state, "cancelled");
            assert!(cancelled.cancel_requested);
            assert_eq!(
                cancelled.write_id.as_deref(),
                Some("abababababababababababababababab")
            );
            assert_eq!(cancelled.operation_revision, Some(7));
        }
    }

    #[test]
    fn copy_producer_success_admission_wins_over_late_cancel() {
        let jobs = Arc::new(VaultEditReconcileJobs::default());
        let destination = make_scope("profile-a", "space-d", "root-d");
        let source = make_scope("profile-a", "space-s", "root-s");
        let queued = VaultEditReconcileJobs::start_copy_producer(
            &jobs,
            CopyProducerJobSpec {
                destination: &destination,
                source: &source,
                auth_generation: Arc::new(AtomicU64::new(9)),
                expected_generation: 9,
                pin_jobs: Arc::new(VaultPinJobs::default()),
                start_gate: released_copy_start_gate(),
            },
            |cancelled, _progress, publish_binding| {
                publish_binding(&"cd".repeat(16), 3)?;
                // Models successful producer admission followed by a late
                // lock/account cancellation before terminal status publication.
                cancelled.store(true, Ordering::Release);
                Ok(VaultEditReconcileReport {
                    processed: 1,
                    uploaded: 1,
                    conflicts: 0,
                    remaining: 0,
                })
            },
        )
        .unwrap();
        let done = wait_for_state(&jobs, &destination, &queued.job_id, 9, "complete");
        assert!(done.cancel_requested);
        assert_eq!(done.operation.as_deref(), Some("copy_file"));
        assert_eq!(
            done.write_id.as_deref(),
            Some("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")
        );
        assert_eq!(done.operation_revision, Some(3));
    }

    #[test]
    fn copy_producer_rejects_invalid_or_conflicting_binding_without_overwrite() {
        let destination = make_scope("profile-a", "space-d", "root-d");
        let source = make_scope("profile-a", "space-s", "root-s");

        let jobs = Arc::new(VaultEditReconcileJobs::default());
        let invalid = VaultEditReconcileJobs::start_copy_producer(
            &jobs,
            CopyProducerJobSpec {
                destination: &destination,
                source: &source,
                auth_generation: Arc::new(AtomicU64::new(9)),
                expected_generation: 9,
                pin_jobs: Arc::new(VaultPinJobs::default()),
                start_gate: released_copy_start_gate(),
            },
            |_cancelled, _progress, publish_binding| {
                publish_binding("not-an-id", 1)?;
                Ok(VaultEditReconcileReport {
                    processed: 0,
                    uploaded: 0,
                    conflicts: 0,
                    remaining: 0,
                })
            },
        )
        .unwrap();
        let failed = wait_for_state(&jobs, &destination, &invalid.job_id, 9, "failed");
        assert_eq!(failed.write_id, None);
        assert_eq!(failed.operation_revision, None);

        let jobs = Arc::new(VaultEditReconcileJobs::default());
        let missing = VaultEditReconcileJobs::start_copy_producer(
            &jobs,
            CopyProducerJobSpec {
                destination: &destination,
                source: &source,
                auth_generation: Arc::new(AtomicU64::new(9)),
                expected_generation: 9,
                pin_jobs: Arc::new(VaultPinJobs::default()),
                start_gate: released_copy_start_gate(),
            },
            |_cancelled, _progress, _publish_binding| {
                Ok(VaultEditReconcileReport {
                    processed: 1,
                    uploaded: 1,
                    conflicts: 0,
                    remaining: 0,
                })
            },
        )
        .unwrap();
        let failed = wait_for_state(&jobs, &destination, &missing.job_id, 9, "failed");
        assert!(
            failed
                .error
                .as_deref()
                .unwrap()
                .contains("without publishing")
        );

        let jobs = Arc::new(VaultEditReconcileJobs::default());
        let conflicting = VaultEditReconcileJobs::start_copy_producer(
            &jobs,
            CopyProducerJobSpec {
                destination: &destination,
                source: &source,
                auth_generation: Arc::new(AtomicU64::new(9)),
                expected_generation: 9,
                pin_jobs: Arc::new(VaultPinJobs::default()),
                start_gate: released_copy_start_gate(),
            },
            |_cancelled, _progress, publish_binding| {
                publish_binding("ab".repeat(16).as_str(), 2)?;
                publish_binding("cd".repeat(16).as_str(), 3)?;
                Ok(VaultEditReconcileReport {
                    processed: 0,
                    uploaded: 0,
                    conflicts: 0,
                    remaining: 0,
                })
            },
        )
        .unwrap();
        let failed = wait_for_state(&jobs, &destination, &conflicting.job_id, 9, "failed");
        assert_eq!(
            failed.write_id.as_deref(),
            Some("abababababababababababababababab")
        );
        assert_eq!(failed.operation_revision, Some(2));
    }

    #[test]
    fn copy_verification_admission_wins_over_late_cancel_for_terminal_status() {
        let jobs = Arc::new(VaultEditReconcileJobs::default());
        let destination = make_scope("profile-a", "space-d", "root-d");
        let source = make_scope("profile-a", "space-s", "root-s");
        let queued = VaultEditReconcileJobs::start_copy_verification(
            &jobs,
            CopyVerificationJobSpec {
                destination: &destination,
                source: Some(&source),
                auth_generation: Arc::new(AtomicU64::new(9)),
                expected_generation: 9,
                pin_jobs: Arc::new(VaultPinJobs::default()),
                binding: VaultEditOperationBinding {
                    operation: "copy_verify".into(),
                    write_id: "cd".repeat(16),
                    revision: 3,
                    retry_generation: None,
                },
            },
            |cancelled, _progress| {
                // Models cancellation arriving after the resolver's guarded
                // retirement admission but before job status publication.
                cancelled.store(true, Ordering::Release);
                Ok(VaultEditReconcileReport {
                    processed: 1,
                    uploaded: 0,
                    conflicts: 0,
                    remaining: 0,
                })
            },
        )
        .unwrap();
        let done = wait_for_state(&jobs, &destination, &queued.job_id, 9, "complete");
        assert!(done.cancel_requested);
        assert_eq!(done.operation.as_deref(), Some("copy_verify"));
    }

    #[test]
    fn automatic_retry_backoff_keeps_manual_retry_available_after_reconnect() {
        let jobs = Arc::new(VaultEditReconcileJobs::default());
        let pin_jobs = Arc::new(VaultPinJobs::default());
        let scope = make_scope("profile-a", "space-a", "root-a");
        let auth_generation = Arc::new(AtomicU64::new(3));
        let automatic = VaultEditReconcileJobs::start(
            &jobs,
            &scope,
            Arc::clone(&auth_generation),
            3,
            Arc::clone(&pin_jobs),
            true,
            |_, _| Err("synthetic transport offline".into()),
        )
        .unwrap();
        let failed = wait_for_state(&jobs, &scope, &automatic.job_id, 3, "failed");
        assert!(failed.automatic);
        assert!(
            failed
                .error
                .as_deref()
                .unwrap()
                .contains("transport offline")
        );
        let latest_failed = jobs.latest(&scope, 3).unwrap().unwrap();
        assert_eq!(latest_failed.job_id, failed.job_id);

        let throttled = VaultEditReconcileJobs::start(
            &jobs,
            &scope,
            Arc::clone(&auth_generation),
            3,
            Arc::clone(&pin_jobs),
            true,
            |_, _| unreachable!("cooldown must reject before starting the job"),
        );
        assert!(throttled.unwrap_err().contains("cooling down"));
        assert!(!jobs.automatic_due(&scope).unwrap());

        // A user Retry is intentionally not blocked by automatic backoff;
        // this models reconnect while preserving an explicit recovery path.
        let manual = VaultEditReconcileJobs::start(
            &jobs,
            &scope,
            Arc::clone(&auth_generation),
            3,
            Arc::clone(&pin_jobs),
            false,
            |_, progress| {
                progress(1, 1, 0, 0);
                Ok(VaultEditReconcileReport {
                    processed: 1,
                    uploaded: 1,
                    conflicts: 0,
                    remaining: 0,
                })
            },
        )
        .unwrap();
        let complete = wait_for_state(&jobs, &scope, &manual.job_id, 3, "complete");
        assert!(!complete.automatic);
        let latest_complete = jobs.latest(&scope, 3).unwrap().unwrap();
        assert_eq!(latest_complete.job_id, complete.job_id);

        // Once backoff expires, the next authenticated scheduler cycle can
        // retry the durable row automatically after connectivity returns.
        jobs.store
            .lock()
            .unwrap()
            .last_auto_attempt
            .insert(scope_key(&scope), Instant::now() - AUTO_RETRY_COOLDOWN);
        assert!(jobs.automatic_due(&scope).unwrap());
        let reconnected = VaultEditReconcileJobs::start(
            &jobs,
            &scope,
            auth_generation,
            3,
            pin_jobs,
            true,
            |_, progress| {
                progress(1, 1, 0, 0);
                Ok(VaultEditReconcileReport {
                    processed: 1,
                    uploaded: 1,
                    conflicts: 0,
                    remaining: 0,
                })
            },
        )
        .unwrap();
        let auto_complete = wait_for_state(&jobs, &scope, &reconnected.job_id, 3, "complete");
        assert!(auto_complete.automatic);
        assert_eq!(
            jobs.latest(&scope, 3).unwrap().unwrap().job_id,
            reconnected.job_id
        );
        assert!(jobs.latest(&scope, 4).unwrap().is_none());
    }

    #[test]
    fn batch_stops_before_upload_when_account_generation_changes() {
        let edits = (0..2)
            .map(|index| TestEdit {
                id: format!("write-{index}"),
                revision: 1,
                state: CiphertextWriteState::Pending,
            })
            .collect();
        let generation = AtomicU64::new(3);
        let mut attempted = Vec::new();
        let mut progress = |_, _, _, _| {};
        let report = reconcile_batch(
            edits,
            &AtomicBool::new(false),
            &generation,
            3,
            |edit| {
                attempted.push(edit.id.clone());
                generation.store(4, Ordering::Release);
                Ok(())
            },
            || Ok(1),
            &mut progress,
        )
        .unwrap();
        assert_eq!(attempted, ["write-0"]);
        assert_eq!(report.processed, 1);
        assert_eq!(report.uploaded, 1);
    }

    #[test]
    fn worker_retires_only_durable_retryable_rows_and_keeps_conflicts() {
        use std::collections::HashSet;

        fn edit(id: String, state: CiphertextWriteState) -> TestEdit {
            TestEdit {
                id,
                revision: 1,
                state,
            }
        }

        let scope = make_scope("account-a", "space-a", "root-a");
        let jobs = Arc::new(VaultEditReconcileJobs::default());
        let pin_jobs = Arc::new(VaultPinJobs::default());
        let auth_generation = Arc::new(AtomicU64::new(4));
        let rows = Arc::new(Mutex::new(
            (0..35)
                .map(|index| edit(format!("write-{index:03}"), CiphertextWriteState::Conflict))
                .chain([
                    edit("write-035".into(), CiphertextWriteState::Pending),
                    edit("write-036".into(), CiphertextWriteState::Pending),
                    edit("write-037".into(), CiphertextWriteState::Pending),
                ])
                .collect::<Vec<_>>(),
        ));
        let verified_readbacks = Arc::new(Mutex::new(HashSet::new()));
        let worker_rows = Arc::clone(&rows);
        let worker_readbacks = Arc::clone(&verified_readbacks);

        let started = VaultEditReconcileJobs::start_with_failure_class(
            &jobs,
            &scope,
            auth_generation,
            4,
            pin_jobs,
            false,
            move |cancelled, progress| {
                let retryable = worker_rows
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|row| {
                        matches!(
                            row.state,
                            CiphertextWriteState::Pending | CiphertextWriteState::Uncertain
                        )
                    })
                    .cloned()
                    .collect();
                reconcile_batch(
                    retryable,
                    cancelled,
                    &AtomicU64::new(4),
                    4,
                    |edit| {
                        let mut rows = worker_rows.lock().unwrap();
                        if edit.id == "write-036" {
                            // A row is retired only after the synthetic remote
                            // readback agrees with the queued snapshot.
                            worker_readbacks.lock().unwrap().insert(edit.id.clone());
                            rows.retain(|row| row.id != edit.id);
                            Ok(())
                        } else if edit.id == "write-037" {
                            rows.iter_mut().find(|row| row.id == edit.id).unwrap().state =
                                CiphertextWriteState::Conflict;
                            Err(ReconcileFailure::Conflict)
                        } else {
                            rows.retain(|row| row.id != edit.id);
                            worker_readbacks.lock().unwrap().insert(edit.id.clone());
                            Ok(())
                        }
                    },
                    || Ok(worker_rows.lock().unwrap().len() as u64),
                    progress,
                )
            },
        )
        .unwrap();

        let status = wait_for_state(&jobs, &scope, &started.job_id, 4, "complete");
        assert_eq!(status.root_resource_id, "root-a");
        assert_eq!(status.uploaded, 2);
        assert_eq!(status.conflicts, 1);
        assert_eq!(status.remaining, 36);
        assert_eq!(verified_readbacks.lock().unwrap().len(), 2);
        let retained = rows.lock().unwrap();
        assert_eq!(retained.len(), 36);
        assert!(
            retained
                .iter()
                .all(|row| row.state == CiphertextWriteState::Conflict)
        );
    }

    #[test]
    fn dependency_batches_requery_after_parent_receipt_and_never_guess_after_conflict() {
        use raiun_opencloud::vault_cache::VaultPendingParentRef;

        fn operation(id: &str, parent_ref: Option<VaultPendingParentRef>) -> TestOperation {
            TestOperation {
                id: id.into(),
                revision: 1,
                parent_ref,
            }
        }

        let parent = operation(
            "parent",
            Some(VaultPendingParentRef::Stable {
                resource_id: "root".into(),
            }),
        );
        let child = operation(
            "child",
            Some(VaultPendingParentRef::PendingCreate {
                write_id: "parent".into(),
                revision: 1,
            }),
        );
        let rows = Arc::new(Mutex::new(vec![parent, child]));
        let receipt_ready = Arc::new(AtomicBool::new(false));
        let reconcile_order = Arc::new(Mutex::new(Vec::new()));
        let rows_for_load = Arc::clone(&rows);
        let receipt_for_load = Arc::clone(&receipt_ready);
        let rows_for_reconcile = Arc::clone(&rows);
        let receipt_for_reconcile = Arc::clone(&receipt_ready);
        let order_for_reconcile = Arc::clone(&reconcile_order);
        let generation = AtomicU64::new(1);
        let mut progress = |_, _, _, _| {};
        let report = reconcile_dependency_batches(
            &AtomicBool::new(false),
            &generation,
            1,
            maximum_batch(),
            move |limit| {
                Ok(rows_for_load
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|row| {
                        !matches!(
                            row.parent_ref.as_ref(),
                            Some(VaultPendingParentRef::PendingCreate { .. })
                        ) || receipt_for_load.load(Ordering::Acquire)
                    })
                    .take(limit)
                    .cloned()
                    .collect())
            },
            move |row| {
                order_for_reconcile.lock().unwrap().push(row.id.clone());
                if row.id == "parent" {
                    receipt_for_reconcile.store(true, Ordering::Release);
                }
                rows_for_reconcile
                    .lock()
                    .unwrap()
                    .retain(|candidate| candidate.id != row.id);
                Ok(())
            },
            || Ok(0),
            &mut progress,
        )
        .expect("parent and newly eligible child reconcile");
        assert_eq!(report.processed, 2);
        assert_eq!(*reconcile_order.lock().unwrap(), ["parent", "child"]);
        assert!(rows.lock().unwrap().is_empty());

        // Without a verified receipt, re-querying must never make a child
        // eligible merely because a same-path object appears after conflict.
        let parent = operation(
            "parent-conflict",
            Some(VaultPendingParentRef::Stable {
                resource_id: "root".into(),
            }),
        );
        let child = operation(
            "child-blocked",
            Some(VaultPendingParentRef::PendingCreate {
                write_id: "parent-conflict".into(),
                revision: 1,
            }),
        );
        let blocked_rows = Arc::new(Mutex::new(vec![parent, child]));
        let blocked_for_load = Arc::clone(&blocked_rows);
        let blocked_order = Arc::new(Mutex::new(Vec::new()));
        let blocked_for_reconcile = Arc::clone(&blocked_order);
        let mut progress = |_, _, _, _| {};
        let report = reconcile_dependency_batches(
            &AtomicBool::new(false),
            &generation,
            1,
            maximum_batch(),
            move |limit| {
                Ok(blocked_for_load
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|row| {
                        !matches!(
                            row.parent_ref.as_ref(),
                            Some(VaultPendingParentRef::PendingCreate { .. })
                        )
                    })
                    .take(limit)
                    .cloned()
                    .collect())
            },
            move |row| {
                blocked_for_reconcile.lock().unwrap().push(row.id.clone());
                Err(ReconcileFailure::Conflict)
            },
            || Ok(2),
            &mut progress,
        )
        .expect("conflict retained without unsafe child replay");
        assert_eq!(report.processed, 1);
        assert_eq!(report.conflicts, 1);
        assert_eq!(*blocked_order.lock().unwrap(), ["parent-conflict"]);
    }

    #[test]
    fn cancellation_waits_and_shared_gate_serializes_with_pins() {
        let jobs = Arc::new(VaultEditReconcileJobs::default());
        let pin_jobs = Arc::new(VaultPinJobs::default());
        let scope = make_scope("profile-a", "space-a", "root-a");
        let auth_generation = Arc::new(AtomicU64::new(9));
        let (gate_entered_tx, gate_entered_rx) = mpsc::channel();
        let (release_gate_tx, release_gate_rx) = mpsc::channel();
        let pins = Arc::clone(&pin_jobs);
        let cancelled = Arc::new(AtomicBool::new(false));
        let pin_cancelled = Arc::clone(&cancelled);
        let held_gate = thread::spawn(move || {
            pins.run_serialized(&pin_cancelled, || {
                gate_entered_tx.send(()).unwrap();
                release_gate_rx.recv().unwrap();
                Ok(())
            })
            .unwrap();
        });
        gate_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();

        let (reconcile_started_tx, reconcile_started_rx) = mpsc::channel();
        let queued = VaultEditReconcileJobs::start(
            &jobs,
            &scope,
            auth_generation,
            9,
            pin_jobs,
            false,
            move |cancelled, _| {
                reconcile_started_tx.send(()).unwrap();
                while !cancelled.load(Ordering::Acquire) {
                    thread::yield_now();
                }
                Ok(VaultEditReconcileReport {
                    processed: 0,
                    uploaded: 0,
                    conflicts: 0,
                    remaining: 1,
                })
            },
        )
        .unwrap();
        assert!(
            reconcile_started_rx
                .recv_timeout(Duration::from_millis(25))
                .is_err()
        );

        release_gate_tx.send(()).unwrap();
        held_gate.join().unwrap();
        reconcile_started_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        let cancelled_jobs = Arc::clone(&jobs);
        let cancelled_scope = scope.clone();
        let cancel_thread = thread::spawn(move || {
            cancelled_jobs
                .cancel_scope_and_wait(&cancelled_scope)
                .unwrap();
        });
        cancel_thread.join().unwrap();
        let final_status = jobs
            .status(&scope, &queued.job_id, 9)
            .expect("status remains available");
        assert_eq!(final_status.state, "cancelled");
        assert!(final_status.cancel_requested);
    }

    #[test]
    fn interrupted_create_job_status_is_bound_to_exact_operation_revision() {
        let jobs = Arc::new(VaultEditReconcileJobs::default());
        let pin_jobs = Arc::new(VaultPinJobs::default());
        let scope = make_scope("profile-a", "space-a", "root-a");
        let auth_generation = Arc::new(AtomicU64::new(12));
        let started = VaultEditReconcileJobs::start_operation(
            &jobs,
            &scope,
            auth_generation,
            12,
            pin_jobs,
            VaultEditOperationBinding {
                operation: "create_file".into(),
                write_id: "a1".repeat(16),
                revision: 7,
                retry_generation: Some(3),
            },
            |_cancelled, progress| {
                progress(1, 1, 0, 0);
                Ok(VaultEditReconcileReport {
                    processed: 1,
                    uploaded: 1,
                    conflicts: 0,
                    remaining: 0,
                })
            },
        )
        .unwrap();
        assert_eq!(started.operation.as_deref(), Some("create_file"));
        let expected_write_id = "a1".repeat(16);
        assert_eq!(
            started.write_id.as_deref(),
            Some(expected_write_id.as_str())
        );
        assert_eq!(started.operation_revision, Some(7));
        assert_eq!(started.retry_generation, Some(3));
        let final_status = wait_for_state(&jobs, &scope, &started.job_id, 12, "complete");
        assert_eq!(final_status.write_id, started.write_id);
        assert_eq!(final_status.operation_revision, Some(7));
        assert_eq!(final_status.retry_generation, Some(3));
    }

    #[test]
    fn interrupted_create_failure_class_is_opt_in_and_typed() {
        let jobs = Arc::new(VaultEditReconcileJobs::default());
        let pin_jobs = Arc::new(VaultPinJobs::default());
        let scope = make_scope("profile-a", "space-a", "root-a");
        let auth_generation = Arc::new(AtomicU64::new(13));
        let started = VaultEditReconcileJobs::start_operation_with_failure_class(
            &jobs,
            &scope,
            auth_generation,
            13,
            pin_jobs,
            VaultEditOperationBinding {
                operation: "create_file".into(),
                write_id: "b2".repeat(16),
                revision: 2,
                retry_generation: Some(4),
            },
            |_cancelled, _progress| {
                Err(VaultEditJobFailure::classified(
                    "safe generic transport message",
                    VaultEditFailureClass::TransportUnavailable,
                ))
            },
        )
        .unwrap();
        let status = wait_for_state(&jobs, &scope, &started.job_id, 13, "failed");
        assert_eq!(
            status.failure_class,
            Some(VaultEditFailureClass::TransportUnavailable)
        );
        assert_eq!(
            status.error.as_deref(),
            Some("safe generic transport message")
        );
        assert_eq!(
            serde_json::to_value(&status).unwrap()["failure_class"],
            "transport_unavailable"
        );

        let generic_jobs = Arc::new(VaultEditReconcileJobs::default());
        let generic_started = VaultEditReconcileJobs::start_operation_with_failure_class(
            &generic_jobs,
            &scope,
            Arc::new(AtomicU64::new(14)),
            14,
            Arc::new(VaultPinJobs::default()),
            VaultEditOperationBinding {
                operation: "create_file".into(),
                write_id: "c3".repeat(16),
                revision: 1,
                retry_generation: Some(0),
            },
            |_cancelled, _progress| {
                Err(VaultEditJobFailure::unclassified(
                    "ambiguous verification failure",
                ))
            },
        )
        .unwrap();
        let generic_status =
            wait_for_state(&generic_jobs, &scope, &generic_started.job_id, 14, "failed");
        assert_eq!(generic_status.failure_class, None);
        assert!(
            serde_json::to_value(&generic_status)
                .unwrap()
                .get("failure_class")
                .is_none()
        );

        use raiun_core::backend::ErrorKind;
        assert_eq!(
            interrupted_create_failure_class(ErrorKind::Offline),
            Some(VaultEditFailureClass::TransportUnavailable)
        );
        for ambiguous in [ErrorKind::Io, ErrorKind::NotFound, ErrorKind::Conflict] {
            assert_eq!(interrupted_create_failure_class(ambiguous), None);
        }
    }

    #[test]
    fn general_retry_status_preserves_only_allowlisted_failure_class() {
        let scope = make_scope("profile-a", "space-a", "root-a");
        for (generation, class, wire_name) in [
            (
                31,
                VaultEditFailureClass::TransportUnavailable,
                "transport_unavailable",
            ),
            (
                32,
                VaultEditFailureClass::AuthenticationRequired,
                "authentication_required",
            ),
        ] {
            let jobs = Arc::new(VaultEditReconcileJobs::default());
            let started = VaultEditReconcileJobs::start_with_failure_class(
                &jobs,
                &scope,
                Arc::new(AtomicU64::new(generation)),
                generation,
                Arc::new(VaultPinJobs::default()),
                false,
                move |_cancelled, _progress| {
                    Err(VaultEditJobFailure::classified(
                        "safe status text; no remote response copied",
                        class,
                    ))
                },
            )
            .unwrap();
            let status = wait_for_state(&jobs, &scope, &started.job_id, generation, "failed");
            assert_eq!(status.failure_class, Some(class));
            let value = serde_json::to_value(&status).unwrap();
            assert_eq!(value["failure_class"], wire_name);
            assert_eq!(
                value["error"],
                "safe status text; no remote response copied"
            );
        }
    }

    #[test]
    fn retry_failure_class_distinguishes_offline_auth_and_conflict() {
        use raiun_core::backend::ErrorKind;
        assert_eq!(
            reconcile_failure_class(ErrorKind::Offline),
            Some(VaultEditFailureClass::TransportUnavailable)
        );
        assert_eq!(
            reconcile_failure_class(ErrorKind::Unauthorized),
            Some(VaultEditFailureClass::AuthenticationRequired)
        );
        assert_eq!(
            interrupted_create_failure_class(ErrorKind::Unauthorized),
            Some(VaultEditFailureClass::AuthenticationRequired)
        );
        assert_eq!(reconcile_failure_class(ErrorKind::Conflict), None);
        assert_eq!(reconcile_failure_class(ErrorKind::Forbidden), None);
        assert_eq!(reconcile_failure_class(ErrorKind::Io), None);
    }
}
