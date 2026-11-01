//! Owner-only create phase driver. Candidates are hints, never replay authority.
use super::windows_create_executor::{CancelOnDrop, Executor};
use raiun_cloudfiles_windows::{
    CancellationToken, ConfiguredRootConnection, ConfiguredRootIdentity, FileCreateReply,
    FileCreateStep, FileCreateTask, FreshFileCreateOutcome, OpenCloudPlaceholderBackend,
    PlaceholderBackend, StreamedRecoveryJob, StreamedRecoveryPolicy,
    namespace_intent::CapturedAuthorization,
};
use std::sync::{
    Arc, Weak,
    atomic::{AtomicU64, Ordering},
};
pub(crate) type Workers = Executor<FileCreateTask, FileCreateReply>;
pub(crate) const PRODUCTION_ENABLED: bool = false;
pub(crate) const HOLD: &str =
    "File creation sync needs attention. Existing recovery files have been kept.";
struct Candidate {
    name: String,
    generation: u64,
    job: StreamedRecoveryJob,
    current: Arc<dyn Fn(CapturedAuthorization) -> bool + Send + Sync>,
}
pub(crate) struct Producer {
    backend: Weak<OpenCloudPlaceholderBackend>,
    generation: Arc<AtomicU64>,
    expected: u64,
    root: ConfiguredRootIdentity,
    candidate: Option<Candidate>,
    cancel_on_drop: Option<CancelOnDrop>,
    deferred: Option<FileCreateTask>,
    flight: Option<u64>,
    held: bool,
}
impl Producer {
    pub(crate) fn new(
        backend: &Arc<OpenCloudPlaceholderBackend>,
        generation: &Arc<AtomicU64>,
        expected: u64,
        root: ConfiguredRootIdentity,
    ) -> Self {
        Self {
            backend: Arc::downgrade(backend),
            generation: generation.clone(),
            expected,
            root,
            candidate: None,
            cancel_on_drop: None,
            deferred: None,
            flight: None,
            held: false,
        }
    }
    fn current(
        &self,
        backend: &Arc<OpenCloudPlaceholderBackend>,
        root: ConfiguredRootIdentity,
    ) -> bool {
        self.expected != 0
            && self.generation.load(Ordering::Acquire) == self.expected
            && root == self.root
            && !backend.recovery_job_revoked()
            && self
                .backend
                .upgrade()
                .is_some_and(|old| Arc::ptr_eq(&old, backend))
    }
    pub(crate) fn active(&self) -> bool {
        self.candidate.is_some()
    }
    pub(crate) fn stop(&mut self, connection: &ConfiguredRootConnection) {
        self.held = true;
        self.cancel_on_drop.take();
        if let Some(candidate) = &self.candidate {
            candidate.job.cancel();
        }
        // Cancel before dropping an unexecuted task. CF flight tracks its disposal.
        let _ = connection.close_fresh_personal_file_create();
        self.deferred.take();
    }
    /// Poll even on HOLD so completed/late replies cannot consume a slot forever.
    pub(crate) fn drain_held(
        &mut self,
        connection: &ConfiguredRootConnection,
        workers: &mut Workers,
    ) {
        if self.held {
            while workers.poll().is_some() {}
            let _ = connection.close_fresh_personal_file_create();
        }
    }
    pub(crate) fn step(
        &mut self,
        connection: &ConfiguredRootConnection,
        backend: &Arc<OpenCloudPlaceholderBackend>,
        root: ConfiguredRootIdentity,
        name: &str,
        record_generation: u64,
        workers: &mut Workers,
    ) -> Result<bool, &'static str> {
        if self.held || !self.current(backend, root) {
            self.stop(connection);
            self.drain_held(connection, workers);
            return Err(HOLD);
        }
        if self
            .candidate
            .as_ref()
            .is_some_and(|old| old.name != name || old.generation != record_generation)
        {
            self.stop(connection);
            return Err(HOLD);
        }
        if self.candidate.is_none() {
            // Capture the original backend transfer-cancel epoch BEFORE first prepare.
            let cancelled = backend.recovery_transfer_cancellation().ok_or(HOLD)?;
            let generations = self.generation.clone();
            let expected = self.expected;
            let original = Arc::downgrade(backend);
            let auth = CapturedAuthorization {
                agent_generation: expected,
                token_generation: backend.scope().token_generation(),
            };
            let current: Arc<dyn Fn(CapturedAuthorization) -> bool + Send + Sync> =
                Arc::new(move |value| {
                    value == auth
                        && generations.load(Ordering::Acquire) == expected
                        && !cancelled()
                        && original
                            .upgrade()
                            .is_some_and(|backend| !backend.recovery_job_revoked())
                });
            let check = current.clone();
            let job = CancellationToken::for_recovery_job(StreamedRecoveryPolicy::default())
                .with_revocation_check(Arc::new(move || !check(auth)));
            let original_job = job.clone();
            self.cancel_on_drop = Some(CancelOnDrop::new(Arc::new(move || original_job.cancel())));
            self.candidate = Some(Candidate {
                name: name.into(),
                generation: record_generation,
                job,
                current,
            });
        }
        let candidate = self.candidate.as_ref().ok_or(HOLD)?;
        if candidate.job.is_stopped() {
            self.stop(connection);
            return Err(HOLD);
        }
        let step = if let Some(id) = self.flight {
            let Some(done) = workers.poll() else {
                return Ok(false);
            };
            if done.id != id {
                self.stop(connection);
                return Err(HOLD);
            }
            self.flight = None;
            let reply = match done.result {
                Ok(reply) => reply,
                Err(_) => {
                    self.stop(connection);
                    return Err(HOLD);
                }
            };
            Some(
                connection
                    .advance_fresh_personal_file_create(reply)
                    .map_err(|_| HOLD)?,
            )
        } else if self.deferred.is_none() {
            let auth = CapturedAuthorization {
                agent_generation: self.expected,
                token_generation: backend.scope().token_generation(),
            };
            Some(
                connection
                    .begin_fresh_personal_file_create(
                        backend,
                        name,
                        auth,
                        record_generation,
                        &candidate.job,
                        candidate.current.clone(),
                    )
                    .map_err(|_| HOLD)?,
            )
        } else {
            None
        };
        if let Some(step) = step {
            match step {
                FileCreateStep::Task(task) => self.deferred = Some(task),
                FileCreateStep::Finished(FreshFileCreateOutcome::BusyBeforeCapture) => {
                    return Ok(false);
                }
                FileCreateStep::Finished(FreshFileCreateOutcome::LocallyCompleted) => {
                    self.candidate = None;
                    self.cancel_on_drop.take();
                    return Ok(true);
                }
                FileCreateStep::Finished(_) => {
                    self.stop(connection);
                    return Err(HOLD);
                }
            }
        }
        if let Some(task) = self.deferred.take() {
            match workers.submit(task) {
                Ok(id) => self.flight = Some(id),
                Err(task) => self.deferred = Some(task),
            }
        }
        Ok(false)
    }
}

impl Drop for Producer {
    fn drop(&mut self) {
        // Owner unwind must cancel before the enclosing worker executor joins.
        self.cancel_on_drop.take();
        self.deferred.take();
    }
}
