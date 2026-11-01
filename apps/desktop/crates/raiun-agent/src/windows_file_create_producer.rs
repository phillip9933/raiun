//! Owner-only create phase driver. Candidates are hints, never replay authority.
use super::windows_create_executor::{CancelOnDrop, Executor};
use super::windows_namespace_dispatcher::{CreateKind, matching_create_completion};
use raiun_cloudfiles_windows::{
    CancellationToken, ConfiguredRootConnection, ConfiguredRootIdentity, DirectoryCreateReply,
    DirectoryCreateStep, DirectoryCreateTask, FileCreateReply, FileCreateStep, FileCreateTask,
    FreshFileCreateOutcome, OpenCloudPlaceholderBackend, PlaceholderBackend, StreamedRecoveryJob,
    StreamedRecoveryPolicy, namespace_intent::CapturedAuthorization,
};
use std::sync::{
    Arc, Weak,
    atomic::{AtomicU64, Ordering},
};
pub(crate) enum Task {
    File(Box<FileCreateTask>),
    Directory(Box<DirectoryCreateTask>),
}
pub(crate) enum Reply {
    File(Box<FileCreateReply>),
    Directory(Box<DirectoryCreateReply>),
}
impl Task {
    fn kind(&self) -> CreateKind {
        match self {
            Self::File(_) => CreateKind::File,
            Self::Directory(_) => CreateKind::Directory,
        }
    }
    pub(crate) fn execute(self) -> Reply {
        match self {
            Self::File(task) => Reply::File(Box::new((*task).execute())),
            Self::Directory(task) => Reply::Directory(Box::new((*task).execute())),
        }
    }
}
impl Reply {
    fn kind(&self) -> CreateKind {
        match self {
            Self::File(_) => CreateKind::File,
            Self::Directory(_) => CreateKind::Directory,
        }
    }
}
pub(crate) type Workers = Executor<Task, Reply>;
enum Step {
    Task(Task),
    BusyFile,
    Completed,
    Held,
}
fn file_step(step: FileCreateStep) -> Step {
    match step {
        FileCreateStep::Task(task) => Step::Task(Task::File(Box::new(task))),
        FileCreateStep::Finished(FreshFileCreateOutcome::BusyBeforeCapture) => Step::BusyFile,
        FileCreateStep::Finished(FreshFileCreateOutcome::LocallyCompleted) => Step::Completed,
        FileCreateStep::Finished(_) => Step::Held,
    }
}
fn directory_step(step: DirectoryCreateStep) -> Step {
    match step {
        DirectoryCreateStep::Task(task) => Step::Task(Task::Directory(Box::new(task))),
        DirectoryCreateStep::Finished(
            raiun_cloudfiles_windows::namespace_reconcile::DirectoryCreateOutcome::LocalCompleted,
        ) => Step::Completed,
        // Deferred conflates pre-intent busy with post-intent refusal. Never retry.
        DirectoryCreateStep::Finished(_) => Step::Held,
    }
}
pub(crate) const PRODUCTION_ENABLED: bool = false;
pub(crate) const HOLD: &str =
    "Creation sync needs attention. Existing recovery files have been kept.";
struct Candidate {
    kind: CreateKind,
    components: Vec<String>,
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
    deferred: Option<Task>,
    flight: Option<u64>,
    held: bool,
    allow_file: bool,
    allow_directory: bool,
}
impl Producer {
    pub(crate) fn new(
        backend: &Arc<OpenCloudPlaceholderBackend>,
        generation: &Arc<AtomicU64>,
        expected: u64,
        root: ConfiguredRootIdentity,
        allow_file: bool,
        allow_directory: bool,
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
            allow_file,
            allow_directory,
        }
    }
    pub(crate) fn is_current(
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
    pub(crate) fn allows_file(&self) -> bool {
        self.allow_file
    }
    pub(crate) fn allows_directory(&self) -> bool {
        self.allow_directory
    }
    pub(crate) fn active_kind(&self) -> Option<CreateKind> {
        self.candidate.as_ref().map(|candidate| candidate.kind)
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
        let _ = connection.close_fresh_personal_directory_create();
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
            let _ = connection.close_fresh_personal_directory_create();
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn step(
        &mut self,
        connection: &ConfiguredRootConnection,
        backend: &Arc<OpenCloudPlaceholderBackend>,
        root: ConfiguredRootIdentity,
        components: &[String],
        record_generation: u64,
        kind: CreateKind,
        workers: &mut Workers,
    ) -> Result<bool, &'static str> {
        if components.len() < 2
            || components.len() > 256
            || components.first().map(String::as_str) != Some("Personal")
            || (kind == CreateKind::File && !self.allow_file)
            || (kind == CreateKind::Directory && !self.allow_directory)
            || self.held
            || !self.is_current(backend, root)
        {
            self.stop(connection);
            self.drain_held(connection, workers);
            return Err(HOLD);
        }
        if self.candidate.as_ref().is_some_and(|old| {
            old.components != components || old.generation != record_generation || old.kind != kind
        }) {
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
            // One original deadline, captured before first prepare, includes queue wait.
            let job = match kind {
                CreateKind::File => {
                    CancellationToken::for_recovery_job(StreamedRecoveryPolicy::default())
                }
                CreateKind::Directory => CancellationToken::for_metadata_job(),
            }
            .with_revocation_check(Arc::new(move || !check(auth)));
            let original_job = job.clone();
            self.cancel_on_drop = Some(CancelOnDrop::new(Arc::new(move || original_job.cancel())));
            self.candidate = Some(Candidate {
                kind,
                components: components.to_vec(),
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
            self.flight = None;
            let reply = match done.result {
                Ok(reply)
                    if matching_create_completion(candidate.kind, id, reply.kind(), done.id) =>
                {
                    reply
                }
                _ => {
                    self.stop(connection);
                    return Err(HOLD);
                }
            };
            Some(match reply {
                Reply::File(reply) => file_step(
                    connection
                        .advance_fresh_personal_file_create(*reply)
                        .map_err(|_| HOLD)?,
                ),
                Reply::Directory(reply) => directory_step(
                    connection
                        .advance_fresh_personal_directory_create(*reply)
                        .map_err(|_| HOLD)?,
                ),
            })
        } else if self.deferred.is_none() {
            let auth = CapturedAuthorization {
                agent_generation: self.expected,
                token_generation: backend.scope().token_generation(),
            };
            let parents: Vec<_> = candidate.components[..candidate.components.len() - 1]
                .iter()
                .map(String::as_str)
                .collect();
            let name = candidate.components.last().ok_or(HOLD)?;
            Some(match candidate.kind {
                CreateKind::File => file_step(
                    connection
                        .begin_fresh_personal_file_create_in_parent(
                            backend,
                            &parents,
                            name,
                            auth,
                            record_generation,
                            &candidate.job,
                            candidate.current.clone(),
                        )
                        .map_err(|_| HOLD)?,
                ),
                CreateKind::Directory => directory_step(
                    connection
                        .begin_fresh_personal_directory_create(
                            backend,
                            &parents,
                            name,
                            auth,
                            record_generation,
                            &candidate.job,
                            candidate.current.clone(),
                        )
                        .map_err(|_| HOLD)?,
                ),
            })
        } else {
            None
        };
        if let Some(step) = step {
            match step {
                Step::Task(task) => self.deferred = Some(task),
                Step::BusyFile => {
                    return Ok(false);
                }
                Step::Completed => {
                    self.candidate = None;
                    self.cancel_on_drop.take();
                    return Ok(true);
                }
                Step::Held => {
                    self.stop(connection);
                    return Err(HOLD);
                }
            }
        }
        if let Some(task) = self.deferred.take() {
            if task.kind() != kind {
                self.stop(connection);
                return Err(HOLD);
            }
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
