//! Owner-only create phase driver. Candidates are hints, never replay authority.
use super::windows_create_executor::{CancelOnDrop, Executor, Failure};
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
    Vault(Box<raiun_cloudfiles_windows::VaultChildCreateTask>),
    Directory(Box<DirectoryCreateTask>),
}
pub(crate) enum Reply {
    File(Box<FileCreateReply>),
    Vault(Box<raiun_cloudfiles_windows::VaultChildCreateReply>),
    Directory(Box<DirectoryCreateReply>),
}
impl Task {
    fn kind(&self) -> CreateKind {
        match self {
            Self::File(_) => CreateKind::File,
            Self::Vault(task) => match task.kind() {
                raiun_cloudfiles_windows::namespace_intent::NamespaceObjectKind::File => {
                    CreateKind::File
                }
                raiun_cloudfiles_windows::namespace_intent::NamespaceObjectKind::Directory => {
                    CreateKind::Directory
                }
            },
            Self::Directory(_) => CreateKind::Directory,
        }
    }
    pub(crate) fn execute(self) -> Reply {
        match self {
            Self::File(task) => Reply::File(Box::new((*task).execute())),
            Self::Vault(task) => Reply::Vault(Box::new((*task).execute())),
            Self::Directory(task) => Reply::Directory(Box::new((*task).execute())),
        }
    }
}
impl Reply {
    fn kind(&self) -> CreateKind {
        match self {
            Self::File(_) => CreateKind::File,
            Self::Vault(task) => match task.kind() {
                raiun_cloudfiles_windows::namespace_intent::NamespaceObjectKind::File => {
                    CreateKind::File
                }
                raiun_cloudfiles_windows::namespace_intent::NamespaceObjectKind::Directory => {
                    CreateKind::Directory
                }
            },
            Self::Directory(_) => CreateKind::Directory,
        }
    }
}
pub(crate) type Workers = Executor<Task, Reply>;
// These diagnostics name only boundaries/outcomes visible to this owner. They
// never format backend errors, paths, reply contents or credential state.
#[derive(Clone, Copy)]
enum Stage {
    Begin,
    Advance,
}
macro_rules! stage_hold {
    ($stage:expr, $route:literal, $outcome:literal) => {
        match $stage {
            Stage::Begin => concat!(
                "Creation sync needs attention: ",
                $route,
                " begin ",
                $outcome,
                ". Existing recovery files have been kept."
            ),
            Stage::Advance => concat!(
                "Creation sync needs attention: ",
                $route,
                " advance ",
                $outcome,
                ". Existing recovery files have been kept."
            ),
        }
    };
}
macro_rules! kind_hold {
    ($kind:expr, $reason:literal) => {
        match $kind {
            CreateKind::File => concat!(
                "Creation sync needs attention: file ",
                $reason,
                ". Existing recovery files have been kept."
            ),
            CreateKind::Directory => concat!(
                "Creation sync needs attention: directory ",
                $reason,
                ". Existing recovery files have been kept."
            ),
        }
    };
}
enum Step {
    Task(Task),
    BusyFile,
    BusyVaultTask(Task),
    Ordinary,
    Completed,
    Held(&'static str),
}
fn file_step(step: FileCreateStep, stage: Stage) -> Step {
    match step {
        FileCreateStep::Task(task) => Step::Task(Task::File(Box::new(task))),
        FileCreateStep::Finished(FreshFileCreateOutcome::BusyBeforeCapture) => Step::BusyFile,
        FileCreateStep::Finished(FreshFileCreateOutcome::LocallyCompleted) => Step::Completed,
        FileCreateStep::Finished(FreshFileCreateOutcome::CapturedLocalIncomplete) => Step::Held(
            stage_hold!(stage, "ordinary file", "captured local incomplete"),
        ),
        FileCreateStep::Finished(FreshFileCreateOutcome::SubmittedUncertain) => {
            Step::Held(stage_hold!(stage, "ordinary file", "submitted uncertain"))
        }
        FileCreateStep::Finished(FreshFileCreateOutcome::RemoteVerifiedLocalIncomplete) => {
            Step::Held(stage_hold!(
                stage,
                "ordinary file",
                "remote verified local incomplete"
            ))
        }
    }
}
fn directory_step(step: DirectoryCreateStep, stage: Stage) -> Step {
    use raiun_cloudfiles_windows::namespace_reconcile::DirectoryCreateOutcome as D;
    match step {
        DirectoryCreateStep::Task(task) => Step::Task(Task::Directory(Box::new(task))),
        DirectoryCreateStep::BusyBeforeCapture => Step::BusyFile,
        DirectoryCreateStep::Finished(D::LocalCompleted) => Step::Completed,
        DirectoryCreateStep::Finished(D::RemoteVerifiedLocalPending) => Step::Held(stage_hold!(
            stage,
            "ordinary directory",
            "remote verified local pending"
        )),
        // Only explicit BusyBeforeCapture is retryable; Deferred can own an intent.
        DirectoryCreateStep::Finished(D::Deferred) => {
            Step::Held(stage_hold!(stage, "ordinary directory", "deferred"))
        }
        DirectoryCreateStep::Finished(D::Conflict) => {
            Step::Held(stage_hold!(stage, "ordinary directory", "conflict"))
        }
        DirectoryCreateStep::Finished(D::Uncertain) => {
            Step::Held(stage_hold!(stage, "ordinary directory", "uncertain"))
        }
        DirectoryCreateStep::Finished(D::Retained) => {
            Step::Held(stage_hold!(stage, "ordinary directory", "retained"))
        }
    }
}
fn vault_hold(stage: Stage, kind: CreateKind) -> &'static str {
    match kind {
        CreateKind::File => stage_hold!(stage, "vault file", "held"),
        CreateKind::Directory => stage_hold!(stage, "vault directory", "held"),
    }
}
fn vault_refused(stage: Stage, kind: CreateKind) -> &'static str {
    match kind {
        CreateKind::File => stage_hold!(stage, "vault file", "owner refused"),
        CreateKind::Directory => stage_hold!(stage, "vault directory", "owner refused"),
    }
}
fn vault_step(
    step: raiun_cloudfiles_windows::VaultChildCreateStep,
    stage: Stage,
    kind: CreateKind,
) -> Step {
    use raiun_cloudfiles_windows::VaultChildCreateStep as V;
    match step {
        V::Task(t) => Step::Task(Task::Vault(Box::new(t))),
        V::Ordinary => Step::Ordinary,
        V::Busy => Step::BusyFile,
        V::BusyBeforeCapture(task) => Step::BusyVaultTask(Task::Vault(Box::new(task))),
        V::Completed => Step::Completed,
        V::Held => Step::Held(vault_hold(stage, kind)),
    }
}
pub(crate) const PRODUCTION_ENABLED: bool = true;
pub(crate) const HOLD: &str =
    "Creation sync needs attention. Existing recovery files have been kept.";
struct Candidate {
    kind: CreateKind,
    components: Vec<String>,
    generation: u64,
    job: StreamedRecoveryJob,
    current: Arc<dyn Fn(CapturedAuthorization) -> bool + Send + Sync>,
}
struct Lane {
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
    ordinary_candidate: bool,
    retry_after_wave: bool,
}
impl Lane {
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
            ordinary_candidate: false,
            retry_after_wave: false,
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
        let _ = connection.close_fresh_vault_child_create();
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
            let _ = connection.close_fresh_vault_child_create();
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
        collect_only: bool,
    ) -> Result<bool, &'static str> {
        let supported_leaf = match components.first().map(String::as_str) {
            Some("Personal") => components.len() >= 2,
            Some("Spaces") => components.len() >= 3,
            _ => false,
        };
        let validation = if !supported_leaf || components.len() > 256 {
            Some(kind_hold!(kind, "candidate namespace refused"))
        } else if (kind == CreateKind::File && !self.allow_file)
            || (kind == CreateKind::Directory && !self.allow_directory)
        {
            Some(kind_hold!(kind, "creation disabled"))
        } else if self.held {
            Some(kind_hold!(kind, "owner already stopped"))
        } else if !self.is_current(backend, root) {
            Some(kind_hold!(kind, "original context changed"))
        } else {
            None
        };
        if let Some(reason) = validation {
            self.stop(connection);
            self.drain_held(connection, workers);
            return Err(reason);
        }
        if self.candidate.as_ref().is_some_and(|old| {
            old.components != components || old.generation != record_generation || old.kind != kind
        }) {
            self.stop(connection);
            return Err(kind_hold!(kind, "candidate identity changed"));
        }
        if self.candidate.is_none() {
            // Capture the original backend transfer-cancel epoch BEFORE first prepare.
            let cancelled = backend
                .recovery_transfer_cancellation()
                .ok_or(kind_hold!(kind, "initial cancellation context unavailable"))?;
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
        if collect_only {
            return Ok(false);
        }
        let candidate = self
            .candidate
            .as_ref()
            .ok_or(kind_hold!(kind, "candidate unavailable"))?;
        if candidate.job.is_stopped() {
            self.stop(connection);
            return Err(kind_hold!(kind, "original job stopped"));
        }
        let step = if let Some(id) = self.flight {
            let Some(done) = workers.poll_for(id) else {
                return Ok(false);
            };
            self.flight = None;
            let reply = match done.result {
                Ok(reply)
                    if matching_create_completion(candidate.kind, id, reply.kind(), done.id) =>
                {
                    reply
                }
                result => {
                    let reason = match result {
                        Ok(_) => kind_hold!(kind, "executor completion identity mismatch"),
                        Err(Failure::Cancelled) => kind_hold!(kind, "executor cancelled"),
                        Err(Failure::Panicked) => kind_hold!(kind, "executor panicked"),
                    };
                    self.stop(connection);
                    return Err(reason);
                }
            };
            Some(match reply {
                Reply::Vault(reply) => {
                    let failure = reply.failure_context();
                    vault_step(
                        connection
                            .advance_fresh_vault_child_create(*reply)
                            .map_err(|_| failure)?,
                        Stage::Advance,
                        kind,
                    )
                }
                Reply::File(reply) => {
                    let failure = reply.failure_context();
                    file_step(
                        connection
                            .advance_fresh_personal_file_create(*reply)
                            .map_err(|_| failure)?,
                        Stage::Advance,
                    )
                }
                Reply::Directory(reply) => {
                    let failure = reply.failure_context();
                    directory_step(
                        connection
                            .advance_fresh_personal_directory_create(*reply)
                            .map_err(|_| failure)?,
                        Stage::Advance,
                    )
                }
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
            let name = candidate
                .components
                .last()
                .ok_or(kind_hold!(kind, "candidate leaf unavailable"))?;
            if !self.ordinary_candidate {
                let object_kind = match candidate.kind {
                    CreateKind::File => {
                        raiun_cloudfiles_windows::namespace_intent::NamespaceObjectKind::File
                    }
                    CreateKind::Directory => {
                        raiun_cloudfiles_windows::namespace_intent::NamespaceObjectKind::Directory
                    }
                };
                Some(vault_step(
                    connection
                        .begin_fresh_vault_child_create(
                            backend,
                            &parents,
                            name,
                            object_kind,
                            auth,
                            record_generation,
                            &candidate.job,
                            candidate.current.clone(),
                            self.generation.clone(),
                        )
                        .map_err(|_| vault_refused(Stage::Begin, kind))?,
                    Stage::Begin,
                    kind,
                ))
            } else {
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
                            .map_err(|_| {
                                stage_hold!(Stage::Begin, "ordinary file", "owner refused")
                            })?,
                        Stage::Begin,
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
                            .map_err(|_| {
                                stage_hold!(Stage::Begin, "ordinary directory", "owner refused")
                            })?,
                        Stage::Begin,
                    ),
                })
            }
        } else {
            None
        };
        if let Some(step) = step {
            match step {
                Step::Task(task) => self.deferred = Some(task),
                Step::BusyVaultTask(task) => {
                    self.deferred = Some(task);
                    return Ok(false);
                }
                Step::BusyFile => {
                    // A closed-writer retry must not rediscover metadata while
                    // sibling captures are unresolved in the same wave.
                    self.retry_after_wave = self.ordinary_candidate;
                    return Ok(false);
                }
                Step::Ordinary => {
                    self.ordinary_candidate = true;
                    return Ok(false);
                }
                Step::Completed => {
                    self.ordinary_candidate = false;
                    self.candidate = None;
                    self.cancel_on_drop.take();
                    return Ok(true);
                }
                Step::Held(reason) => {
                    self.stop(connection);
                    return Err(reason);
                }
            }
        }
        if let Some(task) = self.deferred.take() {
            if task.kind() != kind {
                self.stop(connection);
                return Err(kind_hold!(kind, "executor task kind mismatch"));
            }
            match workers.submit(task) {
                Ok(id) => self.flight = Some(id),
                Err(task) => self.deferred = Some(task),
            }
        }
        Ok(false)
    }
}

impl Drop for Lane {
    fn drop(&mut self) {
        // Owner unwind must cancel before the enclosing worker executor joins.
        self.cancel_on_drop.take();
        self.deferred.take();
    }
}

/// At most four independently owned ordinary files from one notification wave.
/// Directory/vault work and parent changes remain serial namespace barriers.
pub(crate) struct Producer {
    lanes: Vec<Lane>,
    round_ready: bool,
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
            lanes: (0..super::windows_create_executor::WORKERS)
                .map(|_| {
                    Lane::new(
                        backend,
                        generation,
                        expected,
                        root,
                        allow_file,
                        allow_directory,
                    )
                })
                .collect(),
            round_ready: false,
        }
    }
    pub(crate) fn is_current(
        &self,
        backend: &Arc<OpenCloudPlaceholderBackend>,
        root: ConfiguredRootIdentity,
    ) -> bool {
        self.lanes.iter().all(|lane| lane.is_current(backend, root))
    }
    pub(crate) fn allows_file(&self) -> bool {
        self.lanes[0].allows_file()
    }
    pub(crate) fn allows_directory(&self) -> bool {
        self.lanes[0].allows_directory()
    }
    pub(crate) fn active(&self) -> bool {
        self.lanes.iter().any(Lane::active)
    }
    pub(crate) fn active_kind_for(&self, generation: u64) -> Option<CreateKind> {
        self.lanes.iter().find_map(|lane| {
            lane.candidate
                .as_ref()
                .filter(|c| c.generation == generation)
                .map(|c| c.kind)
        })
    }
    pub(crate) fn can_join(&self, components: &[String]) -> bool {
        !components.is_empty()
            && self.lanes.iter().any(|lane| !lane.active())
            && self.lanes.iter().filter(|lane| lane.active()).all(|lane| {
                lane.ordinary_candidate
                    && lane.candidate.as_ref().is_some_and(|candidate| {
                        candidate.kind == CreateKind::File
                            && candidate.components.len() == components.len()
                            && candidate.components[..components.len() - 1]
                                .iter()
                                .zip(&components[..components.len() - 1])
                                .all(|(a, b)| a.eq_ignore_ascii_case(b))
                    })
            })
    }
    pub(crate) fn pipeline_ready(&self, generation: u64) -> bool {
        self.lanes.iter().any(|lane| {
            lane.ordinary_candidate
                && lane.candidate.as_ref().is_some_and(|candidate| {
                    candidate.generation == generation && candidate.kind == CreateKind::File
                })
        })
    }
    pub(crate) fn begin_round(&mut self, workers: &mut Workers) {
        self.round_ready = workers.all_completed();
    }
    pub(crate) fn stop(&mut self, connection: &ConfiguredRootConnection) {
        for lane in &mut self.lanes {
            lane.stop(connection);
        }
    }
    pub(crate) fn drain_held(
        &mut self,
        connection: &ConfiguredRootConnection,
        workers: &mut Workers,
    ) {
        for lane in &mut self.lanes {
            lane.drain_held(connection, workers);
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
        let index = self.lanes.iter().position(|lane| {
            lane.candidate
                .as_ref()
                .is_some_and(|candidate| candidate.generation == record_generation)
        });
        let inherit = index.is_none()
            && self.active()
            && kind == CreateKind::File
            && self.can_join(components);
        let index = match index {
            Some(index) => index,
            None => {
                if self.active() && !inherit {
                    return Ok(false);
                }
                self.lanes
                    .iter()
                    .position(|lane| !lane.active())
                    .ok_or(HOLD)?
            }
        };
        if self.lanes[index].retry_after_wave
            && self
                .lanes
                .iter()
                .enumerate()
                .any(|(other, lane)| other != index && lane.active() && !lane.retry_after_wave)
        {
            return Ok(false);
        }
        let lane = &mut self.lanes[index];
        lane.retry_after_wave = false;
        if inherit {
            lane.ordinary_candidate = true;
        }
        // Prepare's unresolved-recovery preflight is unchanged. Collect every
        // reply in the wave before the owner captures any sibling body.
        if lane.flight.is_some() && !self.round_ready {
            return Ok(false);
        }
        lane.step(
            connection,
            backend,
            root,
            components,
            record_generation,
            kind,
            workers,
            inherit,
        )
    }
}
