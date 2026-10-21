//! One bounded explicit offline file/folder job. No automatic replay on restart.
use super::*;
use raiun_cloudfiles_windows::{BackendError, CancellationToken, OfflineDownloadError};

#[derive(Default)]
pub(super) struct OfflineJobs {
    active: Mutex<Option<Arc<Job>>>,
    reservation: Mutex<Option<(ActiveProviderBinding, String)>>,
}

struct Job {
    binding: ActiveProviderBinding,
    id: String,
    cancellation: CancellationToken,
    state: Mutex<JobState>,
    kind: &'static str,
    pin_progress: Mutex<Option<raiun_cache::PinInfo>>,
}

#[derive(Clone, Copy)]
enum JobState {
    Running,
    Complete,
    Cancelled,
    Failed,
    RecoveryRequired,
}

impl JobState {
    fn label(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Complete => "complete",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
            Self::RecoveryRequired => "recovery_required",
        }
    }
}

impl Job {
    fn snapshot(&self) -> Result<Value, String> {
        let state = *self
            .state
            .lock()
            .map_err(|_| "Offline job state is unavailable")?;
        let pin = self
            .pin_progress
            .lock()
            .map_err(|_| "Offline folder progress is unavailable")?
            .clone();
        let folder = pin.map(|pin| {
            json!({
                "pin_id": pin.id, "root_resource_id": pin.root_resource_id,
                "path": pin.root_path,
                "state": match pin.state {
                    raiun_cache::PinState::Building => "building",
                    raiun_cache::PinState::Ready => "ready",
                    raiun_cache::PinState::Stale => "stale",
                    raiun_cache::PinState::Unavailable => "unavailable",
                },
                "item_count": pin.item_count, "ready_content_count": pin.ready_content_count,
                "required_content_count": pin.required_content_count,
            })
        });
        // Preserve the exact four-field file-job response consumed by the
        // existing strict UI parser. Folder jobs have their own response shape.
        let mut status = json!({"job_id":self.id,"state":state.label(),
            "cancel_requested":self.cancellation.is_cancelled(),
            "recovery_required":matches!(state, JobState::RecoveryRequired)});
        if self.kind == "folder" {
            status["kind"] = json!("folder");
            status["folder"] = folder.unwrap_or(Value::Null);
        }
        Ok(status)
    }
}

fn reserved_snapshot(id: &str, state: &str) -> Value {
    json!({"job_id":id,"state":state,"kind":"folder","folder":null,
        "cancel_requested":state == "cancelled","recovery_required":false})
}

fn new_job_id() -> Result<String, String> {
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| "Could not create an offline job identity")?;
    Ok(nonce.iter().map(|byte| format!("{byte:02x}")).collect())
}

impl OfflineJobs {
    /// Reserve an ID without starting work. The caller receives this ID before
    /// it can submit admission, so a lost start reply can be inspected safely.
    pub(super) fn prepare_folder(
        &self,
        binding: ActiveProviderBinding,
        authorized_generation: &AtomicU64,
    ) -> Result<Value, String> {
        let active = self
            .active
            .lock()
            .map_err(|_| "Offline jobs are unavailable")?;
        if binding.generation == 0
            || authorized_generation.load(Ordering::Acquire) != binding.generation
        {
            return Err("The account changed before offline job preparation".into());
        }
        if let Some(job) = active.as_ref()
            && matches!(
                *job.state
                    .lock()
                    .map_err(|_| "Offline job state is unavailable")?,
                JobState::Running
            )
        {
            return Err("An offline job is already running; wait for it or cancel it".into());
        }
        let id = new_job_id()?;
        *self
            .reservation
            .lock()
            .map_err(|_| "Offline jobs are unavailable")? = Some((binding, id.clone()));
        Ok(reserved_snapshot(&id, "prepared"))
    }

    pub(super) fn start(
        &self,
        binding: ActiveProviderBinding,
        authorized_generation: &AtomicU64,
        operation: impl FnOnce(&CancellationToken) -> Result<(), OfflineDownloadError> + Send + 'static,
    ) -> Result<Value, String> {
        self.start_inner(
            binding,
            authorized_generation,
            "file",
            None,
            move |cancellation, _| operation(cancellation),
        )
    }

    #[cfg(test)]
    fn start_folder(
        &self,
        binding: ActiveProviderBinding,
        authorized_generation: &AtomicU64,
        operation: impl FnOnce(
            &CancellationToken,
            &mut dyn FnMut(raiun_cache::PinInfo),
        ) -> Result<(), OfflineDownloadError>
        + Send
        + 'static,
    ) -> Result<Value, String> {
        let prepared = self.prepare_folder(binding.clone(), authorized_generation)?;
        let id = prepared["job_id"]
            .as_str()
            .ok_or("Offline preparation failed")?;
        self.start_folder_with_id(binding, authorized_generation, id, operation)
    }

    pub(super) fn start_folder_with_id(
        &self,
        binding: ActiveProviderBinding,
        authorized_generation: &AtomicU64,
        id: &str,
        operation: impl FnOnce(
            &CancellationToken,
            &mut dyn FnMut(raiun_cache::PinInfo),
        ) -> Result<(), OfflineDownloadError>
        + Send
        + 'static,
    ) -> Result<Value, String> {
        if id.len() != 32
            || !id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("Prepare the offline folder job first".into());
        }
        self.start_inner(
            binding,
            authorized_generation,
            "folder",
            Some(id),
            operation,
        )
    }

    fn start_inner(
        &self,
        binding: ActiveProviderBinding,
        authorized_generation: &AtomicU64,
        kind: &'static str,
        requested_id: Option<&str>,
        operation: impl FnOnce(
            &CancellationToken,
            &mut dyn FnMut(raiun_cache::PinInfo),
        ) -> Result<(), OfflineDownloadError>
        + Send
        + 'static,
    ) -> Result<Value, String> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| "Offline jobs are unavailable")?;
        if binding.generation == 0
            || authorized_generation.load(Ordering::Acquire) != binding.generation
        {
            return Err("The account changed before offline job admission".into());
        }
        if let Some(id) = requested_id {
            if let Some(job) = active.as_ref().filter(|job| job.id == id) {
                if job.binding != binding || job.kind != "folder" {
                    return Err("The prepared job belongs to a different drive".into());
                }
                // Duplicate delivery returns the existing result; never replay.
                return job.snapshot();
            }
        }
        let mut reservation = self
            .reservation
            .lock()
            .map_err(|_| "Offline jobs are unavailable")?;
        if let Some(id) = requested_id {
            if reservation
                .as_ref()
                .is_none_or(|(owner, reserved)| owner != &binding || reserved != id)
            {
                return Err("The offline folder reservation is no longer current".into());
            }
        }
        if let Some(job) = active.as_ref()
            && matches!(
                *job.state
                    .lock()
                    .map_err(|_| "Offline job state is unavailable")?,
                JobState::Running
            )
        {
            return Err("An offline job is already running; wait for it or cancel it".into());
        }
        let id = match requested_id {
            Some(id) => id.to_owned(),
            None => new_job_id()?,
        };
        let job = Arc::new(Job {
            binding,
            id,
            cancellation: CancellationToken::for_offline_job(),
            state: Mutex::new(JobState::Running),
            kind,
            pin_progress: Mutex::new(None),
        });
        let worker = Arc::clone(&job);
        thread::Builder::new()
            .name("raiun-offline".into())
            .spawn(move || {
                // Preserve the slot until the operation actually exits, even after
                // cancel. This bounds both memory and in-flight file/network work.
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut progress = |pin| {
                        if let Ok(mut current) = worker.pin_progress.lock() {
                            *current = Some(pin);
                        }
                    };
                    operation(&worker.cancellation, &mut progress)
                }));
                let result = match outcome {
                    // A durable commit wins cancellation observed after completion.
                    Ok(Ok(())) => JobState::Complete,
                    Ok(Err(OfflineDownloadError::ReservationRetained { .. })) => {
                        JobState::RecoveryRequired
                    }
                    Ok(Err(OfflineDownloadError::Backend(BackendError::Cancelled))) => {
                        JobState::Cancelled
                    }
                    Ok(Err(_)) => JobState::Failed,
                    // Unwinding can leave uncertain stage bytes. Never report clean
                    // cancellation or automatically delete/replay them.
                    Err(_) => JobState::RecoveryRequired,
                };
                if let Ok(mut state) = worker.state.lock() {
                    *state = result;
                }
            })
            .map_err(|_| "Could not start the offline job")?;
        *reservation = None;
        *active = Some(Arc::clone(&job));
        job.snapshot()
    }

    pub(super) fn inspect(
        &self,
        binding: &ActiveProviderBinding,
        id: &str,
        cancel: bool,
    ) -> Result<Value, String> {
        let active = self
            .active
            .lock()
            .map_err(|_| "Offline jobs are unavailable")?;
        let job = active
            .as_ref()
            .filter(|job| &job.binding == binding && job.id == id);
        let Some(job) = job else {
            let mut reservation = self
                .reservation
                .lock()
                .map_err(|_| "Offline jobs are unavailable")?;
            if reservation
                .as_ref()
                .is_some_and(|(owner, reserved)| owner == binding && reserved == id)
            {
                if cancel {
                    *reservation = None;
                }
                return Ok(reserved_snapshot(
                    id,
                    if cancel { "cancelled" } else { "prepared" },
                ));
            }
            return Err("The offline job does not belong to this connected drive".into());
        };
        if cancel {
            job.cancellation.cancel();
        }
        job.snapshot()
    }

    pub(super) fn cancel_and_authorize(&self, generation: &AtomicU64, next: u64) {
        // Admission uses the same slot lock: an old-generation job cannot start
        // in the gap between invalidation and cooperative cancellation.
        let active = self.active.lock();
        generation.store(next, Ordering::Release);
        if let Ok(mut reservation) = self.reservation.lock() {
            *reservation = None;
        }
        if let Ok(active) = active
            && let Some(job) = active.as_ref()
        {
            job.cancellation.cancel();
        }
    }

    pub(super) fn cancel_all(&self) {
        // Poisoning fails closed: no new admission can acquire this slot.
        if let Ok(active) = self.active.lock() {
            if let Ok(mut reservation) = self.reservation.lock() {
                *reservation = None;
            }
            if let Some(job) = active.as_ref() {
                job.cancellation.cancel();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicU64, AtomicUsize, Ordering},
        sync::mpsc,
        time::{Duration, Instant},
    };

    fn binding(generation: u64) -> ActiveProviderBinding {
        ActiveProviderBinding {
            generation,
            path: PathBuf::from(format!("C:/synthetic/offline-{generation}")),
            identity: raiun_cloudfiles_windows::ConfiguredRootIdentity {
                volume_serial: 0x1234,
                file_index: 0x5678,
            },
            personal_space_id: "synthetic-personal".into(),
            personal_root_resource_id: "synthetic-root".into(),
        }
    }

    fn job_id(value: &Value) -> String {
        value["job_id"].as_str().unwrap().to_owned()
    }

    fn wait_for_state(
        jobs: &OfflineJobs,
        binding: &ActiveProviderBinding,
        id: &str,
        expected: &str,
    ) -> Value {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let status = jobs.inspect(binding, id, false).unwrap();
            if status["state"] == expected {
                return status;
            }
            assert!(Instant::now() < deadline, "job did not reach {expected}");
            thread::yield_now();
        }
    }

    #[test]
    fn cancelled_running_slot_blocks_replacement_until_operation_exits() {
        let jobs = OfflineJobs::default();
        let generation = AtomicU64::new(7);
        let binding = binding(7);
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let first_id = job_id(
            &jobs
                .start(binding.clone(), &generation, move |_| {
                    started_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
                    Err(OfflineDownloadError::Backend(BackendError::Cancelled))
                })
                .unwrap(),
        );
        started_rx.recv_timeout(Duration::from_secs(3)).unwrap();

        let cancelled = jobs.inspect(&binding, &first_id, true).unwrap();
        assert_eq!(cancelled["state"], "running");
        assert_eq!(cancelled["cancel_requested"], true);
        assert!(
            jobs.start(binding.clone(), &generation, |_| Ok(()))
                .is_err()
        );

        release_tx.send(()).unwrap();
        let terminal = wait_for_state(&jobs, &binding, &first_id, "cancelled");
        assert_eq!(terminal["recovery_required"], false);
        let replacement_id = job_id(
            &jobs
                .start(binding.clone(), &generation, |_| Ok(()))
                .unwrap(),
        );
        wait_for_state(&jobs, &binding, &replacement_id, "complete");
    }

    #[test]
    fn status_and_cancel_reject_other_job_id_or_provider_binding() {
        let jobs = OfflineJobs::default();
        let generation = AtomicU64::new(11);
        let binding = binding(11);
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let id = job_id(
            &jobs
                .start(binding.clone(), &generation, move |_| {
                    started_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
                    Ok(())
                })
                .unwrap(),
        );
        started_rx.recv_timeout(Duration::from_secs(3)).unwrap();

        let mut wrong_generation = binding.clone();
        wrong_generation.generation += 1;
        assert!(jobs.inspect(&wrong_generation, &id, false).is_err());
        assert!(jobs.inspect(&wrong_generation, &id, true).is_err());

        let mut wrong_root = binding.clone();
        wrong_root.personal_root_resource_id.push_str("-other");
        assert!(jobs.inspect(&wrong_root, &id, false).is_err());
        assert!(jobs.inspect(&wrong_root, &id, true).is_err());

        let other_id = format!("{id}-other");
        assert!(jobs.inspect(&binding, &other_id, false).is_err());
        assert!(jobs.inspect(&binding, &other_id, true).is_err());
        assert_eq!(
            jobs.inspect(&binding, &id, false).unwrap()["cancel_requested"],
            false
        );

        release_tx.send(()).unwrap();
        wait_for_state(&jobs, &binding, &id, "complete");
    }

    #[test]
    fn generation_change_cancels_current_job_and_rejects_stale_admission() {
        let jobs = OfflineJobs::default();
        let generation = AtomicU64::new(21);
        let old_binding = binding(21);
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let old_id = job_id(
            &jobs
                .start(old_binding.clone(), &generation, move |_| {
                    started_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
                    Err(OfflineDownloadError::Backend(BackendError::Cancelled))
                })
                .unwrap(),
        );
        started_rx.recv_timeout(Duration::from_secs(3)).unwrap();

        jobs.cancel_and_authorize(&generation, 22);
        assert_eq!(generation.load(Ordering::Acquire), 22);
        assert_eq!(
            jobs.inspect(&old_binding, &old_id, false).unwrap()["cancel_requested"],
            true
        );
        assert!(
            jobs.start(old_binding.clone(), &generation, |_| Ok(()))
                .is_err()
        );
        release_tx.send(()).unwrap();
        wait_for_state(&jobs, &old_binding, &old_id, "cancelled");
        assert!(jobs.start(binding(21), &generation, |_| Ok(())).is_err());

        let current_binding = binding(22);
        let current_id = job_id(
            &jobs
                .start(current_binding.clone(), &generation, |_| Ok(()))
                .unwrap(),
        );
        wait_for_state(&jobs, &current_binding, &current_id, "complete");
    }

    #[test]
    fn durable_success_wins_cancellation_requested_before_worker_returns() {
        let jobs = OfflineJobs::default();
        let generation = AtomicU64::new(31);
        let binding = binding(31);
        let (started_tx, started_rx) = mpsc::channel();
        let (committed_tx, committed_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let id = job_id(
            &jobs
                .start(binding.clone(), &generation, move |_| {
                    started_tx.send(()).unwrap();
                    committed_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
                    // Model a durable commit completed before cancellation.
                    Ok(())
                })
                .unwrap(),
        );
        started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        committed_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(
            jobs.inspect(&binding, &id, true).unwrap()["cancel_requested"],
            true
        );
        release_tx.send(()).unwrap();
        let terminal = wait_for_state(&jobs, &binding, &id, "complete");
        assert_eq!(terminal["cancel_requested"], true);
        assert_eq!(terminal["recovery_required"], false);
    }

    #[test]
    fn retained_reservation_and_panic_are_reported_as_recovery_required() {
        let jobs = OfflineJobs::default();
        let generation = AtomicU64::new(41);
        let binding = binding(41);

        let retained_id = job_id(
            &jobs
                .start(binding.clone(), &generation, |_| {
                    Err(OfflineDownloadError::ReservationRetained {
                        cause: BackendError::Unavailable,
                    })
                })
                .unwrap(),
        );
        let retained = wait_for_state(&jobs, &binding, &retained_id, "recovery_required");
        assert_eq!(retained["recovery_required"], true);

        let panic_id = job_id(
            &jobs
                .start(
                    binding.clone(),
                    &generation,
                    |_| -> Result<(), OfflineDownloadError> {
                        panic!("synthetic uncertain stage failure")
                    },
                )
                .unwrap(),
        );
        let panicked = wait_for_state(&jobs, &binding, &panic_id, "recovery_required");
        assert_eq!(panicked["recovery_required"], true);
    }

    fn folder_pin(id: &str, state: raiun_cache::PinState, ready: usize) -> raiun_cache::PinInfo {
        raiun_cache::PinInfo {
            id: id.to_owned(),
            root_resource_id: "synthetic-root".into(),
            root_path: "/Documents".into(),
            state,
            item_count: 3,
            ready_content_count: ready,
            required_content_count: 2,
        }
    }

    #[test]
    fn folder_progress_survives_running_cancel_and_blocks_other_job_until_exit() {
        let jobs = OfflineJobs::default();
        let generation = AtomicU64::new(51);
        let binding = binding(51);
        let (progress_tx, progress_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let id = job_id(
            &jobs
                .start_folder(binding.clone(), &generation, move |_, progress| {
                    progress(folder_pin(
                        "durable-pin-id",
                        raiun_cache::PinState::Building,
                        0,
                    ));
                    progress_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
                    // Durable metadata remains useful even though the job was
                    // cooperatively cancelled after the progress callback.
                    Err(OfflineDownloadError::Backend(BackendError::Cancelled))
                })
                .unwrap(),
        );
        progress_rx.recv_timeout(Duration::from_secs(3)).unwrap();

        let running = jobs.inspect(&binding, &id, false).unwrap();
        assert_eq!(running["kind"], "folder");
        assert_eq!(running["folder"]["pin_id"], "durable-pin-id");
        assert_eq!(running["folder"]["state"], "building");
        assert_eq!(running["folder"]["item_count"], 3);
        assert_eq!(running["folder"]["ready_content_count"], 0);
        assert_eq!(running["folder"]["required_content_count"], 2);

        let cancelling = jobs.inspect(&binding, &id, true).unwrap();
        assert_eq!(cancelling["state"], "running");
        assert_eq!(cancelling["cancel_requested"], true);
        assert_eq!(cancelling["folder"]["pin_id"], "durable-pin-id");
        assert_eq!(cancelling["folder"]["item_count"], 3);
        assert!(
            jobs.start(binding.clone(), &generation, |_| Ok(()))
                .is_err()
        );
        assert!(
            jobs.start_folder(binding.clone(), &generation, |_, _| Ok(()))
                .is_err()
        );

        release_tx.send(()).unwrap();
        let terminal = wait_for_state(&jobs, &binding, &id, "cancelled");
        assert_eq!(terminal["cancel_requested"], true);
        assert_eq!(terminal["folder"]["pin_id"], "durable-pin-id");
        assert_eq!(terminal["folder"]["state"], "building");

        let next_id = job_id(
            &jobs
                .start(binding.clone(), &generation, |_| Ok(()))
                .unwrap(),
        );
        wait_for_state(&jobs, &binding, &next_id, "complete");
    }

    #[test]
    fn folder_progress_is_hidden_from_a_different_binding() {
        let jobs = OfflineJobs::default();
        let generation = AtomicU64::new(61);
        let binding = binding(61);
        let (progress_tx, progress_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let id = job_id(
            &jobs
                .start_folder(binding.clone(), &generation, move |_, progress| {
                    progress(folder_pin(
                        "folder-pin-61",
                        raiun_cache::PinState::Building,
                        1,
                    ));
                    progress_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
                    Ok(())
                })
                .unwrap(),
        );
        progress_rx.recv_timeout(Duration::from_secs(3)).unwrap();

        let mut other = binding.clone();
        other.personal_space_id.push_str("-other");
        assert!(jobs.inspect(&other, &id, false).is_err());
        assert!(jobs.inspect(&other, &id, true).is_err());
        let status = jobs.inspect(&binding, &id, false).unwrap();
        assert_eq!(status["folder"]["pin_id"], "folder-pin-61");
        assert_eq!(status["folder"]["ready_content_count"], 1);
        assert_eq!(status["cancel_requested"], false);
        release_tx.send(()).unwrap();
        wait_for_state(&jobs, &binding, &id, "complete");
    }

    #[test]
    fn folder_progress_reports_durable_active_id_after_stage_handoff() {
        let jobs = OfflineJobs::default();
        let generation = AtomicU64::new(71);
        let binding = binding(71);
        let (staged_tx, staged_rx) = mpsc::channel();
        let (publish_active_tx, publish_active_rx) = mpsc::channel();
        let (active_tx, active_rx) = mpsc::channel();
        let (finish_tx, finish_rx) = mpsc::channel();
        let id = job_id(
            &jobs
                .start_folder(binding.clone(), &generation, move |_, progress| {
                    progress(folder_pin(
                        "staging-pin",
                        raiun_cache::PinState::Building,
                        0,
                    ));
                    staged_tx.send(()).unwrap();
                    publish_active_rx
                        .recv_timeout(Duration::from_secs(3))
                        .unwrap();
                    progress(folder_pin("active-pin", raiun_cache::PinState::Ready, 2));
                    active_tx.send(()).unwrap();
                    finish_rx.recv_timeout(Duration::from_secs(3)).unwrap();
                    Ok(())
                })
                .unwrap(),
        );

        staged_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let staged = jobs.inspect(&binding, &id, false).unwrap();
        assert_eq!(staged["folder"]["pin_id"], "staging-pin");
        assert_eq!(staged["folder"]["state"], "building");

        publish_active_tx.send(()).unwrap();
        active_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let active = jobs.inspect(&binding, &id, false).unwrap();
        assert_eq!(active["folder"]["pin_id"], "active-pin");
        assert_eq!(active["folder"]["state"], "ready");
        assert_eq!(active["folder"]["ready_content_count"], 2);

        finish_tx.send(()).unwrap();
        let terminal = wait_for_state(&jobs, &binding, &id, "complete");
        assert_eq!(terminal["folder"]["pin_id"], "active-pin");
        assert_eq!(terminal["folder"]["state"], "ready");
    }
    #[test]
    fn file_job_response_preserves_the_exact_legacy_ui_shape() {
        let jobs = OfflineJobs::default();
        let generation = AtomicU64::new(81);
        let owner = binding(81);
        let reply = jobs.start(owner.clone(), &generation, |_| Ok(())).unwrap();
        let terminal = wait_for_state(&jobs, &owner, &job_id(&reply), "complete");
        for value in [&reply, &terminal] {
            let keys = value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(
                keys,
                std::collections::BTreeSet::from([
                    "job_id",
                    "state",
                    "cancel_requested",
                    "recovery_required",
                ])
            );
        }
    }

    #[test]
    fn prepared_id_recovers_lost_start_reply_without_replaying_operation() {
        let jobs = OfflineJobs::default();
        let generation = AtomicU64::new(91);
        let binding = binding(91);
        let prepared = jobs.prepare_folder(binding.clone(), &generation).unwrap();
        let id = job_id(&prepared);
        assert_eq!(prepared["state"], "prepared");
        assert_eq!(jobs.inspect(&binding, &id, false).unwrap(), prepared);

        let calls = Arc::new(AtomicUsize::new(0));
        let calls_first = Arc::clone(&calls);
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let _lost_start_reply = jobs
            .start_folder_with_id(binding.clone(), &generation, &id, move |_, _| {
                calls_first.fetch_add(1, Ordering::SeqCst);
                started_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
                Ok(())
            })
            .unwrap();
        started_rx.recv_timeout(Duration::from_secs(3)).unwrap();

        let recovered = jobs.inspect(&binding, &id, false).unwrap();
        assert_eq!(recovered["job_id"], id);
        assert_eq!(recovered["state"], "running");
        assert_eq!(recovered["kind"], "folder");

        let calls_duplicate = Arc::clone(&calls);
        let duplicate = jobs
            .start_folder_with_id(binding.clone(), &generation, &id, move |_, _| {
                calls_duplicate.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .unwrap();
        assert_eq!(duplicate["job_id"], id);
        assert_eq!(duplicate["state"], "running");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        release_tx.send(()).unwrap();
        assert_eq!(
            wait_for_state(&jobs, &binding, &id, "complete")["job_id"],
            id
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cancelled_or_replaced_reservation_never_runs_old_closure() {
        let jobs = OfflineJobs::default();
        let generation = AtomicU64::new(101);
        let binding = binding(101);
        let cancelled = jobs.prepare_folder(binding.clone(), &generation).unwrap();
        let cancelled_id = job_id(&cancelled);
        assert_eq!(
            jobs.inspect(&binding, &cancelled_id, true).unwrap()["state"],
            "cancelled"
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let refused_calls = Arc::clone(&calls);
        assert!(
            jobs.start_folder_with_id(binding.clone(), &generation, &cancelled_id, move |_, _| {
                refused_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .is_err()
        );

        let old_reservation = jobs.prepare_folder(binding.clone(), &generation).unwrap();
        let old_id = job_id(&old_reservation);
        let current_reservation = jobs.prepare_folder(binding.clone(), &generation).unwrap();
        let current_id = job_id(&current_reservation);
        assert_ne!(old_id, current_id);
        let replaced_calls = Arc::clone(&calls);
        assert!(
            jobs.start_folder_with_id(binding.clone(), &generation, &old_id, move |_, _| {
                replaced_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .is_err()
        );

        let current_calls = Arc::clone(&calls);
        jobs.start_folder_with_id(binding.clone(), &generation, &current_id, move |_, _| {
            current_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .unwrap();
        wait_for_state(&jobs, &binding, &current_id, "complete");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn old_completed_id_cannot_restart_and_generation_change_clears_reservation() {
        let jobs = OfflineJobs::default();
        let generation = AtomicU64::new(111);
        let binding = binding(111);
        let prepared = jobs.prepare_folder(binding.clone(), &generation).unwrap();
        let old_id = job_id(&prepared);
        jobs.start_folder_with_id(binding.clone(), &generation, &old_id, |_, _| Ok(()))
            .unwrap();
        wait_for_state(&jobs, &binding, &old_id, "complete");

        let pending = jobs.prepare_folder(binding.clone(), &generation).unwrap();
        let pending_id = job_id(&pending);
        jobs.cancel_and_authorize(&generation, 112);
        assert!(jobs.inspect(&binding, &pending_id, false).is_err());
        let pending_calls = Arc::new(AtomicUsize::new(0));
        let calls_after_generation_change = Arc::clone(&pending_calls);
        assert!(
            jobs.start_folder_with_id(binding.clone(), &generation, &pending_id, move |_, _| {
                calls_after_generation_change.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .is_err()
        );

        let current_binding = self::binding(112);
        let replacement_id = job_id(
            &jobs
                .start(current_binding.clone(), &generation, |_| Ok(()))
                .unwrap(),
        );
        wait_for_state(&jobs, &current_binding, &replacement_id, "complete");
        let calls_old = Arc::clone(&pending_calls);
        assert!(
            jobs.start_folder_with_id(current_binding, &generation, &old_id, move |_, _| {
                calls_old.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .is_err()
        );
        assert_eq!(pending_calls.load(Ordering::SeqCst), 0);
    }
}
