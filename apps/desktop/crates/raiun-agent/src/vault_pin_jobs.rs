//! Bounded per-profile encrypted snapshot jobs.
//!
//! The runtime owns one registry per account profile, so at most one remote
//! traversal runs for that profile at a time. Cancellation is observed
//! between backend operations; in-flight HTTP transfers are not interrupted.

use raiun_cache::CiphertextPinInfo;
use raiun_opencloud::vault_backend::{VaultBackend, VaultPinProgress};
use raiun_vault::session::VaultSessionScope;
use std::{
    collections::{HashMap, VecDeque},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const MAX_RETAINED_JOBS: usize = 64;
const MAX_AUTO_REFRESH_KEYS: usize = 128;
const AUTO_REFRESH_INTERVAL: Duration = Duration::from_secs(60 * 60);

#[derive(Clone, Debug)]
pub(super) struct PinJobSnapshot {
    pub state: &'static str,
    pub error: Option<&'static str>,
    pub pin: Option<CiphertextPinInfo>,
    pub items_done: usize,
    pub bytes_done: u64,
}

enum JobState {
    Queued,
    Running { items_done: usize, bytes_done: u64 },
    Ready(CiphertextPinInfo),
    Failed,
    Cancelled,
}

impl JobState {
    fn active(&self) -> bool {
        matches!(self, Self::Queued | Self::Running { .. })
    }

    fn snapshot(&self) -> PinJobSnapshot {
        match self {
            Self::Queued => PinJobSnapshot {
                state: "queued",
                error: None,
                pin: None,
                items_done: 0,
                bytes_done: 0,
            },
            Self::Running {
                items_done,
                bytes_done,
            } => PinJobSnapshot {
                state: "running",
                error: None,
                pin: None,
                items_done: *items_done,
                bytes_done: *bytes_done,
            },
            Self::Ready(pin) => PinJobSnapshot {
                state: "ready",
                error: None,
                pin: Some(pin.clone()),
                items_done: pin.item_count,
                bytes_done: pin.byte_len,
            },
            Self::Failed => PinJobSnapshot {
                state: "failed",
                error: Some("Encrypted snapshot could not be completed"),
                pin: None,
                items_done: 0,
                bytes_done: 0,
            },
            Self::Cancelled => PinJobSnapshot {
                state: "cancelled",
                error: None,
                pin: None,
                items_done: 0,
                bytes_done: 0,
            },
        }
    }
}

struct Job {
    scope_key: String,
    cancelled: Arc<AtomicBool>,
    state: Mutex<JobState>,
    changed: Condvar,
}

#[derive(Default)]
struct JobStore {
    jobs: HashMap<String, Arc<Job>>,
    order: VecDeque<String>,
    last_auto_refresh: HashMap<String, Instant>,
}

/// One registry belongs to one Runtime/profile. Job IDs are random opaque
/// handles; the internal exact vault scope is never serialized.
#[derive(Default)]
pub(super) struct VaultPinJobs {
    store: Mutex<JobStore>,
    /// Serialize all encrypted remote maintenance (pins and queued edit
    /// reconciliation) for this profile without holding registry locks.
    remote_gate: Arc<Mutex<()>>,
}

impl VaultPinJobs {
    pub fn start(
        this: &Arc<Self>,
        scope: &VaultSessionScope,
        backend: VaultBackend,
        existing_pin_id: Option<String>,
        auth_generation: Arc<AtomicU64>,
        expected_generation: u64,
    ) -> Result<String, String> {
        let scope_key = scope_key(scope);
        this.start_inner(scope_key, None, move |cancelled, progress| {
            if auth_generation.load(Ordering::Acquire) != expected_generation {
                cancelled.store(true, Ordering::Release);
            }
            backend
                .pin_offline_tree_with_progress(existing_pin_id.as_deref(), cancelled, progress)
                .map_err(|_| ())
        })?
        .ok_or_else(|| "Encrypted snapshot refresh was skipped".into())
    }

    /// Start a low-priority refresh no more than once per hour for this exact
    /// scope and pin. A user-started job may run more often. The cooldown is
    /// process-local, so restart permits an explicit/currently-due refresh.
    pub fn start_auto_refresh(
        this: &Arc<Self>,
        scope: &VaultSessionScope,
        backend: VaultBackend,
        pin_id: String,
        auth_generation: Arc<AtomicU64>,
        expected_generation: u64,
    ) -> Result<Option<String>, String> {
        let scope_key = scope_key(scope);
        let cooldown_key = format!("{scope_key}\0{pin_id}");
        this.start_inner(scope_key, Some(cooldown_key), move |cancelled, progress| {
            if auth_generation.load(Ordering::Acquire) != expected_generation {
                cancelled.store(true, Ordering::Release);
            }
            backend
                .pin_offline_tree_with_progress(Some(&pin_id), cancelled, progress)
                .map_err(|_| ())
        })
    }

    fn start_inner<F>(
        &self,
        scope_key: String,
        auto_refresh_key: Option<String>,
        operation: F,
    ) -> Result<Option<String>, String>
    where
        F: FnOnce(&AtomicBool, &mut dyn FnMut(VaultPinProgress)) -> Result<CiphertextPinInfo, ()>
            + Send
            + 'static,
    {
        let (job_id, job) = {
            let mut store = self
                .store
                .lock()
                .map_err(|_| "Encrypted snapshot job state is poisoned")?;
            prune_finished(&mut store);
            if let Some(key) = auto_refresh_key.as_ref() {
                store
                    .last_auto_refresh
                    .retain(|_, last| last.elapsed() < Duration::from_secs(24 * 60 * 60));
                if store.last_auto_refresh.len() >= MAX_AUTO_REFRESH_KEYS
                    && !store.last_auto_refresh.contains_key(key)
                {
                    return Ok(None);
                }
                if store
                    .last_auto_refresh
                    .get(key)
                    .is_some_and(|last| last.elapsed() < AUTO_REFRESH_INTERVAL)
                {
                    return Ok(None);
                }
            }
            if store
                .jobs
                .values()
                .any(|job| job.state.lock().map(|state| state.active()).unwrap_or(true))
            {
                return Err("An encrypted snapshot job is already active for this profile".into());
            }
            if store.jobs.len() >= MAX_RETAINED_JOBS {
                return Err("Too many recent encrypted snapshot jobs".into());
            }
            let job_id = random_job_id(&store)?;
            let job = Arc::new(Job {
                scope_key,
                cancelled: Arc::new(AtomicBool::new(false)),
                state: Mutex::new(JobState::Queued),
                changed: Condvar::new(),
            });
            store.order.push_back(job_id.clone());
            store.jobs.insert(job_id.clone(), Arc::clone(&job));
            if let Some(key) = auto_refresh_key {
                store.last_auto_refresh.insert(key, Instant::now());
            }
            (job_id, job)
        };

        let worker_job = Arc::clone(&job);
        let worker_id = job_id.clone();
        let remote_gate = Arc::clone(&self.remote_gate);
        if let Err(error) = thread::Builder::new()
            .name("raiun-vault-pin".into())
            .spawn(move || {
                let _remote = match remote_gate.lock() {
                    Ok(guard) => guard,
                    Err(_) => {
                        if let Ok(mut state) = worker_job.state.lock() {
                            *state = JobState::Failed;
                            worker_job.changed.notify_all();
                        }
                        return;
                    }
                };
                if let Ok(mut state) = worker_job.state.lock() {
                    if worker_job.cancelled.load(Ordering::Acquire) {
                        *state = JobState::Cancelled;
                        worker_job.changed.notify_all();
                        return;
                    }
                    *state = JobState::Running {
                        items_done: 0,
                        bytes_done: 0,
                    };
                } else {
                    return;
                }
                let result = catch_unwind(AssertUnwindSafe(|| {
                    let mut progress = |value| publish_job_progress(&worker_job, value);
                    operation(&worker_job.cancelled, &mut progress)
                }));
                if let Ok(mut state) = worker_job.state.lock() {
                    *state = match result {
                        Ok(Ok(pin)) => JobState::Ready(pin),
                        Ok(Err(())) | Err(_) if worker_job.cancelled.load(Ordering::Acquire) => {
                            JobState::Cancelled
                        }
                        Ok(Err(())) | Err(_) => JobState::Failed,
                    };
                    worker_job.changed.notify_all();
                }
            })
        {
            if let Ok(mut state) = job.state.lock() {
                *state = JobState::Failed;
                job.changed.notify_all();
            }
            return Err(format!("Could not start encrypted snapshot job: {error}"));
        }
        Ok(Some(worker_id))
    }

    /// Run another encrypted maintenance operation through the same account
    /// gate used by pin/refresh workers. This prevents remote vault writes
    /// from racing pin generation replacement while leaving registry locks
    /// free for status and cancellation calls.
    pub fn run_serialized<T>(
        &self,
        cancelled: &AtomicBool,
        operation: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        let _remote = self
            .remote_gate
            .lock()
            .map_err(|_| "Encrypted remote-operation gate is poisoned")?;
        if cancelled.load(Ordering::Acquire) {
            return Err("Encrypted maintenance operation was cancelled".into());
        }
        operation()
    }

    pub fn status(
        &self,
        scope: &VaultSessionScope,
        job_id: &str,
    ) -> Result<Option<PinJobSnapshot>, String> {
        let store = self
            .store
            .lock()
            .map_err(|_| "Encrypted snapshot job state is poisoned")?;
        let Some(job) = store.jobs.get(job_id) else {
            return Ok(None);
        };
        if job.scope_key != scope_key(scope) {
            return Ok(None);
        }
        let snapshot = job
            .state
            .lock()
            .map_err(|_| "Encrypted snapshot job state is poisoned")?
            .snapshot();
        Ok(Some(snapshot))
    }

    pub fn active_job_id(&self, scope: &VaultSessionScope) -> Result<Option<String>, String> {
        let store = self
            .store
            .lock()
            .map_err(|_| "Encrypted snapshot job state is poisoned")?;
        for (job_id, job) in &store.jobs {
            if job.scope_key != scope_key(scope) {
                continue;
            }
            if job
                .state
                .lock()
                .map_err(|_| "Encrypted snapshot job state is poisoned")?
                .active()
            {
                return Ok(Some(job_id.clone()));
            }
        }
        Ok(None)
    }

    pub fn cancel(&self, scope: &VaultSessionScope, job_id: &str) -> Result<bool, String> {
        let job = {
            let store = self
                .store
                .lock()
                .map_err(|_| "Encrypted snapshot job state is poisoned")?;
            let Some(job) = store.jobs.get(job_id) else {
                return Ok(false);
            };
            if job.scope_key != scope_key(scope) {
                return Ok(false);
            }
            Arc::clone(job)
        };
        let active = job
            .state
            .lock()
            .map_err(|_| "Encrypted snapshot job state is poisoned")?
            .active();
        if active {
            job.cancelled.store(true, Ordering::Release);
        }
        Ok(active)
    }

    /// Set cancellation and wait until every matching worker has reached an
    /// operation boundary and stopped before the caller locks/replaces its key.
    pub fn cancel_scope_and_wait(&self, scope: &VaultSessionScope) -> Result<(), String> {
        self.cancel_matching_and_wait(Some(&scope_key(scope)))
    }

    pub fn cancel_all_and_wait(&self) -> Result<(), String> {
        self.cancel_matching_and_wait(None)
    }

    fn cancel_matching_and_wait(&self, scope_key: Option<&str>) -> Result<(), String> {
        let jobs = {
            let store = self
                .store
                .lock()
                .map_err(|_| "Encrypted snapshot job state is poisoned")?;
            store
                .jobs
                .values()
                .filter(|job| scope_key.is_none_or(|scope| job.scope_key == scope))
                .cloned()
                .collect::<Vec<_>>()
        };
        for job in &jobs {
            let active = job
                .state
                .lock()
                .map_err(|_| "Encrypted snapshot job state is poisoned")?
                .active();
            if active {
                job.cancelled.store(true, Ordering::Release);
            }
        }
        for job in jobs {
            let mut state = job
                .state
                .lock()
                .map_err(|_| "Encrypted snapshot job state is poisoned")?;
            while state.active() {
                state = job
                    .changed
                    .wait(state)
                    .map_err(|_| "Encrypted snapshot job state is poisoned")?;
            }
        }
        Ok(())
    }
}

fn publish_job_progress(job: &Job, progress: VaultPinProgress) {
    if let Ok(mut state) = job.state.lock() {
        if matches!(*state, JobState::Running { .. }) {
            *state = JobState::Running {
                items_done: progress.items_done,
                bytes_done: progress.bytes_done,
            };
            job.changed.notify_all();
        }
    }
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

fn prune_finished(store: &mut JobStore) {
    while store.jobs.len() >= MAX_RETAINED_JOBS {
        let Some(oldest) = store.order.pop_front() else {
            break;
        };
        let Some(job) = store.jobs.get(&oldest) else {
            continue;
        };
        let finished = job
            .state
            .lock()
            .map(|state| !state.active())
            .unwrap_or(false);
        if finished {
            store.jobs.remove(&oldest);
        } else {
            store.order.push_front(oldest);
            break;
        }
    }
}

fn random_job_id(store: &JobStore) -> Result<String, String> {
    for _ in 0..8 {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| "Could not generate encrypted snapshot job ID")?;
        let id = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if !store.jobs.contains_key(&id) {
            return Ok(id);
        }
    }
    Err("Could not allocate an encrypted snapshot job ID".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::mpsc,
        time::{Duration, Instant},
    };

    fn scope(account: &str, resource: &str) -> VaultSessionScope {
        VaultSessionScope::new(account, "https://cloud.example", "space-a", resource).unwrap()
    }

    #[test]
    fn only_one_job_runs_and_scoped_cancel_waits_for_worker() {
        let jobs = Arc::new(VaultPinJobs::default());
        let scope = scope("profile-a", "root-a");
        let (started_tx, started_rx) = mpsc::channel();
        let (finish_tx, finish_rx) = mpsc::channel();
        let job_id = jobs
            .start_inner(scope_key(&scope), None, move |cancelled, progress| {
                progress(VaultPinProgress {
                    items_done: 2,
                    bytes_done: 4096,
                });
                started_tx.send(()).unwrap();
                finish_rx.recv().unwrap();
                assert!(cancelled.load(Ordering::Acquire));
                Err(())
            })
            .unwrap()
            .unwrap();
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let running = jobs.status(&scope, &job_id).unwrap().unwrap();
        assert_eq!(running.items_done, 2);
        assert_eq!(running.bytes_done, 4096);
        assert!(
            jobs.start_inner(scope_key(&scope), None, |_, _| Err(()))
                .unwrap_err()
                .contains("already active")
        );

        let cancel_jobs = Arc::clone(&jobs);
        let cancel_scope = scope.clone();
        let cancel = thread::spawn(move || {
            cancel_jobs.cancel_scope_and_wait(&cancel_scope).unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        while jobs
            .status(&scope, &job_id)
            .unwrap()
            .is_some_and(|snapshot| snapshot.state == "running")
            && Instant::now() < deadline
        {
            if jobs
                .store
                .lock()
                .unwrap()
                .jobs
                .get(&job_id)
                .unwrap()
                .cancelled
                .load(Ordering::Acquire)
            {
                break;
            }
            thread::yield_now();
        }
        finish_tx.send(()).unwrap();
        cancel.join().unwrap();
        assert_eq!(
            jobs.status(&scope, &job_id).unwrap().unwrap().state,
            "cancelled"
        );
    }

    #[test]
    fn job_status_and_cancel_are_bound_to_the_exact_vault_scope() {
        let jobs = Arc::new(VaultPinJobs::default());
        let scope = scope("profile-a", "root-a");
        let other = self::scope("profile-b", "root-a");
        let (started_tx, started_rx) = mpsc::channel();
        let (finish_tx, finish_rx) = mpsc::channel();
        let job_id = jobs
            .start_inner(scope_key(&scope), None, move |_, _| {
                started_tx.send(()).unwrap();
                finish_rx.recv().unwrap();
                Err(())
            })
            .unwrap()
            .unwrap();
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(jobs.status(&other, &job_id).unwrap().is_none());
        assert!(!jobs.cancel(&other, &job_id).unwrap());
        assert!(jobs.cancel(&scope, &job_id).unwrap());
        finish_tx.send(()).unwrap();
        jobs.cancel_scope_and_wait(&scope).unwrap();
        assert_eq!(
            jobs.status(&scope, &job_id).unwrap().unwrap().state,
            "cancelled"
        );
    }

    #[test]
    fn global_cancel_waits_for_the_worker_before_lock_or_logout_returns() {
        let jobs = Arc::new(VaultPinJobs::default());
        let scope = scope("profile-a", "root-a");
        let (started_tx, started_rx) = mpsc::channel();
        let (finish_tx, finish_rx) = mpsc::channel();
        let job_id = jobs
            .start_inner(scope_key(&scope), None, move |cancelled, _| {
                started_tx.send(()).unwrap();
                finish_rx.recv().unwrap();
                assert!(cancelled.load(Ordering::Acquire));
                Err(())
            })
            .unwrap()
            .unwrap();
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let cancel_jobs = Arc::clone(&jobs);
        let waiter = thread::spawn(move || cancel_jobs.cancel_all_and_wait().unwrap());
        let deadline = Instant::now() + Duration::from_secs(1);
        while !jobs
            .store
            .lock()
            .unwrap()
            .jobs
            .get(&job_id)
            .unwrap()
            .cancelled
            .load(Ordering::Acquire)
            && Instant::now() < deadline
        {
            thread::yield_now();
        }
        assert!(
            Instant::now() < deadline,
            "global cancel did not reach worker"
        );
        assert!(!waiter.is_finished());
        finish_tx.send(()).unwrap();
        waiter.join().unwrap();
        assert_eq!(
            jobs.status(&scope, &job_id).unwrap().unwrap().state,
            "cancelled"
        );
    }

    #[test]
    fn automatic_refresh_obeys_the_per_pin_cooldown() {
        let jobs = Arc::new(VaultPinJobs::default());
        let scope = scope("profile-a", "root-a");
        let first = jobs
            .start_inner(scope_key(&scope), Some("same-pin".into()), |_, _| Err(()))
            .unwrap()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while jobs
            .status(&scope, &first)
            .unwrap()
            .is_some_and(|snapshot| snapshot.state == "queued" || snapshot.state == "running")
            && Instant::now() < deadline
        {
            thread::yield_now();
        }
        assert_eq!(
            jobs.status(&scope, &first).unwrap().unwrap().state,
            "failed"
        );
        assert!(
            jobs.start_inner(scope_key(&scope), Some("same-pin".into()), |_, _| Err(()))
                .unwrap()
                .is_none()
        );
        assert!(
            jobs.start_inner(scope_key(&scope), Some("other-pin".into()), |_, _| Err(()))
                .unwrap()
                .is_some()
        );
    }
}
