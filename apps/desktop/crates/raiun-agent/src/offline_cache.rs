//! Per-account, bounded background jobs for explicit offline folder pins.
//!
//! Cache identity is supplied by the Runtime's authenticated Engine, never by
//! request fields. One job can run for a profile at a time; cancellation is
//! cooperative between network operations and invalidated by auth generation.

use raiun_cache::{PinInfo, PinState};
use raiun_engine::Engine;
use serde::Serialize;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

pub const DEFAULT_CACHE_QUOTA_BYTES: u64 = 1 << 30;
const MAX_PIN_PATH_BYTES: usize = 32 * 1024;
const MAX_PIN_SPACE_ID_BYTES: usize = 1024;

#[derive(Clone, Debug, Serialize)]
pub struct PinJobStatus {
    #[serde(skip_serializing)]
    generation: u64,
    pub job_id: String,
    pub space_id: String,
    pub path: String,
    pub state: String,
    pub pin_id: Option<String>,
    pub item_count: usize,
    pub files_done: usize,
    pub files_total: usize,
    pub error: Option<String>,
    pub cancel_requested: bool,
}

struct Job {
    status: Mutex<PinJobStatus>,
    cancelled: AtomicBool,
}

#[derive(Default)]
pub struct CacheJobs {
    active: Mutex<Option<Arc<Job>>>,
    next_id: AtomicU64,
    worker: Arc<Mutex<()>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WriteReconcileStatus {
    #[serde(skip_serializing)]
    generation: u64,
    pub job_id: String,
    pub space_id: String,
    pub state: String,
    pub uploaded: u64,
    pub conflicts: u64,
    pub remaining: u64,
    pub error: Option<String>,
    pub cancel_requested: bool,
}

struct WriteJob {
    status: Mutex<WriteReconcileStatus>,
    cancelled: AtomicBool,
}

#[derive(Default)]
pub struct WriteReconcileJobs {
    active: Mutex<Option<Arc<WriteJob>>>,
    next_id: AtomicU64,
}

impl WriteReconcileJobs {
    pub fn start(
        self: &Arc<Self>,
        generation: u64,
        space_id: String,
        operation: impl FnOnce(&AtomicBool) -> Result<raiun_engine::WriteReconcileReport, String>
        + Send
        + 'static,
    ) -> Result<WriteReconcileStatus, String> {
        if space_id.is_empty() || space_id.len() > MAX_PIN_SPACE_ID_BYTES {
            return Err("Space identifier is invalid or too large".into());
        }
        let job_id = format!(
            "writes-{generation}-{}",
            self.next_id.fetch_add(1, Ordering::Relaxed)
        );
        let job = Arc::new(WriteJob {
            status: Mutex::new(WriteReconcileStatus {
                generation,
                job_id,
                space_id,
                state: "queued".into(),
                uploaded: 0,
                conflicts: 0,
                remaining: 0,
                error: None,
                cancel_requested: false,
            }),
            cancelled: AtomicBool::new(false),
        });
        {
            let mut active = self
                .active
                .lock()
                .map_err(|_| "Write retry state poisoned")?;
            if active.as_ref().is_some_and(|current| {
                current
                    .status
                    .lock()
                    .map(|status| matches!(status.state.as_str(), "queued" | "running"))
                    .unwrap_or(true)
            }) {
                return Err("A write retry is already running for this account".into());
            }
            *active = Some(job.clone());
        }

        let job_thread = job.clone();
        std::thread::Builder::new()
            .name("raiun-write-reconcile".into())
            .spawn(move || {
                if let Ok(mut status) = job_thread.status.lock() {
                    status.state = "running".into();
                }
                let result = operation(&job_thread.cancelled);
                if let Ok(mut status) = job_thread.status.lock() {
                    match result {
                        Ok(report) => {
                            status.uploaded = report.uploaded;
                            status.conflicts = report.conflicts;
                            status.remaining = report.remaining;
                            status.state = if job_thread.cancelled.load(Ordering::Acquire) {
                                "cancelled"
                            } else {
                                "complete"
                            }
                            .into();
                            status.cancel_requested = job_thread.cancelled.load(Ordering::Acquire);
                        }
                        Err(error) => {
                            status.state = if job_thread.cancelled.load(Ordering::Acquire) {
                                "cancelled"
                            } else {
                                "failed"
                            }
                            .into();
                            status.cancel_requested = job_thread.cancelled.load(Ordering::Acquire);
                            status.error = Some(bounded_error(error));
                        }
                    }
                }
            })
            .map_err(|error| {
                if let Ok(mut active) = self.active.lock() {
                    if active
                        .as_ref()
                        .is_some_and(|current| Arc::ptr_eq(current, &job))
                    {
                        *active = None;
                    }
                }
                error.to_string()
            })?;
        job.status
            .lock()
            .map(|status| status.clone())
            .map_err(|_| "Write retry state poisoned".into())
    }

    pub fn status(&self, job_id: &str, generation: u64) -> Result<WriteReconcileStatus, String> {
        let active = self
            .active
            .lock()
            .map_err(|_| "Write retry state poisoned")?;
        let job = active
            .as_ref()
            .filter(|job| {
                job.status
                    .lock()
                    .map(|status| status.job_id == job_id && status.generation == generation)
                    .unwrap_or(false)
            })
            .ok_or("Unknown write retry job")?;
        job.status
            .lock()
            .map(|status| status.clone())
            .map_err(|_| "Write retry state poisoned".into())
    }

    pub fn cancel(&self, job_id: &str, generation: u64) -> Result<WriteReconcileStatus, String> {
        let active = self
            .active
            .lock()
            .map_err(|_| "Write retry state poisoned")?;
        let job = active
            .as_ref()
            .filter(|job| {
                job.status
                    .lock()
                    .map(|status| status.job_id == job_id && status.generation == generation)
                    .unwrap_or(false)
            })
            .ok_or("Unknown write retry job")?;
        if let Ok(status) = job.status.lock()
            && !matches!(status.state.as_str(), "queued" | "running")
        {
            return Err("Write retry job is no longer running".into());
        }
        job.cancelled.store(true, Ordering::Release);
        let mut status = job
            .status
            .lock()
            .map_err(|_| "Write retry state poisoned")?;
        status.cancel_requested = true;
        Ok(status.clone())
    }

    pub fn cancel_active(&self) {
        if let Ok(active) = self.active.lock()
            && let Some(job) = active.as_ref()
        {
            job.cancelled.store(true, Ordering::Release);
            if let Ok(mut status) = job.status.lock() {
                status.cancel_requested = true;
            }
        }
    }

    pub fn cancel_space(&self, space_id: &str) {
        if let Ok(active) = self.active.lock()
            && let Some(job) = active.as_ref()
            && job
                .status
                .lock()
                .map(|status| status.space_id == space_id)
                .unwrap_or(false)
        {
            job.cancelled.store(true, Ordering::Release);
            if let Ok(mut status) = job.status.lock() {
                status.cancel_requested = true;
            }
        }
    }
}

impl CacheJobs {
    /// Serialize explicit pin builds and the account's automatic refresh so
    /// their complete metadata snapshots cannot interleave.
    pub fn run_serialized<T>(&self, operation: impl FnOnce() -> T) -> T {
        let _worker = self
            .worker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        operation()
    }

    pub fn start(
        self: &Arc<Self>,
        engine: Engine,
        auth_generation: Arc<AtomicU64>,
        generation: u64,
        space_id: String,
        path: String,
    ) -> Result<PinJobStatus, String> {
        if space_id.is_empty() || space_id.len() > MAX_PIN_SPACE_ID_BYTES {
            return Err("Space identifier is invalid or too large".into());
        }
        if path.is_empty()
            || path.len() > MAX_PIN_PATH_BYTES
            || !path.starts_with('/')
            || path.contains('\0')
            || (path != "/"
                && path
                    .split('/')
                    .skip(1)
                    .any(|part| part.is_empty() || part == "." || part == ".."))
        {
            return Err("Offline pin path is invalid or exceeds the path limit".into());
        }
        let sequence = self.next_id.fetch_add(1, Ordering::Relaxed);
        let job_id = format!("pin-{generation}-{sequence}");
        let job = Arc::new(Job {
            status: Mutex::new(PinJobStatus {
                generation,
                job_id: job_id.clone(),
                space_id: space_id.clone(),
                path: path.clone(),
                state: "preparing".into(),
                pin_id: None,
                item_count: 0,
                files_done: 0,
                files_total: 0,
                error: None,
                cancel_requested: false,
            }),
            cancelled: AtomicBool::new(false),
        });
        {
            let mut active = self
                .active
                .lock()
                .map_err(|_| "Offline pin job state poisoned")?;
            if active.as_ref().is_some_and(|job| {
                job.status
                    .lock()
                    .map(|status| matches!(status.state.as_str(), "preparing" | "building"))
                    .unwrap_or(true)
            }) {
                return Err("An offline pin is already running for this account".into());
            }
            *active = Some(job.clone());
        }

        let job_for_thread = job.clone();
        let jobs_for_thread = self.clone();
        std::thread::Builder::new()
            .name("raiun-offline-pin".into())
            .spawn(move || {
                let result = jobs_for_thread.run_serialized(|| {
                    engine.pin_offline_tree_cancellable(
                        &space_id,
                        &path,
                        || {
                            job_for_thread.cancelled.load(Ordering::Acquire)
                                || auth_generation.load(Ordering::Acquire) != generation
                        },
                        |info| update_from_pin(&job_for_thread, &info),
                    )
                });
                if let Ok(mut status) = job_for_thread.status.lock() {
                    match result {
                        Ok(info)
                            if job_for_thread.cancelled.load(Ordering::Acquire)
                                || auth_generation.load(Ordering::Acquire) != generation =>
                        {
                            update_fields(&mut status, &info);
                            let _ = engine.cancel_offline_pin(&status.space_id, &info.id);
                            status.state = "cancelled".into();
                            status.cancel_requested = true;
                        }
                        Ok(info) => update_fields(&mut status, &info),
                        Err(error)
                            if job_for_thread.cancelled.load(Ordering::Acquire)
                                || auth_generation.load(Ordering::Acquire) != generation
                                || error.message == "offline pin cancelled" =>
                        {
                            status.state = "cancelled".into();
                            status.cancel_requested = true;
                            if status.pin_id.is_some() {
                                // Cancellation of the active job preserves verified
                                // recent bytes but discards the incomplete pin manifest.
                                let _ = engine.cancel_offline_pin(
                                    &status.space_id,
                                    status.pin_id.as_deref().unwrap_or_default(),
                                );
                            }
                        }
                        Err(error) => {
                            status.state = "failed".into();
                            status.error = Some(bounded_error(error.message));
                        }
                    }
                }
            })
            .map_err(|error| {
                if let Ok(mut active) = self.active.lock() {
                    if active
                        .as_ref()
                        .is_some_and(|current| Arc::ptr_eq(current, &job))
                    {
                        *active = None;
                    }
                }
                error.to_string()
            })?;
        job.status
            .lock()
            .map(|status| status.clone())
            .map_err(|_| "Offline pin job state poisoned".into())
    }

    pub fn status(&self, job_id: &str, generation: u64) -> Result<PinJobStatus, String> {
        let active = self
            .active
            .lock()
            .map_err(|_| "Offline pin job state poisoned")?;
        let job = active
            .as_ref()
            .filter(|job| {
                job.status
                    .lock()
                    .map(|status| status.job_id == job_id && status.generation == generation)
                    .unwrap_or(false)
            })
            .ok_or("Unknown offline pin job")?;
        job.status
            .lock()
            .map(|status| status.clone())
            .map_err(|_| "Offline pin job state poisoned".into())
    }

    pub fn cancel(&self, job_id: &str, generation: u64) -> Result<PinJobStatus, String> {
        let active = self
            .active
            .lock()
            .map_err(|_| "Offline pin job state poisoned")?;
        let job = active
            .as_ref()
            .filter(|job| {
                job.status
                    .lock()
                    .map(|status| status.job_id == job_id && status.generation == generation)
                    .unwrap_or(false)
            })
            .ok_or("Unknown offline pin job")?;
        job.cancelled.store(true, Ordering::Release);
        let mut status = job
            .status
            .lock()
            .map_err(|_| "Offline pin job state poisoned")?;
        status.cancel_requested = true;
        Ok(status.clone())
    }

    pub fn cancel_active(&self) {
        if let Ok(active) = self.active.lock()
            && let Some(job) = active.as_ref()
        {
            job.cancelled.store(true, Ordering::Release);
            if let Ok(mut status) = job.status.lock() {
                status.cancel_requested = true;
            }
        }
    }
}

fn update_from_pin(job: &Job, info: &PinInfo) {
    if let Ok(mut status) = job.status.lock() {
        update_fields(&mut status, info);
    }
}

fn update_fields(status: &mut PinJobStatus, info: &PinInfo) {
    status.pin_id = Some(info.id.clone());
    status.state = pin_state_name(info.state).into();
    status.item_count = info.item_count;
    status.files_done = info.ready_content_count;
    status.files_total = info.required_content_count;
}

fn pin_state_name(state: PinState) -> &'static str {
    match state {
        PinState::Building => "building",
        PinState::Ready => "ready",
        PinState::Stale => "stale",
        PinState::Unavailable => "unavailable",
    }
}

fn bounded_error(error: String) -> String {
    error.chars().take(512).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn pin_status_preserves_stale_state() {
        assert_eq!(pin_state_name(PinState::Building), "building");
        assert_eq!(pin_state_name(PinState::Ready), "ready");
        assert_eq!(pin_state_name(PinState::Stale), "stale");
        assert_eq!(pin_state_name(PinState::Unavailable), "unavailable");
    }

    #[test]
    fn serialized_pin_and_refresh_worker_never_overlaps_operations() {
        let jobs = Arc::new(CacheJobs::default());
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let threads = (0..8)
            .map(|_| {
                let jobs = jobs.clone();
                let active = active.clone();
                let maximum = maximum.clone();
                std::thread::spawn(move || {
                    jobs.run_serialized(|| {
                        let now = active.fetch_add(1, Ordering::AcqRel) + 1;
                        maximum.fetch_max(now, Ordering::AcqRel);
                        for _ in 0..100 {
                            std::thread::yield_now();
                        }
                        active.fetch_sub(1, Ordering::AcqRel);
                    });
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(maximum.load(Ordering::Acquire), 1);
    }

    #[test]
    fn one_job_per_account_and_cancel_is_cooperative() {
        let jobs = Arc::new(CacheJobs::default());
        let generation = Arc::new(AtomicU64::new(4));
        let engine = test_engine();
        // This exercises the capacity gate without reaching a network backend.
        let job = Arc::new(Job {
            status: Mutex::new(PinJobStatus {
                generation: 4,
                job_id: "pin-test".into(),
                space_id: "space".into(),
                path: "/".into(),
                state: "building".into(),
                pin_id: None,
                item_count: 0,
                files_done: 0,
                files_total: 0,
                error: None,
                cancel_requested: false,
            }),
            cancelled: AtomicBool::new(false),
        });
        *jobs.active.lock().unwrap() = Some(job);
        assert!(
            jobs.start(engine, generation, 4, "space".into(), "/".into())
                .unwrap_err()
                .contains("already running")
        );
        assert!(jobs.status("pin-test", 5).is_err());
        assert!(jobs.cancel("pin-test", 4).unwrap().cancel_requested);
    }

    #[test]
    fn write_retry_job_is_bounded_singleflight_and_cancellable() {
        let jobs = Arc::new(WriteReconcileJobs::default());
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let status = jobs
            .start(7, "space-a".into(), move |cancelled| {
                started_tx.send(()).unwrap();
                while !cancelled.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
                Ok(raiun_engine::WriteReconcileReport {
                    remaining: 3,
                    ..Default::default()
                })
            })
            .unwrap();
        assert!(matches!(status.state.as_str(), "queued" | "running"));
        started_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert!(
            jobs.start(7, "space-b".into(), |_| Ok(Default::default()))
                .is_err()
        );
        jobs.cancel(&status.job_id, 7).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let status = jobs.status(&status.job_id, 7).unwrap();
            if status.state == "cancelled" {
                assert_eq!(status.remaining, 3);
                assert!(status.cancel_requested);
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "write retry did not stop"
            );
            std::thread::yield_now();
        }
        assert!(jobs.status(&status.job_id, 8).is_err());
    }

    fn test_engine() -> Engine {
        struct NeverBackend;
        impl raiun_core::backend::CloudBackend for NeverBackend {
            fn server_origin(&self) -> Option<String> {
                Some("https://example.test".into())
            }
            fn spaces(
                &self,
            ) -> Result<Vec<raiun_core::backend::CloudSpace>, raiun_core::backend::CloudError>
            {
                unreachable!()
            }
            fn list(
                &self,
                _: &str,
                _: &str,
                _: &mut dyn FnMut(
                    raiun_core::backend::RemoteEntry,
                ) -> Result<(), raiun_core::backend::CloudError>,
            ) -> Result<(), raiun_core::backend::CloudError> {
                unreachable!()
            }
            fn stat(
                &self,
                _: &str,
                _: &str,
            ) -> Result<raiun_core::backend::RemoteEntry, raiun_core::backend::CloudError>
            {
                unreachable!()
            }
            fn download(
                &self,
                _: &str,
                _: &str,
                _: Option<&str>,
                _: &std::path::Path,
            ) -> Result<raiun_core::backend::RemoteEntry, raiun_core::backend::CloudError>
            {
                unreachable!()
            }
            fn upload(
                &self,
                _: &str,
                _: &str,
                _: &std::path::Path,
                _: raiun_core::backend::WriteCondition,
            ) -> Result<raiun_core::backend::RemoteEntry, raiun_core::backend::CloudError>
            {
                unreachable!()
            }
            fn mkdir(
                &self,
                _: &str,
                _: &str,
            ) -> Result<raiun_core::backend::RemoteEntry, raiun_core::backend::CloudError>
            {
                unreachable!()
            }
            fn delete(
                &self,
                _: &str,
                _: &str,
                _: &str,
            ) -> Result<(), raiun_core::backend::CloudError> {
                unreachable!()
            }
            fn rename(
                &self,
                _: &str,
                _: &str,
                _: &str,
                _: &str,
            ) -> Result<raiun_core::backend::RemoteEntry, raiun_core::backend::CloudError>
            {
                unreachable!()
            }
        }
        let directory = tempfile::tempdir().unwrap();
        Engine::open(directory.path(), Arc::new(NeverBackend)).unwrap()
    }
}
