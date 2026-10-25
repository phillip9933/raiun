//! Fresh, lossy notifications only. The protected capture remains the durable
//! record on every queue/worker error; this queue never scans or replays history.
use std::{
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const CAPACITY: usize = 32;

#[cfg(any(windows, test))]
#[derive(Clone, Copy)]
pub(super) enum FreshCloseCompletionPolicy {
    RemoteOnly,
    #[cfg(all(test, debug_assertions))]
    WritableBytes,
}
#[cfg(any(windows, test))]
impl FreshCloseCompletionPolicy {
    pub(super) fn writable_bytes(self) -> bool {
        match self {
            Self::RemoteOnly => false,
            #[cfg(all(test, debug_assertions))]
            Self::WritableBytes => true,
        }
    }
    pub(super) fn permits_mode(self, complete_local: bool, writable_bytes: bool) -> bool {
        let requested = self.writable_bytes();
        complete_local == requested && writable_bytes == requested
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FreshVaultClosePublishError {
    Full,
    Cancelled,
    Disconnected,
}

struct Source<T> {
    sender: SyncSender<T>,
    active: Arc<AtomicBool>,
    current_generation: Arc<AtomicU64>,
    job_generation: fn(&T) -> u64,
}
impl<T> Clone for Source<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            active: Arc::clone(&self.active),
            current_generation: Arc::clone(&self.current_generation),
            job_generation: self.job_generation,
        }
    }
}
impl<T> Source<T> {
    fn cancel(&self) {
        self.active.store(false, Ordering::Release);
    }
    #[cfg(test)]
    fn active_marker(&self, generation: u64) -> Option<Arc<AtomicBool>> {
        (generation != 0
            && self.active.load(Ordering::Acquire)
            && self.current_generation.load(Ordering::Acquire) == generation)
            .then(|| Arc::clone(&self.active))
    }
    fn publisher(&self, generation: u64) -> Option<Publisher<T>> {
        (generation != 0
            && self.active.load(Ordering::Acquire)
            && self.current_generation.load(Ordering::Acquire) == generation)
            .then(|| Publisher {
                source: self.clone(),
                generation,
            })
    }
}
struct Publisher<T> {
    source: Source<T>,
    generation: u64,
}
impl<T> Clone for Publisher<T> {
    fn clone(&self) -> Self {
        Self {
            source: self.source.clone(),
            generation: self.generation,
        }
    }
}
impl<T> Publisher<T> {
    fn try_send(&self, job: T) -> Result<(), FreshVaultClosePublishError> {
        if !self.source.active.load(Ordering::Acquire)
            || self.source.current_generation.load(Ordering::Acquire) != self.generation
            || (self.source.job_generation)(&job) != self.generation
        {
            return Err(FreshVaultClosePublishError::Cancelled);
        }
        self.source
            .sender
            .try_send(job)
            .map_err(|error| match error {
                TrySendError::Full(_) => FreshVaultClosePublishError::Full,
                TrySendError::Disconnected(_) => FreshVaultClosePublishError::Disconnected,
            })
    }
}

struct Worker<T> {
    source: Source<T>,
    handle: Option<JoinHandle<()>>,
}
impl<T: Send + 'static> Worker<T> {
    fn start<O: Send + Sync + 'static>(
        owner: Weak<O>,
        generation: Arc<AtomicU64>,
        job_generation: fn(&T) -> u64,
        consume: impl Fn(&O, T, Arc<AtomicBool>) + Send + 'static,
    ) -> Result<Self, String> {
        let (source, receiver) = channel(generation, job_generation);
        let active = Arc::clone(&source.active);
        let current = Arc::clone(&source.current_generation);
        let handle = thread::Builder::new()
            .name("raiun-vault-fresh-close".into())
            .spawn(move || {
                while active.load(Ordering::Acquire) {
                    let job = match receiver.recv_timeout(Duration::from_millis(25)) {
                        Ok(job) => job,
                        Err(RecvTimeoutError::Timeout) => {
                            if owner.strong_count() == 0 {
                                break;
                            }
                            continue;
                        }
                        Err(RecvTimeoutError::Disconnected) => break,
                    };
                    if !active.load(Ordering::Acquire)
                        || job_generation(&job) != current.load(Ordering::Acquire)
                    {
                        continue;
                    }
                    let Some(owner) = owner.upgrade() else {
                        break;
                    };
                    if active.load(Ordering::Acquire)
                        && job_generation(&job) == current.load(Ordering::Acquire)
                    {
                        // No queue, provider, custody, or Agent mutex is held.
                        // The actual entry rechecks origin/route/stamp before
                        // ledger admission and its single guarded HTTP attempt.
                        consume(&owner, job, Arc::clone(&active));
                    }
                }
                active.store(false, Ordering::Release);
                // Dropping the receiver drops pending notifications only.
            })
            .map_err(|_| "Could not start the fresh vault close worker".to_owned())?;
        Ok(Self {
            source,
            handle: Some(handle),
        })
    }
}
impl<T> Worker<T> {
    fn stop(mut self) -> Result<(), String> {
        self.source.cancel();
        self.join()
    }
    fn join(&mut self) -> Result<(), String> {
        if let Some(handle) = self.handle.take()
            && handle.thread().id() != thread::current().id()
        {
            handle
                .join()
                .map_err(|_| "The fresh vault close worker stopped unexpectedly".to_owned())?;
        }
        // The last Agent Arc can drop on this consumer. Its own handle must
        // detach rather than join itself; cancellation makes the loop exit.
        Ok(())
    }
}
impl<T> Drop for Worker<T> {
    fn drop(&mut self) {
        self.source.cancel();
        let _ = self.join();
    }
}
fn channel<T>(
    generation: Arc<AtomicU64>,
    job_generation: fn(&T) -> u64,
) -> (Source<T>, Receiver<T>) {
    let (sender, receiver) = mpsc::sync_channel(CAPACITY);
    (
        Source {
            sender,
            active: Arc::new(AtomicBool::new(true)),
            current_generation: generation,
            job_generation,
        },
        receiver,
    )
}

#[cfg(windows)]
mod agent {
    use super::*;
    use crate::agent_windows::{WindowsAgent, windows_vault_custody::FreshCaptureOrigin};
    use raiun_cloudfiles_windows::FreshVaultCaptureDispatch;
    use raiun_vault::session::VaultSessionScope;

    // No keys, token, body, lease, Clone, Debug or persistence representation.
    pub(in crate::agent_windows) struct FreshVaultCloseJob {
        pub(in crate::agent_windows) origin: FreshCaptureOrigin,
        pub(in crate::agent_windows) vault: VaultSessionScope,
        pub(in crate::agent_windows) remote_root: String,
        pub(in crate::agent_windows) capture_id: String,
        pub(in crate::agent_windows) dispatch: FreshVaultCaptureDispatch,
        pub(in crate::agent_windows) expected_generation: u64,
    }
    #[derive(Clone)]
    pub(in crate::agent_windows) struct VaultClosePublisher(Publisher<FreshVaultCloseJob>);
    impl VaultClosePublisher {
        pub(in crate::agent_windows) fn generation(&self) -> u64 {
            self.0.generation
        }
        pub(in crate::agent_windows) fn try_send(
            &self,
            job: FreshVaultCloseJob,
        ) -> Result<(), FreshVaultClosePublishError> {
            self.0.try_send(job)
        }
    }
    #[derive(Clone)]
    pub(in crate::agent_windows) struct VaultClosePublisherSource(Source<FreshVaultCloseJob>);
    impl VaultClosePublisherSource {
        pub(in crate::agent_windows) fn cancel(&self) {
            self.0.cancel();
        }
        pub(in crate::agent_windows) fn publisher(
            &self,
            generation: u64,
        ) -> Option<VaultClosePublisher> {
            self.0.publisher(generation).map(VaultClosePublisher)
        }
    }
    #[cfg(all(test, debug_assertions))]
    #[derive(Clone, Default)]
    pub(in crate::agent_windows) struct FreshCloseObservation {
        pub(in crate::agent_windows) attempted: usize,
        pub(in crate::agent_windows) completed: usize,
        pub(in crate::agent_windows) failed: usize,
        pub(in crate::agent_windows) remote_verified: bool,
        pub(in crate::agent_windows) native_confirmation: Option<bool>,
        pub(in crate::agent_windows) local_completed: bool,
        pub(in crate::agent_windows) thread: Option<thread::ThreadId>,
    }
    pub(in crate::agent_windows) struct FreshCloseWorker {
        worker: Worker<FreshVaultCloseJob>,
        #[cfg(all(test, debug_assertions))]
        observation: Arc<std::sync::Mutex<FreshCloseObservation>>,
    }
    impl FreshCloseWorker {
        pub(in crate::agent_windows) fn start(
            owner: Weak<WindowsAgent>,
            generation: Arc<AtomicU64>,
        ) -> Result<Self, String> {
            Self::start_with_policy(owner, generation, FreshCloseCompletionPolicy::RemoteOnly)
        }
        #[cfg(all(test, debug_assertions))]
        pub(in crate::agent_windows) fn start_with_writable_completion_for_test(
            owner: Weak<WindowsAgent>,
            generation: Arc<AtomicU64>,
        ) -> Result<Self, String> {
            Self::start_with_policy(owner, generation, FreshCloseCompletionPolicy::WritableBytes)
        }
        fn start_with_policy(
            owner: Weak<WindowsAgent>,
            generation: Arc<AtomicU64>,
            policy: FreshCloseCompletionPolicy,
        ) -> Result<Self, String> {
            #[cfg(all(test, debug_assertions))]
            let observation = Arc::new(std::sync::Mutex::new(FreshCloseObservation::default()));
            #[cfg(all(test, debug_assertions))]
            let observed = Arc::clone(&observation);
            let worker = Worker::start(
                owner,
                generation,
                |job: &FreshVaultCloseJob| job.expected_generation,
                move |agent, job, active| {
                    #[cfg(all(test, debug_assertions))]
                    if let Ok(mut value) = observed.lock() {
                        value.attempted += 1;
                        value.thread = Some(thread::current().id());
                    }
                    // The ORIGINAL worker cancellation identity is forwarded;
                    // no Agent lookup can replace it with a newer worker's Arc.
                    // The policy was fixed before thread start. No replay/retry.
                    let _result = agent.upload_from_fresh_close(job, active, policy);
                    #[cfg(all(test, debug_assertions))]
                    if let Ok(mut value) = observed.lock() {
                        value.completed += 1;
                        value.failed += usize::from(_result.is_err());
                        value.remote_verified = _result.as_ref().is_ok_and(|result| {
                            result["state"] == "remote_verified_pending_local"
                                || result["state"] == "local_completed"
                        });
                        value.local_completed = _result
                            .as_ref()
                            .is_ok_and(|result| result["state"] == "local_completed");
                        value.native_confirmation = _result
                            .as_ref()
                            .ok()
                            .and_then(|result| result["native_confirmation"].as_bool());
                    }
                },
            )?;
            Ok(Self {
                worker,
                #[cfg(all(test, debug_assertions))]
                observation,
            })
        }
        pub(in crate::agent_windows) fn source(&self) -> VaultClosePublisherSource {
            VaultClosePublisherSource(self.worker.source.clone())
        }
        pub(in crate::agent_windows) fn stop(self) -> Result<(), String> {
            self.worker.stop()
        }
        #[cfg(all(test, debug_assertions))]
        pub(in crate::agent_windows) fn observation(
            &self,
        ) -> Result<FreshCloseObservation, String> {
            self.observation
                .lock()
                .map(|value| value.clone())
                .map_err(|_| "Fresh close observation unavailable".into())
        }
    }
}
#[cfg(windows)]
pub(super) use agent::{
    FreshCloseWorker, FreshVaultCloseJob, VaultClosePublisher, VaultClosePublisherSource,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Barrier, Mutex};

    struct Job(u64);
    fn generation(job: &Job) -> u64 {
        job.0
    }
    #[test]
    fn default_mode_cannot_admit_local_or_readonly_completion() {
        assert!(FreshCloseCompletionPolicy::RemoteOnly.permits_mode(false, false));
        assert!(!FreshCloseCompletionPolicy::RemoteOnly.permits_mode(true, false));
        assert!(!FreshCloseCompletionPolicy::RemoteOnly.permits_mode(true, true));
        #[cfg(debug_assertions)]
        {
            assert!(FreshCloseCompletionPolicy::WritableBytes.permits_mode(true, true));
            assert!(!FreshCloseCompletionPolicy::WritableBytes.permits_mode(true, false));
            assert!(!FreshCloseCompletionPolicy::WritableBytes.permits_mode(false, false));
        }
    }

    #[test]
    fn bounded_full_stale_cancelled_and_disconnected_notifications_drop_only() {
        let current = Arc::new(AtomicU64::new(1));
        let (source, receiver) = channel(Arc::clone(&current), generation);
        let publisher = source.publisher(1).unwrap();
        for _ in 0..CAPACITY {
            publisher.try_send(Job(1)).unwrap();
        }
        assert_eq!(
            publisher.try_send(Job(1)),
            Err(FreshVaultClosePublishError::Full)
        );
        assert_eq!(
            publisher.try_send(Job(2)),
            Err(FreshVaultClosePublishError::Cancelled)
        );
        current.store(2, Ordering::Release);
        assert_eq!(
            publisher.try_send(Job(1)),
            Err(FreshVaultClosePublishError::Cancelled)
        );
        assert_eq!(receiver.try_iter().count(), CAPACITY);
        source.cancel();
        assert!(source.publisher(2).is_none());
        let (source, receiver) = channel(Arc::new(AtomicU64::new(3)), generation);
        let publisher = source.publisher(3).unwrap();
        drop(receiver);
        assert_eq!(
            publisher.try_send(Job(3)),
            Err(FreshVaultClosePublishError::Disconnected)
        );
    }

    #[test]
    fn consumer_is_off_caller_thread_and_drops_stale_queued_generation() {
        struct PendingJob {
            generation: u64,
            discarded: Option<mpsc::SyncSender<()>>,
        }
        impl Drop for PendingJob {
            fn drop(&mut self) {
                if let Some(signal) = self.discarded.take() {
                    signal.send(()).unwrap();
                }
            }
        }
        let owner = Arc::new(AtomicU64::new(0));
        let current = Arc::new(AtomicU64::new(1));
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let (started, observed) = mpsc::sync_channel(1);
        let (discarded, discarded_observation) = mpsc::sync_channel(1);
        let caller = thread::current().id();
        let e = Arc::clone(&entered);
        let r = Arc::clone(&release);
        let worker = Worker::start(
            Arc::downgrade(&owner),
            Arc::clone(&current),
            |job: &PendingJob| job.generation,
            move |owner, _, _| {
                started.send(thread::current().id()).unwrap();
                e.wait();
                r.wait();
                owner.fetch_add(1, Ordering::AcqRel);
            },
        )
        .unwrap();
        let publisher = worker.source.publisher(1).unwrap();
        publisher
            .try_send(PendingJob {
                generation: 1,
                discarded: None,
            })
            .unwrap();
        assert_ne!(
            observed.recv_timeout(Duration::from_secs(2)).unwrap(),
            caller
        );
        entered.wait();
        publisher
            .try_send(PendingJob {
                generation: 1,
                discarded: Some(discarded),
            })
            .unwrap();
        current.store(2, Ordering::Release);
        release.wait();
        // Observe the stale notification's destruction BEFORE cancellation.
        // A second callback would block and fail this bounded observation.
        discarded_observation
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        assert_eq!(owner.load(Ordering::Acquire), 1);
        worker.stop().unwrap();
    }

    #[test]
    fn in_flight_consumer_observes_existing_cancel_marker_before_join_finishes() {
        let owner = Arc::new(());
        let current = Arc::new(AtomicU64::new(1));
        let (entered, started) = mpsc::sync_channel(1);
        let (observed, cancellation) = mpsc::sync_channel(1);
        let (release, allowed_to_finish) = mpsc::sync_channel(1);
        let worker = Worker::start(
            Arc::downgrade(&owner),
            current,
            generation,
            move |_, _, active| {
                entered.send(Arc::clone(&active)).unwrap();
                let deadline = std::time::Instant::now() + Duration::from_secs(2);
                while active.load(Ordering::Acquire) {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "consumer did not observe cancellation"
                    );
                    thread::yield_now();
                }
                observed.send(()).unwrap();
                // Keep the actual consumer alive until the test has observed the
                // cancellation and verified that stop is still waiting for it.
                allowed_to_finish
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap();
            },
        )
        .unwrap();
        assert!(worker.source.active_marker(0).is_none());
        assert!(worker.source.active_marker(2).is_none());
        let active = worker.source.active_marker(1).unwrap();
        assert!(Arc::ptr_eq(&active, &worker.source.active));
        // The consumer receives this exact Arc directly from its worker.
        assert!(active.load(Ordering::Acquire));
        worker
            .source
            .publisher(1)
            .unwrap()
            .try_send(Job(1))
            .unwrap();
        let forwarded = started.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(Arc::ptr_eq(&forwarded, &active));
        // Even a replacement channel with the SAME generation has a distinct
        // marker; the running consumer must retain and observe its original.
        let (replacement, _replacement_receiver) = channel(Arc::new(AtomicU64::new(1)), generation);
        let replacement_active = replacement.active_marker(1).unwrap();
        assert!(!Arc::ptr_eq(&forwarded, &replacement_active));
        let (joined, completed) = mpsc::sync_channel(1);
        let stopper = thread::spawn(move || {
            worker.stop().unwrap();
            joined.send(()).unwrap();
        });
        cancellation.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(!forwarded.load(Ordering::Acquire));
        assert!(replacement_active.load(Ordering::Acquire));
        assert!(matches!(
            completed.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        release.send(()).unwrap();
        completed.recv_timeout(Duration::from_secs(2)).unwrap();
        stopper.join().unwrap();
    }

    #[test]
    fn idle_worker_does_not_keep_owner_alive() {
        let owner = Arc::new(());
        let worker = Worker::start(
            Arc::downgrade(&owner),
            Arc::new(AtomicU64::new(1)),
            generation,
            |_, _, _| panic!("no job"),
        )
        .unwrap();
        let source = worker.source.clone();
        assert_eq!(Arc::strong_count(&owner), 1);
        drop(owner);
        worker.stop().unwrap();
        assert!(source.publisher(1).is_none());
    }

    #[test]
    fn final_owner_drop_on_consumer_cancels_without_self_join() {
        struct Owner {
            worker: Mutex<Option<Worker<Job>>>,
            dropped: mpsc::SyncSender<()>,
        }
        impl Drop for Owner {
            fn drop(&mut self) {
                self.worker.get_mut().unwrap().take();
                self.dropped.send(()).unwrap();
            }
        }
        let (dropped, received) = mpsc::sync_channel(1);
        let owner = Arc::new(Owner {
            worker: Mutex::new(None),
            dropped,
        });
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let e = Arc::clone(&entered);
        let r = Arc::clone(&release);
        let worker = Worker::start(
            Arc::downgrade(&owner),
            Arc::new(AtomicU64::new(1)),
            generation,
            move |_, _, _| {
                e.wait();
                r.wait();
            },
        )
        .unwrap();
        let publisher = worker.source.publisher(1).unwrap();
        *owner.worker.lock().unwrap() = Some(worker);
        publisher.try_send(Job(1)).unwrap();
        entered.wait();
        drop(owner);
        release.wait();
        received.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(
            publisher.try_send(Job(1)),
            Err(FreshVaultClosePublishError::Cancelled)
        );
    }
}

#[cfg(all(windows, test, debug_assertions))]
pub(super) use agent::FreshCloseObservation;
