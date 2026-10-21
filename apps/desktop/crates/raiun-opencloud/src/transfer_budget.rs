//! Per-account content-transfer rate limiting.
//!
//! The upload and download buckets are independent, while clones of one
//! controller share each bucket. Metadata and authentication requests do not
//! pass through this module. Pausing interrupts a transfer at its next chunk
//! boundary; callers can resume and retry using their existing conditional
//! transfer semantics.

use serde::{Deserialize, Serialize};
use std::{
    io::{self, Read},
    num::NonZeroU64,
    sync::{
        Arc, Condvar, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

const SUBUNITS_PER_BYTE: u128 = 1_000_000_000;
const BURST_SECONDS: u128 = 1;
const WAKE_INTERVAL: Duration = Duration::from_millis(20);
pub const MAX_TRANSFER_RATE_BYTES_PER_SECOND: u64 = 1 << 40;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferDirection {
    Upload,
    Download,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransferLimits {
    pub upload_bytes_per_second: Option<NonZeroU64>,
    pub download_bytes_per_second: Option<NonZeroU64>,
}

impl TransferLimits {
    pub fn validate(self) -> Result<(), &'static str> {
        if self
            .upload_bytes_per_second
            .is_some_and(|rate| rate.get() > MAX_TRANSFER_RATE_BYTES_PER_SECOND)
            || self
                .download_bytes_per_second
                .is_some_and(|rate| rate.get() > MAX_TRANSFER_RATE_BYTES_PER_SECOND)
        {
            return Err("transfer rate exceeds the supported limit");
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct TransferBudget {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    state: Mutex<State>,
    changed: Condvar,
    cancellation_generation: AtomicU64,
}

#[derive(Debug, Default)]
struct State {
    limits: TransferLimits,
    upload: Bucket,
    download: Bucket,
    paused: bool,
}

#[derive(Debug, Default)]
struct Bucket {
    subunits: u128,
    updated: Option<Instant>,
}

#[derive(Clone, Debug)]
pub struct TransferCancellation {
    cancelled: Arc<AtomicBool>,
    owner: Weak<Inner>,
    generation: u64,
}

impl Default for TransferBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl TransferBudget {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State::default()),
                changed: Condvar::new(),
                cancellation_generation: AtomicU64::new(0),
            }),
        }
    }

    pub fn limits(&self) -> TransferLimits {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .limits
    }

    /// Set independent account-wide upload and download ceilings. `None`
    /// leaves that direction unlimited.
    pub fn set_limits(&self, limits: TransferLimits) {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        let previous = state.limits;
        state.upload.reconfigure(
            previous.upload_bytes_per_second,
            limits.upload_bytes_per_second,
            now,
        );
        state.download.reconfigure(
            previous.download_bytes_per_second,
            limits.download_bytes_per_second,
            now,
        );
        state.limits = limits;
        self.inner.changed.notify_all();
    }

    /// Interrupt body streams at their next bounded chunk boundary while
    /// paused. Callers resume and retry through their normal scheduler.
    pub fn set_paused(&self, paused: bool) {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.paused = paused;
        self.inner.changed.notify_all();
    }

    pub fn is_paused(&self) -> bool {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .paused
    }

    pub fn cancellation(&self) -> TransferCancellation {
        TransferCancellation {
            cancelled: Arc::new(AtomicBool::new(false)),
            owner: Arc::downgrade(&self.inner),
            generation: self.inner.cancellation_generation.load(Ordering::Acquire),
        }
    }

    /// Cancel every transfer that is already waiting for bandwidth. New
    /// transfers receive the next generation and remain usable.
    pub fn cancel_waiters(&self) {
        self.inner
            .cancellation_generation
            .fetch_add(1, Ordering::AcqRel);
        self.inner.changed.notify_all();
    }

    pub fn reader<R: Read>(&self, direction: TransferDirection, source: R) -> BudgetReader<R> {
        BudgetReader {
            budget: self.clone(),
            direction,
            cancellation: self.cancellation(),
            source,
        }
    }

    pub fn reader_with_cancellation<R: Read>(
        &self,
        direction: TransferDirection,
        source: R,
        cancellation: TransferCancellation,
    ) -> BudgetReader<R> {
        BudgetReader {
            budget: self.clone(),
            direction,
            cancellation,
            source,
        }
    }

    pub(crate) fn acquire(
        &self,
        direction: TransferDirection,
        requested: usize,
        cancellation: &TransferCancellation,
    ) -> io::Result<Reservation> {
        self.acquire_cancellable(direction, requested, || cancellation.is_cancelled())
    }

    pub(crate) fn acquire_cancellable<F>(
        &self,
        direction: TransferDirection,
        requested: usize,
        is_cancelled: F,
    ) -> io::Result<Reservation>
    where
        F: Fn() -> bool,
    {
        if requested == 0 {
            return Ok(Reservation::unmetered(0));
        }
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| io::Error::other("transfer budget is unavailable"))?;
        loop {
            if is_cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "content transfer was cancelled",
                ));
            }
            if state.paused {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "content transfer was paused",
                ));
            }

            let rate = match direction {
                TransferDirection::Upload => state.limits.upload_bytes_per_second,
                TransferDirection::Download => state.limits.download_bytes_per_second,
            };
            let bucket = match direction {
                TransferDirection::Upload => &mut state.upload,
                TransferDirection::Download => &mut state.download,
            };
            let Some(rate) = rate else {
                return Ok(Reservation::unmetered(requested));
            };
            let now = Instant::now();
            bucket.refill(rate, now);
            let available = (bucket.subunits / SUBUNITS_PER_BYTE).min(usize::MAX as u128) as usize;
            if available > 0 {
                let granted = requested.min(available);
                bucket.subunits = bucket
                    .subunits
                    .saturating_sub((granted as u128) * SUBUNITS_PER_BYTE);
                return Ok(Reservation {
                    owner: Some(Arc::downgrade(&self.inner)),
                    direction,
                    granted,
                    settled: false,
                });
            }

            let fractional = bucket.subunits % SUBUNITS_PER_BYTE;
            let remaining = SUBUNITS_PER_BYTE.saturating_sub(fractional);
            let wait_nanos = remaining.div_ceil(rate.get() as u128).max(1);
            let wait = Duration::from_nanos(wait_nanos.min(WAKE_INTERVAL.as_nanos()) as u64);
            let (next_state, _) = self
                .inner
                .changed
                .wait_timeout(state, wait)
                .map_err(|_| io::Error::other("transfer budget is unavailable"))?;
            state = next_state;
        }
    }

    /// Async counterpart for streaming HTTP bodies. It never blocks an
    /// executor thread and is cancelled by dropping its future; pause and
    /// cancellation-generation changes are observed at most one wake interval
    /// later while a consumer waits for tokens.
    pub(crate) async fn acquire_cancellable_async<F>(
        &self,
        direction: TransferDirection,
        requested: usize,
        is_cancelled: F,
    ) -> io::Result<Reservation>
    where
        F: Fn() -> bool,
    {
        if requested == 0 {
            return Ok(Reservation::unmetered(0));
        }
        loop {
            let wait = {
                let mut state = self
                    .inner
                    .state
                    .lock()
                    .map_err(|_| io::Error::other("transfer budget is unavailable"))?;
                if is_cancelled() {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "content transfer was cancelled",
                    ));
                }
                if state.paused {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "content transfer was paused",
                    ));
                }

                let rate = match direction {
                    TransferDirection::Upload => state.limits.upload_bytes_per_second,
                    TransferDirection::Download => state.limits.download_bytes_per_second,
                };
                let bucket = match direction {
                    TransferDirection::Upload => &mut state.upload,
                    TransferDirection::Download => &mut state.download,
                };
                let Some(rate) = rate else {
                    return Ok(Reservation::unmetered(requested));
                };
                let now = Instant::now();
                bucket.refill(rate, now);
                let available =
                    (bucket.subunits / SUBUNITS_PER_BYTE).min(usize::MAX as u128) as usize;
                if available > 0 {
                    let granted = requested.min(available);
                    bucket.subunits = bucket
                        .subunits
                        .saturating_sub((granted as u128) * SUBUNITS_PER_BYTE);
                    return Ok(Reservation {
                        owner: Some(Arc::downgrade(&self.inner)),
                        direction,
                        granted,
                        settled: false,
                    });
                }

                let fractional = bucket.subunits % SUBUNITS_PER_BYTE;
                let remaining = SUBUNITS_PER_BYTE.saturating_sub(fractional);
                let wait_nanos = remaining.div_ceil(rate.get() as u128).max(1);
                Duration::from_nanos(wait_nanos.min(WAKE_INTERVAL.as_nanos()) as u64)
            };
            tokio::time::sleep(wait).await;
        }
    }
}

impl TransferCancellation {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(owner) = self.owner.upgrade() {
            owner.changed.notify_all();
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
            || self.owner.upgrade().is_none_or(|owner| {
                owner.cancellation_generation.load(Ordering::Acquire) != self.generation
            })
    }
}

#[derive(Debug)]
pub(crate) struct Reservation {
    owner: Option<Weak<Inner>>,
    direction: TransferDirection,
    granted: usize,
    settled: bool,
}

impl Reservation {
    fn unmetered(granted: usize) -> Self {
        Self {
            owner: None,
            direction: TransferDirection::Upload,
            granted,
            settled: true,
        }
    }

    pub(crate) fn granted(&self) -> usize {
        self.granted
    }

    pub(crate) fn settle(mut self, consumed: usize) {
        self.refund(self.granted.saturating_sub(consumed));
        self.settled = true;
    }

    fn refund(&mut self, unused: usize) {
        let Some(owner) = self.owner.as_ref().and_then(Weak::upgrade) else {
            return;
        };
        if unused == 0 {
            return;
        }
        let mut state = owner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let rate = match self.direction {
            TransferDirection::Upload => state.limits.upload_bytes_per_second,
            TransferDirection::Download => state.limits.download_bytes_per_second,
        };
        let bucket = match self.direction {
            TransferDirection::Upload => &mut state.upload,
            TransferDirection::Download => &mut state.download,
        };
        if let Some(rate) = rate {
            let cap = (rate.get() as u128) * BURST_SECONDS * SUBUNITS_PER_BYTE;
            bucket.subunits = bucket
                .subunits
                .saturating_add((unused as u128) * SUBUNITS_PER_BYTE)
                .min(cap);
        }
        owner.changed.notify_all();
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.settled {
            self.refund(self.granted);
        }
    }
}

impl Bucket {
    fn full(rate: Option<NonZeroU64>, now: Instant) -> Self {
        Self {
            subunits: rate.map_or(0, |rate| {
                rate.get() as u128 * BURST_SECONDS * SUBUNITS_PER_BYTE
            }),
            updated: Some(now),
        }
    }

    fn refill(&mut self, rate: NonZeroU64, now: Instant) {
        let prior = self.updated.replace(now).unwrap_or(now);
        let elapsed = now.saturating_duration_since(prior).as_nanos();
        let cap = rate.get() as u128 * BURST_SECONDS * SUBUNITS_PER_BYTE;
        self.subunits = self
            .subunits
            .saturating_add(elapsed.saturating_mul(rate.get() as u128))
            .min(cap);
    }

    fn reconfigure(
        &mut self,
        previous: Option<NonZeroU64>,
        next: Option<NonZeroU64>,
        now: Instant,
    ) {
        // The first finite limit starts with the documented one-second burst.
        if self.updated.is_none() {
            *self = Self::full(next, now);
            return;
        }
        if let Some(previous) = previous {
            self.refill(previous, now);
        }
        self.updated = Some(now);
        match next {
            Some(next) => {
                let cap = next.get() as u128 * BURST_SECONDS * SUBUNITS_PER_BYTE;
                // Going from unlimited to limited starts empty. Repeated
                // limit changes cannot refill a bucket or manufacture a burst.
                if previous.is_none() {
                    self.subunits = 0;
                } else {
                    self.subunits = self.subunits.min(cap);
                }
            }
            None => self.subunits = 0,
        }
    }
}

pub struct BudgetReader<R> {
    budget: TransferBudget,
    direction: TransferDirection,
    cancellation: TransferCancellation,
    source: R,
}

impl<R: Read> Read for BudgetReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let reservation = self
            .budget
            .acquire(self.direction, buffer.len(), &self.cancellation)?;
        let count = self.source.read(&mut buffer[..reservation.granted()]);
        match count {
            Ok(count) => {
                reservation.settle(count);
                Ok(count)
            }
            Err(error) => {
                drop(reservation);
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Read,
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };

    fn rate(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).unwrap()
    }

    fn consume(budget: &TransferBudget, direction: TransferDirection, bytes: usize) {
        let cancellation = budget.cancellation();
        let mut remaining = bytes;
        while remaining > 0 {
            let reservation = budget.acquire(direction, remaining, &cancellation).unwrap();
            let granted = reservation.granted();
            reservation.settle(granted);
            remaining -= granted;
        }
    }

    #[test]
    fn cloned_budgets_share_each_direction_but_directions_are_independent() {
        let budget = TransferBudget::new();
        budget.set_limits(TransferLimits {
            upload_bytes_per_second: Some(rate(32)),
            download_bytes_per_second: Some(rate(16)),
        });
        let clone = budget.clone();
        let start = Instant::now();
        consume(&budget, TransferDirection::Upload, 32);
        consume(&clone, TransferDirection::Upload, 32);
        assert!(start.elapsed() >= Duration::from_millis(800));

        // Upload depletion does not consume the separate download bucket.
        let download = budget
            .acquire(TransferDirection::Download, 16, &budget.cancellation())
            .unwrap();
        download.settle(16);
    }

    #[test]
    fn concurrent_same_direction_consumers_share_one_account_ceiling() {
        let budget = TransferBudget::new();
        budget.set_limits(TransferLimits {
            upload_bytes_per_second: Some(rate(32)),
            download_bytes_per_second: None,
        });
        consume(&budget, TransferDirection::Upload, 32);

        let barrier = Arc::new(std::sync::Barrier::new(3));
        let start = Instant::now();
        let mut workers = Vec::new();
        for _ in 0..2 {
            let worker_budget = budget.clone();
            let worker_barrier = barrier.clone();
            workers.push(thread::spawn(move || {
                let cancellation = worker_budget.cancellation();
                worker_barrier.wait();
                let mut remaining = 32;
                while remaining > 0 {
                    let reservation = worker_budget
                        .acquire(TransferDirection::Upload, remaining, &cancellation)
                        .unwrap();
                    let granted = reservation.granted();
                    reservation.settle(granted);
                    remaining -= granted;
                }
            }));
        }
        barrier.wait();
        for worker in workers {
            worker.join().unwrap();
        }
        assert!(
            start.elapsed() >= Duration::from_millis(1_700),
            "two cloned clients shared a bucket but exceeded its aggregate rate"
        );
    }

    #[test]
    fn shared_contention_and_rate_changes_do_not_cancel_bucket_progress() {
        let budget = TransferBudget::new();
        budget.set_limits(TransferLimits {
            upload_bytes_per_second: Some(rate(4)),
            download_bytes_per_second: None,
        });
        consume(&budget, TransferDirection::Upload, 4);

        let barrier = Arc::new(std::sync::Barrier::new(3));
        let start = Instant::now();
        let mut workers = Vec::new();
        for _ in 0..2 {
            let worker_budget = budget.clone();
            let worker_barrier = barrier.clone();
            workers.push(thread::spawn(move || {
                worker_barrier.wait();
                consume(&worker_budget, TransferDirection::Upload, 4);
            }));
        }
        barrier.wait();
        for worker in workers {
            worker.join().unwrap();
        }
        assert!(
            start.elapsed() >= Duration::from_millis(1_700),
            "two transfers sharing a four-byte/second cap must consume at least two seconds"
        );

        let changing = TransferBudget::new();
        changing.set_limits(TransferLimits {
            upload_bytes_per_second: Some(rate(4)),
            download_bytes_per_second: None,
        });
        consume(&changing, TransferDirection::Upload, 4);
        let worker_budget = changing.clone();
        let started = Instant::now();
        let worker = thread::spawn(move || consume(&worker_budget, TransferDirection::Upload, 2));
        thread::sleep(Duration::from_millis(100));
        changing.set_limits(TransferLimits {
            upload_bytes_per_second: Some(rate(1)),
            download_bytes_per_second: None,
        });
        worker.join().unwrap();
        assert!(
            started.elapsed() >= Duration::from_millis(1_300),
            "the live bucket honors a lower rate applied while a consumer is waiting"
        );
    }

    #[test]
    fn separate_accounts_do_not_share_tokens() {
        let first = TransferBudget::new();
        let second = TransferBudget::new();
        for budget in [&first, &second] {
            budget.set_limits(TransferLimits {
                upload_bytes_per_second: Some(rate(8)),
                download_bytes_per_second: None,
            });
        }
        let start = Instant::now();
        for budget in [&first, &second] {
            budget
                .acquire(TransferDirection::Upload, 8, &budget.cancellation())
                .unwrap()
                .settle(8);
        }
        assert!(start.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn changing_limits_does_not_mint_another_burst() {
        let budget = TransferBudget::new();
        budget.set_limits(TransferLimits {
            upload_bytes_per_second: Some(rate(8)),
            download_bytes_per_second: None,
        });
        consume(&budget, TransferDirection::Upload, 8);
        budget.set_limits(TransferLimits::default());
        budget.set_limits(TransferLimits {
            upload_bytes_per_second: Some(rate(8)),
            download_bytes_per_second: None,
        });
        let started = Instant::now();
        consume(&budget, TransferDirection::Upload, 1);
        assert!(started.elapsed() >= Duration::from_millis(100));
    }

    #[test]
    fn pause_and_cancel_interrupt_rate_waiters_promptly() {
        let budget = TransferBudget::new();
        budget.set_limits(TransferLimits {
            upload_bytes_per_second: Some(rate(1)),
            download_bytes_per_second: None,
        });
        budget
            .acquire(TransferDirection::Upload, 1, &budget.cancellation())
            .unwrap()
            .settle(1);
        let waiter_budget = budget.clone();
        let waiter = thread::spawn(move || {
            waiter_budget.acquire(TransferDirection::Upload, 1, &waiter_budget.cancellation())
        });
        thread::sleep(Duration::from_millis(30));
        budget.set_paused(true);
        let error = waiter.join().unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);

        budget.set_paused(false);
        budget
            .acquire(TransferDirection::Upload, 1, &budget.cancellation())
            .unwrap()
            .settle(1);
        let cancellation = budget.cancellation();
        let worker_budget = budget.clone();
        let worker_cancellation = cancellation.clone();
        let (ready, started) = mpsc::channel();
        let worker = thread::spawn(move || {
            ready.send(()).unwrap();
            worker_budget.acquire(TransferDirection::Upload, 1, &worker_cancellation)
        });
        started.recv().unwrap();
        thread::sleep(Duration::from_millis(30));
        cancellation.cancel();
        assert_eq!(
            worker.join().unwrap().unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
    }

    #[test]
    fn unlimited_budget_preserves_reader_bytes_without_waiting() {
        let budget = TransferBudget::new();
        let mut reader = budget.reader(TransferDirection::Download, &b"content"[..]);
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"content");
    }
}
