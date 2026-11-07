//! Bounded hint transport only. The native observer is constructed and remains
//! on its worker; no Send implementation or mutation authority is introduced.
use super::{
    DirectoryHint, DirectoryObserver, MAX_NOTIFICATION_HINTS, NotificationBatch, ObserverPoll,
    RescanReason,
};
use crate::PinnedFileIdentity;
use std::{
    collections::VecDeque,
    io,
    marker::PhantomData,
    os::windows::io::{AsHandle, BorrowedHandle, OwnedHandle},
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const MAX_WEIGHT: usize = 4 * 1024 * 1024;
const MAX_BATCHES: usize = 1024;
const MAX_HINTS: usize = 16 * MAX_NOTIFICATION_HINTS;
const POLL_WAIT: Duration = Duration::from_millis(10);
const MAX_OWNER_WAIT: Duration = Duration::from_millis(250);
type QueuedBatch = (NotificationBatch, usize, usize);

#[derive(Default)]
struct State {
    start: bool,
    armed: bool,
    terminal: Option<RescanReason>,
    queue: VecDeque<QueuedBatch>,
    weight: usize,
    hints: usize,
}
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
    stopping: AtomicBool,
    drained: AtomicBool,
    current: Arc<dyn Fn() -> bool + Send + Sync>,
    terminal: Arc<dyn Fn(RescanReason) + Send + Sync>,
}
impl Shared {
    fn stop(&self) {
        let _state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.stopping.store(true, Ordering::Release);
        self.changed.notify_all();
    }
    fn fail(&self, reason: RescanReason) {
        let first = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.terminal.is_some() || self.stopping.load(Ordering::Acquire) {
                false
            } else {
                state.terminal = Some(reason);
                true
            }
        };
        self.publish_terminal(reason, first);
    }
    fn publish_terminal(&self, reason: RescanReason, first: bool) {
        // Publish terminal loss before the callback closes original job fences.
        // No queue/state lock crosses that callback or its publication gate.
        self.changed.notify_all();
        if first {
            let _ = catch_unwind(AssertUnwindSafe(|| (self.terminal)(reason)));
        }
    }
    fn enqueue(&self, hints: Vec<DirectoryHint>) {
        if hints.is_empty() {
            self.fail(RescanReason::EmptyCompletion);
            return;
        }
        if hints.len() > MAX_NOTIFICATION_HINTS {
            self.fail(RescanReason::Limit);
            return;
        }
        let Some(weight) = batch_weight(&hints) else {
            self.fail(RescanReason::Limit);
            return;
        };
        let count = hints.len();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.terminal.is_some() || self.stopping.load(Ordering::Acquire) {
            return;
        }
        let next_weight = state.weight.checked_add(weight);
        let next_hints = state.hints.checked_add(count);
        if state.queue.len() >= MAX_BATCHES
            || next_weight.is_none_or(|value| value > MAX_WEIGHT)
            || next_hints.is_none_or(|value| value > MAX_HINTS)
        {
            // Latch while holding the same admission lock: a dequeue cannot
            // expose another batch between observing full and publishing loss.
            state.terminal = Some(RescanReason::Limit);
            drop(state);
            self.publish_terminal(RescanReason::Limit, true);
            return;
        }
        state.weight = next_weight.expect("bounded queue weight");
        state.hints = next_hints.expect("bounded queue hint count");
        state
            .queue
            .push_back((NotificationBatch::Hints(hints), weight, count));
        self.changed.notify_all();
    }
    fn failed(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .terminal
            .is_some()
    }
}

fn batch_weight(hints: &[DirectoryHint]) -> Option<usize> {
    let mut weight = std::mem::size_of::<QueuedBatch>()
        .checked_add(std::mem::size_of::<VecDeque<QueuedBatch>>())?;
    for hint in hints {
        weight = weight.checked_add(std::mem::size_of::<DirectoryHint>())?;
        for component in hint.components() {
            weight = weight
                .checked_add(std::mem::size_of::<String>())?
                .checked_add(component.len())?;
        }
    }
    // Conservative queue weight, including allocation/spare-capacity overhead;
    // not an estimate of the entire process's memory consumption.
    weight.checked_mul(2)
}

// Declared AFTER the native observer: on panic this closes admission before
// the native observer's potentially blocking Drop drains the actual read.
struct PanicFence<'a>(&'a Shared, bool);
impl Drop for PanicFence<'_> {
    fn drop(&mut self) {
        if self.1 && !self.0.stopping.load(Ordering::Acquire) {
            self.0.fail(RescanReason::Cancelled);
        }
    }
}

fn make_observer(
    original: BorrowedHandle<'_>,
    expected: PinnedFileIdentity,
) -> io::Result<DirectoryObserver> {
    #[cfg(all(debug_assertions, feature = "synthetic-agent-integration"))]
    if std::env::var("RAIUN_RUN_CONNECTED_OBSERVER_FIXTURE").as_deref() == Ok("fresh-owned-state")
        && std::env::var("RAIUN_CONNECTED_OBSERVER_FIXTURE_CHILD").as_deref() == Ok("1")
    {
        return DirectoryObserver::from_borrowed_directory_diagnostic(original, expected).map_err(
            |failure| {
                eprintln!(
                    "synthetic observer construction stage={} kind={:?} native_code={:?}",
                    failure.stage(),
                    failure.kind(),
                    failure.native_code()
                );
                failure.into_io_error()
            },
        );
    }
    DirectoryObserver::from_borrowed_directory(original, expected)
}

fn run(original: OwnedHandle, expected: PinnedFileIdentity, shared: &Shared) {
    {
        let mut state = shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !state.start && !shared.stopping.load(Ordering::Acquire) {
            state = shared
                .changed
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
    if shared.stopping.load(Ordering::Acquire) {
        return;
    }
    // The !Send/!Sync observer is created here, never transported to this thread.
    let mut observer = match make_observer(original.as_handle(), expected) {
        Ok(observer) => observer,
        Err(error) => {
            shared.fail(
                error
                    .raw_os_error()
                    .map_or(RescanReason::RootChanged, |code| {
                        RescanReason::NativeError(code as u32)
                    }),
            );
            return;
        }
    };
    let mut panic_fence = PanicFence(shared, true);
    if !shared.stopping.load(Ordering::Acquire) && (shared.current)() {
        match observer.arm() {
            ObserverPoll::Pending => {
                shared
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .armed = true;
                shared.changed.notify_all();
            }
            ObserverPoll::Batch(NotificationBatch::RescanRequired(reason)) => shared.fail(reason),
            _ => shared.fail(RescanReason::Cancelled),
        }
    } else {
        shared.stop();
    }
    while !shared.stopping.load(Ordering::Acquire) && !shared.failed() {
        if !(shared.current)() {
            // An external account/lifecycle transition already owns retirement.
            // Do not manufacture a transport fault for that normal revocation.
            shared.stop();
            break;
        }
        match observer.poll(POLL_WAIT) {
            ObserverPoll::Pending => (),
            ObserverPoll::Batch(NotificationBatch::Hints(hints)) => {
                if shared.stopping.load(Ordering::Acquire) {
                    break;
                }
                if !(shared.current)() {
                    shared.stop();
                    break;
                }
                // Complete owned hints no longer borrow the native buffer.
                // Rearm before staging or any consumer/candidate work.
                match observer.arm() {
                    ObserverPoll::Pending => shared.enqueue(hints),
                    ObserverPoll::Batch(NotificationBatch::RescanRequired(reason)) => {
                        shared.fail(reason);
                    }
                    _ => shared.fail(RescanReason::Cancelled),
                }
            }
            ObserverPoll::Batch(NotificationBatch::RescanRequired(reason)) => {
                if !shared.stopping.load(Ordering::Acquire) {
                    shared.fail(reason);
                }
            }
            _ => shared.fail(RescanReason::Cancelled),
        }
    }
    // Explicit stop and terminal loss both keep this same native owner alive
    // until the exact OVERLAPPED operation has actually completed.
    while observer.has_pending_io() {
        let started = Instant::now();
        let _ = observer.cancel_and_drain(POLL_WAIT);
        if observer.has_pending_io() {
            // Unexpected cancellation/wait failures may return immediately.
            // Retain the same owner without spinning on the unchanged failure.
            thread::sleep(POLL_WAIT.saturating_sub(started.elapsed()));
        }
    }
    panic_fence.1 = false;
    drop(panic_fence);
    drop(observer);
    drop(original);
}

/// Single-owner supervisor for a continuously rearmed, hint-only transport.
/// Callers must explicitly cancel and retain this owner while drain is pending.
pub struct DirectoryObserverPump {
    shared: Arc<Shared>,
    worker: Option<JoinHandle<()>>,
    expected: PinnedFileIdentity,
    _single_thread: PhantomData<Rc<()>>,
}
impl DirectoryObserverPump {
    /// Duplicate only the already pinned original. The worker performs the
    /// existing same-object factory checks, and cannot arm before `arm` is called.
    pub fn from_borrowed_directory(
        original: BorrowedHandle<'_>,
        expected: PinnedFileIdentity,
        current: Arc<dyn Fn() -> bool + Send + Sync>,
        terminal: Arc<dyn Fn(RescanReason) + Send + Sync>,
    ) -> io::Result<Self> {
        let original = original.try_clone_to_owned()?;
        let shared = Arc::new(Shared {
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
            stopping: AtomicBool::new(false),
            drained: AtomicBool::new(false),
            current,
            terminal,
        });
        let worker_shared = Arc::clone(&shared);
        let worker = thread::Builder::new()
            .name("raiun-directory-intake".into())
            .spawn(move || {
                let outcome = catch_unwind(AssertUnwindSafe(|| {
                    run(original, expected, &worker_shared);
                }));
                if outcome.is_err() && !worker_shared.stopping.load(Ordering::Acquire) {
                    worker_shared.fail(RescanReason::Cancelled);
                }
                // Native owner and original duplicate were dropped only after
                // actual drain (including the native Drop path during unwind).
                worker_shared.drained.store(true, Ordering::Release);
                worker_shared.changed.notify_all();
            })?;
        Ok(Self {
            shared,
            worker: Some(worker),
            expected,
            _single_thread: PhantomData,
        })
    }
    pub fn root_identity(&self) -> PinnedFileIdentity {
        self.expected
    }
    /// Includes construction/worker ownership, not just an outstanding read.
    pub fn has_pending_io(&self) -> bool {
        !self.shared.drained.load(Ordering::Acquire)
            || self
                .worker
                .as_ref()
                .is_some_and(|worker| !worker.is_finished())
    }
    pub fn arm(&mut self) -> ObserverPoll {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.start = true;
        self.shared.changed.notify_all();
        let (state, _) = self
            .shared
            .changed
            .wait_timeout_while(state, MAX_OWNER_WAIT, |state| {
                !state.armed
                    && state.terminal.is_none()
                    && !self.shared.stopping.load(Ordering::Acquire)
            })
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(reason) = state.terminal {
            ObserverPoll::Batch(NotificationBatch::RescanRequired(reason))
        } else if self.shared.stopping.load(Ordering::Acquire) {
            ObserverPoll::Stopped
        } else if state.armed {
            ObserverPoll::Pending
        } else {
            // Startup has not proved an armed read within the owner's bound.
            // The bridge refuses readiness and explicitly cancels/retains us.
            ObserverPoll::Idle
        }
    }
    pub fn poll(&mut self, wait: Duration) -> ObserverPoll {
        let state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (mut state, _) = self
            .shared
            .changed
            .wait_timeout_while(state, wait.min(MAX_OWNER_WAIT), |state| {
                state.terminal.is_none()
                    && state.queue.is_empty()
                    && !self.shared.stopping.load(Ordering::Acquire)
            })
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Terminal loss always wins over queued observations. No valid prefix
        // can conceal a later loss, and no batch is merged or replayed.
        if let Some(reason) = state.terminal {
            return ObserverPoll::Batch(NotificationBatch::RescanRequired(reason));
        }
        if self.shared.stopping.load(Ordering::Acquire) {
            return if self.has_pending_io() {
                ObserverPoll::Pending
            } else {
                ObserverPoll::Stopped
            };
        }
        if let Some((batch, weight, hints)) = state.queue.pop_front() {
            state.weight -= weight;
            state.hints -= hints;
            ObserverPoll::Batch(batch)
        } else {
            ObserverPoll::Pending
        }
    }
    pub fn cancel_and_drain(&mut self, wait: Duration) -> ObserverPoll {
        self.shared.stop();
        let deadline = Instant::now() + wait.min(MAX_OWNER_WAIT);
        while self.has_pending_io() && Instant::now() < deadline {
            let state = self
                .shared
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let remaining = deadline.saturating_duration_since(Instant::now());
            drop(
                self.shared
                    .changed
                    .wait_timeout(state, remaining.min(POLL_WAIT))
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            );
        }
        if self.has_pending_io() {
            return ObserverPoll::Pending;
        }
        if let Some(worker) = self.worker.take() {
            // is_finished + drained are both true; this join cannot wait on IO.
            let _ = worker.join();
        }
        ObserverPoll::Stopped
    }
}
impl Drop for DirectoryObserverPump {
    fn drop(&mut self) {
        self.shared.stop();
        if let Some(worker) = self.worker.take() {
            if self.shared.drained.load(Ordering::Acquire) && worker.is_finished() {
                let _ = worker.join();
            } else {
                // Unexpected Drop must not detach an active native owner.
                // Normal bridges retain the entire pump on a bounded timeout.
                let _ = Box::leak(Box::new((worker, Arc::clone(&self.shared))));
            }
        }
    }
}
