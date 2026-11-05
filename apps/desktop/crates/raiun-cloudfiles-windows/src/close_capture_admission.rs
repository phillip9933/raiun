//! Short admission bookkeeping between native close capture and save/rename.
//!
//! This tracker carries no backend, recovery, path, or native authority. Its
//! mutex is held only while counters and epochs change; callers must drop every
//! mutex guard before doing I/O. Close capture is never suppressed when admission
//! bookkeeping fails: failure makes future rename admission unknown instead.

use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
#[cfg(any(windows, test))]
use std::{marker::PhantomData, rc::Rc, sync::Arc};

#[derive(Default)]
struct State {
    active_closes: usize,
    dirty_epoch: u64,
    rename_claimed: bool,
    dispatch_claimed: bool,
    completion_claimed: bool,
    #[cfg(windows)]
    ordinary_creates: Vec<independent_create::Claim>,
    #[cfg(windows)]
    create_nonce: u64,
}

#[derive(Default)]
pub(crate) struct CloseCaptureAdmission {
    state: Mutex<State>,
    unknown: AtomicBool,
    create_observation: AtomicU64,
}

impl CloseCaptureAdmission {
    /// Begin tracking before inspecting callback parameters or native state.
    /// Failure is fail-closed for rename admission but does not stop capture.
    pub(crate) fn begin_close(&self) -> CloseCapturePermit<'_> {
        let active = match self.try_state() {
            Some(mut state) => {
                self.advance_create_observation();
                match state.active_closes.checked_add(1) {
                    Some(next) => {
                        state.active_closes = next;
                        true
                    }
                    None => {
                        self.unknown.store(true, Ordering::Release);
                        false
                    }
                }
            }
            None => false,
        };
        CloseCapturePermit {
            tracker: self,
            active,
            dirty: false,
            finished: false,
        }
    }

    /// Take one lightweight, retained ticket only while no close is active.
    /// The ticket serializes rename attempts, not close capture or remote I/O.
    #[allow(dead_code)] // R55 explicit producer consumes this capability.
    pub(crate) fn try_begin_rename(&self) -> Option<SaveRenameTicket<'_>> {
        Some(SaveRenameTicket {
            tracker: self,
            ticket: self.try_begin_ticket()?,
        })
    }

    /// Preparatory owner-thread custody only; no path, history or send authority.
    #[cfg(any(windows, test))]
    #[cfg_attr(not(test), allow(dead_code))] // No owner-worker caller is activated yet.
    pub(crate) fn try_begin_create(self: &Arc<Self>) -> Option<OwnedCreateAdmission> {
        let ticket = self.try_begin_ticket()?;
        let (dispatch, lifetime) = DispatchProbeLifetime::new(self.clone(), ticket.observation);
        Some(OwnedCreateAdmission {
            tracker: self.clone(),
            ticket,
            dispatch,
            lifetime,
            _owner_thread: PhantomData,
        })
    }

    /// Distinct directory exclusion only; no file or native authority.
    #[cfg(any(windows, test))]
    pub(crate) fn try_begin_directory(self: &Arc<Self>) -> Option<OwnedDirectoryAdmission> {
        let ticket = self.try_begin_ticket()?;
        let (dispatch, lifetime) = DispatchProbeLifetime::new(self.clone(), ticket.observation);
        Some(OwnedDirectoryAdmission {
            tracker: self.clone(),
            ticket,
            dispatch,
            lifetime,
            _owner_thread: PhantomData,
        })
    }

    fn try_begin_ticket(&self) -> Option<TicketState> {
        if self.unknown.load(Ordering::Acquire) {
            return None;
        }
        let mut state = self.try_state()?;
        if self.unknown.load(Ordering::Acquire) || state.active_closes != 0 || state.rename_claimed
        {
            return None;
        }
        #[cfg(windows)]
        if !state.ordinary_creates.is_empty() {
            return None;
        }
        state.rename_claimed = true;
        state.dispatch_claimed = false;
        state.completion_claimed = false;
        Some(TicketState {
            epoch: state.dirty_epoch,
            observation: self.create_observation.load(Ordering::Acquire),
            dispatch_claimed: false,
            completion_claimed: false,
        })
    }

    fn advance_create_observation(&self) {
        let mut epoch = self.create_observation.load(Ordering::Acquire);
        loop {
            let Some(next) = epoch.checked_add(1) else {
                self.unknown.store(true, Ordering::Release);
                return;
            };
            match self.create_observation.compare_exchange_weak(
                epoch,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return,
                Err(current) => epoch = current,
            }
        }
    }

    fn try_state(&self) -> Option<std::sync::MutexGuard<'_, State>> {
        match self.state.try_lock() {
            Ok(state) => Some(state),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                self.unknown.store(true, Ordering::Release);
                Some(poisoned.into_inner())
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                self.unknown.store(true, Ordering::Release);
                None
            }
        }
    }

    fn decrement_active(&self) -> bool {
        let Some(mut state) = self.try_state() else {
            return false;
        };
        if state.active_closes == 0 {
            self.unknown.store(true, Ordering::Release);
            return false;
        }
        state.active_closes -= 1;
        true
    }

    #[cfg(all(windows, debug_assertions, feature = "synthetic-agent-integration"))]
    pub(crate) fn fixture_admission_unknown(&self) -> bool {
        self.unknown.load(Ordering::Acquire)
    }

    pub(crate) fn mark_unknown(&self) {
        self.unknown.store(true, Ordering::Release);
    }
}

/// An outer native close callback's capture permit. Dropping it without a
/// positive Clean or durable Dirty classification permanently marks this
/// connection's admission summary unknown.
pub(crate) struct CloseCapturePermit<'a> {
    tracker: &'a CloseCaptureAdmission,
    active: bool,
    dirty: bool,
    finished: bool,
}

impl CloseCapturePermit<'_> {
    /// Release a positively validated close with no modified placeholder
    /// ranges. Clean closes do not advance the mutation epoch.
    pub(crate) fn finish_clean(&mut self) {
        if self.finished {
            self.tracker.mark_unknown();
            return;
        }
        if self.dirty {
            self.tracker.mark_unknown();
        }
        if self.active && !self.tracker.decrement_active() {
            self.tracker.mark_unknown();
        }
        self.active = false;
        self.finished = true;
    }

    /// Transfer only this exact Arc-backed tracker; the close remains active
    /// until actual owned deletion completion or fail-closed retirement. This
    /// is not a clean classification or permission from NOTIFY/ACK metadata.
    #[cfg(any(windows, test))]
    pub(crate) fn defer_owned_deleted(
        &mut self,
        tracker: &Arc<CloseCaptureAdmission>,
    ) -> Option<DeferredDeletedClose> {
        if !std::ptr::eq(self.tracker, Arc::as_ptr(tracker))
            || !self.active
            || self.finished
            || self.dirty
            || self.tracker.unknown.load(Ordering::Acquire)
        {
            return None;
        }
        self.active = false;
        self.finished = true;
        Some(DeferredDeletedClose {
            tracker: Arc::clone(tracker),
            active: true,
        })
    }

    /// Record known modified ranges before any body open or recovery write.
    /// The permit remains active until `finish_durable` after the handoff.
    pub(crate) fn mark_dirty_before_capture(&mut self) {
        if self.finished || self.dirty {
            self.tracker.mark_unknown();
            return;
        }
        self.dirty = true;
        if !self.active {
            self.tracker.mark_unknown();
        }
        let Some(mut state) = self.tracker.try_state() else {
            return;
        };
        match state.dirty_epoch.checked_add(1) {
            Some(epoch) => state.dirty_epoch = epoch,
            None => self.tracker.mark_unknown(),
        }
    }

    /// Finish only after protected persistence and its initial queue handoff
    /// have both been attempted successfully.
    pub(crate) fn finish_durable(&mut self) {
        if self.finished || !self.dirty {
            self.tracker.mark_unknown();
        }
        if self.active && !self.tracker.decrement_active() {
            self.tracker.mark_unknown();
        }
        self.active = false;
        self.finished = true;
    }
}

impl Drop for CloseCapturePermit<'_> {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.tracker.mark_unknown();
        if self.active {
            let _ = self.tracker.decrement_active();
            self.active = false;
        }
    }
}

/// Owned pending bookkeeping only. Its sole successful consumer must hold an
/// exact native successful delete-completion receipt. Drop preserves unknown;
/// no path in this type clears an already unknown admission state.
#[cfg(any(windows, test))]
pub(crate) struct DeferredDeletedClose {
    tracker: Arc<CloseCaptureAdmission>,
    active: bool,
}
#[cfg(any(windows, test))]
impl DeferredDeletedClose {
    pub(crate) fn finish_after_owned_completion(mut self) -> bool {
        let known = !self.tracker.unknown.load(Ordering::Acquire);
        let decremented = self.tracker.decrement_active();
        self.active = false;
        if !known || !decremented {
            self.tracker.mark_unknown();
            return false;
        }
        !self.tracker.unknown.load(Ordering::Acquire)
    }
}
#[cfg(any(windows, test))]
impl Drop for DeferredDeletedClose {
    fn drop(&mut self) {
        if self.active {
            self.tracker.mark_unknown();
            let _ = self.tracker.decrement_active();
        }
    }
}

/// A single active rename attempt's epoch snapshot. It holds no mutex while
/// the caller performs remote or storage work. Captures always continue and
/// invalidate it through active-close state or a dirty epoch increment.
pub(crate) struct SaveRenameTicket<'a> {
    tracker: &'a CloseCaptureAdmission,
    ticket: TicketState,
}

// Both ticket shapes use the same original tracker transitions. Only the owned
// create wrapper also requires its mint-time close observation to stay unchanged.
struct TicketState {
    epoch: u64,
    observation: u64,
    dispatch_claimed: bool,
    completion_claimed: bool,
}

/// Retained across owner-loop turns, never cloned or moved to an SDK worker.
/// Atomic probes can travel; this custody and its claims stay on the owner thread.
#[cfg(any(windows, test))]
pub(crate) struct OwnedCreateAdmission {
    tracker: Arc<CloseCaptureAdmission>,
    ticket: TicketState,
    dispatch: Arc<dyn Fn() -> bool + Send + Sync>,
    lifetime: DispatchProbeLifetime,
    _owner_thread: PhantomData<Rc<()>>,
}

// Deliberately preparatory private API: owner-worker integration is not enabled.
#[cfg(any(windows, test))]
#[cfg_attr(not(test), allow(dead_code))]
impl OwnedCreateAdmission {
    pub(crate) fn is_current(&self) -> bool {
        self.ticket.is_current(&self.tracker, true)
    }

    pub(crate) fn observation_probe(&self) -> Arc<dyn Fn() -> bool + Send + Sync> {
        self.lifetime.observation_probe()
    }

    pub(crate) fn dispatch_probe(&self) -> Arc<dyn Fn() -> bool + Send + Sync> {
        self.dispatch.clone()
    }

    pub(crate) fn claim_dispatch(&mut self) -> bool {
        if !self.ticket.claim_dispatch(&self.tracker, true) {
            return false;
        }
        if !self.lifetime.arm_after_dispatch() {
            self.tracker.mark_unknown();
            return false;
        }
        true
    }

    pub(crate) fn claim_completion(&mut self) -> bool {
        self.ticket.claim_completion(&self.tracker, true)
    }
}

#[cfg(any(windows, test))]
impl Drop for OwnedCreateAdmission {
    fn drop(&mut self) {
        self.lifetime.live.store(false, Ordering::Release);
        self.ticket.retire(&self.tracker);
    }
}

#[cfg(any(windows, test))]
pub(crate) struct OwnedDirectoryAdmission {
    tracker: Arc<CloseCaptureAdmission>,
    ticket: TicketState,
    dispatch: Arc<dyn Fn() -> bool + Send + Sync>,
    lifetime: DispatchProbeLifetime,
    _owner_thread: PhantomData<Rc<()>>,
}

#[cfg(any(windows, test))]
impl OwnedDirectoryAdmission {
    pub(crate) fn is_current(&self) -> bool {
        self.ticket.is_current(&self.tracker, true)
    }

    pub(crate) fn observation_probe(&self) -> Arc<dyn Fn() -> bool + Send + Sync> {
        self.lifetime.observation_probe()
    }

    pub(crate) fn dispatch_probe(&self) -> Arc<dyn Fn() -> bool + Send + Sync> {
        self.dispatch.clone()
    }

    pub(crate) fn claim_dispatch(&mut self) -> bool {
        if !self.ticket.claim_dispatch(&self.tracker, true) {
            return false;
        }
        if !self.lifetime.arm_after_dispatch() {
            self.tracker.mark_unknown();
            return false;
        }
        true
    }

    pub(crate) fn claim_completion(&mut self) -> bool {
        self.ticket.claim_completion(&self.tracker, true)
    }
}

#[cfg(any(windows, test))]
impl Drop for OwnedDirectoryAdmission {
    fn drop(&mut self) {
        self.lifetime.live.store(false, Ordering::Release);
        self.ticket.retire(&self.tracker);
    }
}

/// Ends the owned SDK observation before the borrowed ticket is retired.
#[cfg(any(windows, test))]
pub(crate) struct DispatchProbeLifetime {
    live: Arc<AtomicBool>,
    ready: Arc<AtomicBool>,
    tracker: Arc<CloseCaptureAdmission>,
    epoch: u64,
}
#[cfg(any(windows, test))]
impl Drop for DispatchProbeLifetime {
    fn drop(&mut self) {
        self.live.store(false, Ordering::Release);
    }
}
#[cfg(any(windows, test))]
impl DispatchProbeLifetime {
    fn new(
        tracker: Arc<CloseCaptureAdmission>,
        epoch: u64,
    ) -> (Arc<dyn Fn() -> bool + Send + Sync>, Self) {
        let live = Arc::new(AtomicBool::new(true));
        let ready = Arc::new(AtomicBool::new(false));
        let lifetime = Self {
            live: live.clone(),
            ready: ready.clone(),
            tracker: tracker.clone(),
            epoch,
        };
        let probe = Arc::new(move || {
            live.load(Ordering::Acquire)
                && ready.load(Ordering::Acquire)
                && !tracker.unknown.load(Ordering::Acquire)
                && tracker.create_observation.load(Ordering::Acquire) == epoch
        });
        (probe, lifetime)
    }

    pub(crate) fn observation_probe(&self) -> Arc<dyn Fn() -> bool + Send + Sync> {
        let tracker = self.tracker.clone();
        let live = self.live.clone();
        let epoch = self.epoch;
        Arc::new(move || {
            live.load(Ordering::Acquire)
                && !tracker.unknown.load(Ordering::Acquire)
                && tracker.create_observation.load(Ordering::Acquire) == epoch
        })
    }
    pub(crate) fn arm_after_dispatch(&self) -> bool {
        self.ready
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

impl SaveRenameTicket<'_> {
    #[cfg(any(windows, test))]
    #[cfg_attr(not(test), allow(dead_code))] // Phased create uses owned custody; retain borrowed contract/tests.
    pub(crate) fn dispatch_probe(
        &self,
        tracker: Arc<CloseCaptureAdmission>,
    ) -> Option<(Arc<dyn Fn() -> bool + Send + Sync>, DispatchProbeLifetime)> {
        let epoch = tracker.create_observation.load(Ordering::Acquire);
        if !std::ptr::eq(self.tracker, Arc::as_ptr(&tracker)) || !self.is_current() {
            return None;
        }
        Some(DispatchProbeLifetime::new(tracker, epoch))
    }

    #[allow(dead_code)] // R55 explicit producer rechecks this ticket.
    pub(crate) fn is_current(&self) -> bool {
        self.ticket.is_current(self.tracker, false)
    }

    /// Short ordering point, not remote atomicity; later captures still run.
    #[allow(dead_code)] // R55 explicit producer consumes this claim.
    pub(crate) fn claim_dispatch(&mut self) -> bool {
        self.ticket.claim_dispatch(self.tracker, false)
    }

    /// Linearizes completion before later close admission, with no mutex over I/O.
    #[allow(dead_code)] // R55 explicit producer completion fencing consumes this capability.
    pub(crate) fn claim_completion(&mut self) -> bool {
        self.ticket.claim_completion(self.tracker, false)
    }
}

impl TicketState {
    fn is_current(&self, tracker: &CloseCaptureAdmission, observe: bool) -> bool {
        if tracker.unknown.load(Ordering::Acquire) {
            return false;
        }
        let Some(state) = tracker.try_state() else {
            return false;
        };
        !tracker.unknown.load(Ordering::Acquire)
            && state.rename_claimed
            && state.active_closes == 0
            && state.dirty_epoch == self.epoch
            && state.dispatch_claimed == self.dispatch_claimed
            && state.completion_claimed == self.completion_claimed
            && (!observe || tracker.create_observation.load(Ordering::Acquire) == self.observation)
    }

    fn claim_dispatch(&mut self, tracker: &CloseCaptureAdmission, observe: bool) -> bool {
        if self.dispatch_claimed || !self.is_current(tracker, observe) {
            return false;
        }
        let Some(mut state) = tracker.try_state() else {
            return false;
        };
        if !state.rename_claimed
            || state.dispatch_claimed
            || state.completion_claimed
            || state.active_closes != 0
            || state.dirty_epoch != self.epoch
            || tracker.unknown.load(Ordering::Acquire)
            || (observe && tracker.create_observation.load(Ordering::Acquire) != self.observation)
        {
            return false;
        }
        state.dispatch_claimed = true;
        self.dispatch_claimed = true;
        true
    }

    fn claim_completion(&mut self, tracker: &CloseCaptureAdmission, observe: bool) -> bool {
        if self.completion_claimed || !self.dispatch_claimed || !self.is_current(tracker, observe) {
            return false;
        }
        let Some(mut state) = tracker.try_state() else {
            return false;
        };
        if !state.rename_claimed
            || !state.dispatch_claimed
            || state.completion_claimed
            || state.active_closes != 0
            || state.dirty_epoch != self.epoch
            || tracker.unknown.load(Ordering::Acquire)
            || (observe && tracker.create_observation.load(Ordering::Acquire) != self.observation)
        {
            return false;
        }
        // Same short-lock completion ordering used by the borrowed ticket.
        state.completion_claimed = true;
        self.completion_claimed = true;
        true
    }

    fn retire(&self, tracker: &CloseCaptureAdmission) {
        tracker.advance_create_observation();
        let Some(mut state) = tracker.try_state() else {
            return;
        };
        if !state.rename_claimed
            || state.dispatch_claimed != self.dispatch_claimed
            || state.completion_claimed != self.completion_claimed
        {
            tracker.mark_unknown();
        }
        state.rename_claimed = false;
        state.dispatch_claimed = false;
    }
}

#[cfg(test)]
mod connected_create_probe_tests {
    use super::*;
    #[test]
    fn retired_ticket_invalidates_probe_even_if_lifetime_outlives_it() {
        let tracker = Arc::new(CloseCaptureAdmission::default());
        let mut ticket = tracker.try_begin_rename().unwrap();
        let (probe, lifetime) = ticket.dispatch_probe(tracker.clone()).unwrap();
        assert!(ticket.claim_dispatch());
        assert!(lifetime.arm_after_dispatch());
        assert!(probe());
        drop(ticket);
        let mut next = tracker.try_begin_rename().unwrap();
        assert!(next.claim_dispatch());
        assert!(!probe());
        drop(lifetime);
    }

    #[test]
    fn concurrent_atomic_polling_does_not_poison_and_claim_is_one_use() {
        let tracker = Arc::new(CloseCaptureAdmission::default());
        let mut ticket = tracker.try_begin_rename().unwrap();
        assert!(
            ticket
                .dispatch_probe(Arc::new(CloseCaptureAdmission::default()))
                .is_none()
        );
        let (probe, lifetime) = ticket.dispatch_probe(tracker.clone()).unwrap();
        assert!(!probe());
        assert!(ticket.claim_dispatch());
        assert!(!ticket.claim_dispatch());
        assert!(lifetime.arm_after_dispatch());
        assert!(!lifetime.arm_after_dispatch());
        let workers = (0..8)
            .map(|_| {
                let probe = probe.clone();
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        assert!(probe());
                    }
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap();
        }
        assert!(!tracker.unknown.load(Ordering::Acquire));
    }
    #[test]
    fn dropped_lifetime_never_resurrects_under_new_clean_ticket() {
        let tracker = Arc::new(CloseCaptureAdmission::default());
        let mut ticket = tracker.try_begin_rename().unwrap();
        let (probe, lifetime) = ticket.dispatch_probe(tracker.clone()).unwrap();
        assert!(ticket.claim_dispatch());
        assert!(lifetime.arm_after_dispatch());
        assert!(probe());
        drop(lifetime);
        drop(ticket);
        let mut next = tracker.try_begin_rename().unwrap();
        assert!(next.claim_dispatch());
        assert!(!probe());
    }
    #[test]
    fn even_clean_close_invalidates_only_new_create_probe() {
        let tracker = Arc::new(CloseCaptureAdmission::default());
        let mut ticket = tracker.try_begin_rename().unwrap();
        let (probe, lifetime) = ticket.dispatch_probe(tracker.clone()).unwrap();
        assert!(ticket.claim_dispatch());
        assert!(lifetime.arm_after_dispatch());
        let mut close = tracker.begin_close();
        assert!(!probe());
        close.finish_clean();
        assert!(ticket.is_current(), "original rename semantics preserved");
        assert!(!probe());
    }
    #[test]
    fn dirty_unknown_and_observation_overflow_fail_closed() {
        let tracker = Arc::new(CloseCaptureAdmission::default());
        let mut ticket = tracker.try_begin_rename().unwrap();
        let (probe, lifetime) = ticket.dispatch_probe(tracker.clone()).unwrap();
        assert!(ticket.claim_dispatch());
        assert!(lifetime.arm_after_dispatch());
        let mut close = tracker.begin_close();
        close.mark_dirty_before_capture();
        close.finish_durable();
        assert!(!probe());
        tracker
            .create_observation
            .store(u64::MAX, Ordering::Release);
        let mut close = tracker.begin_close();
        close.finish_clean();
        assert!(tracker.unknown.load(Ordering::Acquire));
        assert!(!probe());
    }
}

impl Drop for SaveRenameTicket<'_> {
    fn drop(&mut self) {
        self.ticket.retire(self.tracker);
    }
}

#[cfg(test)]
#[path = "owned_create_admission_tests.rs"]
mod owned_create_admission_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Arc, sync::Barrier, thread};

    #[test]
    fn r51_clean_close_blocks_only_while_active_and_does_not_advance_epoch() {
        let tracker = CloseCaptureAdmission::default();
        let mut close = tracker.begin_close();
        assert!(tracker.try_begin_rename().is_none());
        close.finish_clean();
        assert_eq!(tracker.state.lock().unwrap().dirty_epoch, 0);

        let ticket = tracker
            .try_begin_rename()
            .expect("clean close is quiescent");
        assert!(ticket.is_current());
    }

    #[test]
    fn r51_dirty_close_advances_epoch_before_body_and_stays_active_through_handoff() {
        let tracker = CloseCaptureAdmission::default();
        let mut close = tracker.begin_close();
        close.mark_dirty_before_capture();
        {
            let state = tracker.state.lock().unwrap();
            assert_eq!(state.dirty_epoch, 1);
            assert_eq!(state.active_closes, 1);
        }
        assert!(tracker.try_begin_rename().is_none());

        // Simulate completed body capture while the permit still spans the
        // durable commit/initial-queue handoff boundary.
        {
            let state = tracker.state.lock().unwrap();
            assert_eq!(state.dirty_epoch, 1);
            assert_eq!(state.active_closes, 1);
        }
        close.finish_durable();
        assert_eq!(tracker.state.lock().unwrap().active_closes, 0);
        assert!(tracker.try_begin_rename().is_some());
    }

    #[test]
    fn r51_unclassified_or_failed_dirty_close_poison_summary() {
        let tracker = CloseCaptureAdmission::default();
        drop(tracker.begin_close());
        assert!(tracker.try_begin_rename().is_none());

        let tracker = CloseCaptureAdmission::default();
        let mut close = tracker.begin_close();
        close.mark_dirty_before_capture();
        drop(close); // no durable commit/handoff
        assert!(tracker.try_begin_rename().is_none());
    }

    #[test]
    fn r51_overflow_and_poison_are_fail_closed_without_close_suppression() {
        let overflow = CloseCaptureAdmission::default();
        overflow.state.lock().unwrap().active_closes = usize::MAX;
        let mut permit = overflow.begin_close();
        // Capture code still receives a permit and may continue, but admission
        // is irreversibly unknown after counter overflow.
        permit.mark_dirty_before_capture();
        permit.finish_durable();
        assert!(overflow.try_begin_rename().is_none());

        let poisoned = Arc::new(CloseCaptureAdmission::default());
        let other = Arc::clone(&poisoned);
        assert!(
            thread::spawn(move || {
                let _guard = other.state.lock().unwrap();
                panic!("synthetic tracker poison");
            })
            .join()
            .is_err()
        );
        let _permit = poisoned.begin_close();
        assert!(poisoned.unknown.load(Ordering::Acquire));
        assert!(poisoned.try_begin_rename().is_none());
    }

    #[test]
    fn r51_single_claim_and_concurrent_capture_invalidation() {
        let tracker = CloseCaptureAdmission::default();
        let mut ticket = tracker.try_begin_rename().expect("first ticket");
        assert!(tracker.try_begin_rename().is_none());
        assert!(ticket.claim_dispatch());
        assert!(!ticket.claim_dispatch());

        let mut close = tracker.begin_close();
        assert!(!ticket.is_current());
        close.mark_dirty_before_capture();
        close.finish_durable();
        assert!(!ticket.is_current());
        drop(ticket);
        assert!(tracker.try_begin_rename().is_some());
    }

    #[test]
    fn r51_concurrent_close_start_precedes_rename_ticket_without_blocking_capture() {
        let tracker = Arc::new(CloseCaptureAdmission::default());
        let close_started = Arc::new(Barrier::new(2));
        let release_close = Arc::new(Barrier::new(2));
        let worker_tracker = Arc::clone(&tracker);
        let worker_started = Arc::clone(&close_started);
        let worker_release = Arc::clone(&release_close);
        let worker = thread::spawn(move || {
            let mut permit = worker_tracker.begin_close();
            worker_started.wait();
            worker_release.wait();
            permit.finish_clean();
        });

        close_started.wait();
        assert!(tracker.try_begin_rename().is_none());
        release_close.wait();
        worker.join().unwrap();
        assert!(tracker.try_begin_rename().is_some());
    }

    #[test]
    fn r55_completion_claim_refuses_active_or_dirty_close() {
        let tracker = CloseCaptureAdmission::default();
        let mut ticket = tracker.try_begin_rename().expect("rename ticket");
        assert!(!ticket.claim_completion());
        assert!(ticket.claim_dispatch());

        let mut close = tracker.begin_close();
        assert!(!ticket.claim_completion());
        close.mark_dirty_before_capture();
        assert!(!ticket.claim_completion());
        close.finish_durable();
        assert!(!ticket.claim_completion());
    }

    #[test]
    fn r55_completion_claim_is_one_use_and_orders_later_capture() {
        let tracker = CloseCaptureAdmission::default();
        let mut ticket = tracker.try_begin_rename().expect("rename ticket");
        assert!(ticket.claim_dispatch());
        assert!(ticket.claim_completion());
        assert!(!ticket.claim_completion());

        // A close after completion's ordering point still captures normally,
        // but prevents another rename until its durable handoff finishes.
        let mut close = tracker.begin_close();
        assert!(tracker.try_begin_rename().is_none());
        close.mark_dirty_before_capture();
        assert!(!ticket.is_current());
        close.finish_durable();
        drop(ticket);
        assert!(tracker.try_begin_rename().is_some());
    }
}

#[cfg(test)]
mod owned_deleted_close_tests {
    use super::*;
    #[test]
    fn transfer_requires_same_arc_and_keeps_admission_active_until_completion() {
        let tracker = Arc::new(CloseCaptureAdmission::default());
        let other = Arc::new(CloseCaptureAdmission::default());
        let ticket = tracker.try_begin_rename().unwrap();
        let mut close = tracker.begin_close();
        assert!(close.defer_owned_deleted(&other).is_none());
        let pending = close.defer_owned_deleted(&tracker).unwrap();
        drop(close);
        assert!(!ticket.is_current());
        assert!(pending.finish_after_owned_completion());
        assert!(ticket.is_current());
    }
    #[test]
    fn uncertain_retirement_and_existing_unknown_can_never_be_cleaned() {
        let tracker = Arc::new(CloseCaptureAdmission::default());
        let mut close = tracker.begin_close();
        let pending = close.defer_owned_deleted(&tracker).unwrap();
        drop(close);
        drop(pending);
        assert!(tracker.unknown.load(Ordering::Acquire));
        let mut close = tracker.begin_close();
        assert!(close.defer_owned_deleted(&tracker).is_none());
        close.finish_clean();
        assert!(tracker.unknown.load(Ordering::Acquire));
    }
}

#[cfg(windows)]
#[path = "independent_create_admission.rs"]
mod independent_create;
#[cfg(windows)]
pub(crate) use independent_create::IndependentCreateAdmission;
