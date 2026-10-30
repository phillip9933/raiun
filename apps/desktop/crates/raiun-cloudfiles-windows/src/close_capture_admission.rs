//! Short admission bookkeeping between native close capture and save/rename.
//!
//! This tracker carries no backend, recovery, path, or native authority. Its
//! mutex is held only while counters and epochs change; callers must drop every
//! mutex guard before doing I/O. Close capture is never suppressed when admission
//! bookkeeping fails: failure makes future rename admission unknown instead.

use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Default)]
struct State {
    active_closes: usize,
    dirty_epoch: u64,
    rename_claimed: bool,
    dispatch_claimed: bool,
}

#[derive(Default)]
pub(crate) struct CloseCaptureAdmission {
    state: Mutex<State>,
    unknown: AtomicBool,
}

impl CloseCaptureAdmission {
    /// Begin tracking before inspecting callback parameters or native state.
    /// Failure is fail-closed for rename admission but does not stop capture.
    pub(crate) fn begin_close(&self) -> CloseCapturePermit<'_> {
        let active = match self.try_state() {
            Some(mut state) => match state.active_closes.checked_add(1) {
                Some(next) => {
                    state.active_closes = next;
                    true
                }
                None => {
                    self.unknown.store(true, Ordering::Release);
                    false
                }
            },
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
    #[allow(dead_code)] // R52 producer integration consumes this capability.
    pub(crate) fn try_begin_rename(&self) -> Option<SaveRenameTicket<'_>> {
        if self.unknown.load(Ordering::Acquire) {
            return None;
        }
        let mut state = self.try_state()?;
        if self.unknown.load(Ordering::Acquire) || state.active_closes != 0 || state.rename_claimed
        {
            return None;
        }
        state.rename_claimed = true;
        state.dispatch_claimed = false;
        Some(SaveRenameTicket {
            tracker: self,
            epoch: state.dirty_epoch,
            dispatch_claimed: false,
        })
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

    fn mark_unknown(&self) {
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

/// A single active rename attempt's epoch snapshot. It holds no mutex while
/// the caller performs remote or storage work. Captures always continue and
/// invalidate it through active-close state or a dirty epoch increment.
pub(crate) struct SaveRenameTicket<'a> {
    tracker: &'a CloseCaptureAdmission,
    epoch: u64,
    dispatch_claimed: bool,
}

impl SaveRenameTicket<'_> {
    #[allow(dead_code)] // R52 producer integration rechecks this ticket.
    pub(crate) fn is_current(&self) -> bool {
        if self.tracker.unknown.load(Ordering::Acquire) {
            return false;
        }
        let Some(state) = self.tracker.try_state() else {
            return false;
        };
        !self.tracker.unknown.load(Ordering::Acquire)
            && state.rename_claimed
            && state.active_closes == 0
            && state.dirty_epoch == self.epoch
            && (state.dispatch_claimed == self.dispatch_claimed)
    }

    /// Short local ordering point immediately before a future remote send.
    /// This is not a remote atomicity guarantee; later close activity remains
    /// enabled and invalidates the ticket for subsequent local phases.
    #[allow(dead_code)] // R52 producer integration consumes this claim.
    pub(crate) fn claim_dispatch(&mut self) -> bool {
        if self.dispatch_claimed || !self.is_current() {
            return false;
        }
        let Some(mut state) = self.tracker.try_state() else {
            return false;
        };
        if !state.rename_claimed
            || state.dispatch_claimed
            || state.active_closes != 0
            || state.dirty_epoch != self.epoch
            || self.tracker.unknown.load(Ordering::Acquire)
        {
            return false;
        }
        state.dispatch_claimed = true;
        self.dispatch_claimed = true;
        true
    }
}

impl Drop for SaveRenameTicket<'_> {
    fn drop(&mut self) {
        let Some(mut state) = self.tracker.try_state() else {
            return;
        };
        if !state.rename_claimed || state.dispatch_claimed != self.dispatch_claimed {
            self.tracker.mark_unknown();
        }
        state.rename_claimed = false;
        state.dispatch_claimed = false;
    }
}

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
}
