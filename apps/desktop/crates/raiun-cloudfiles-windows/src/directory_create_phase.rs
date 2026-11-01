//! Private directory-task correlation and disposal; no native or dispatch authority.
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Phase {
    Prepare,
    Preflight,
    Send,
    Refresh,
}
#[derive(Eq, PartialEq)]
pub(crate) enum ReplyDisposition {
    Wrong,
    Retire,
    Accept,
}
pub(crate) struct ReplyKey {
    pub(crate) nonce: u64,
    pub(crate) context: usize,
    pub(crate) root: crate::ConfiguredRootIdentity,
    pub(crate) generation: u64,
    pub(crate) authorization: crate::namespace_intent::CapturedAuthorization,
}
impl ReplyKey {
    pub(crate) fn disposition(
        expected: &Arc<Self>,
        actual: &Arc<Self>,
        phase: Phase,
        actual_phase: Phase,
        flight_done: bool,
        stopped: bool,
        closed: bool,
    ) -> ReplyDisposition {
        if !Self::accepts(expected, actual, phase, actual_phase) || !flight_done {
            ReplyDisposition::Wrong
        } else if stopped || closed {
            ReplyDisposition::Retire
        } else {
            ReplyDisposition::Accept
        }
    }
    pub(crate) fn accepts(
        expected: &Arc<Self>,
        actual: &Arc<Self>,
        phase: Phase,
        actual_phase: Phase,
    ) -> bool {
        Arc::ptr_eq(expected, actual) && phase == actual_phase
    }
}
/// Must be the LAST task field: disposal of owned network/body data precedes it.
pub(crate) struct TaskFlight(Arc<AtomicBool>);
impl TaskFlight {
    pub(crate) fn new() -> (Arc<AtomicBool>, Self) {
        let done = Arc::new(AtomicBool::new(false));
        (done.clone(), Self(done))
    }
}
impl Drop for TaskFlight {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn key() -> Arc<ReplyKey> {
        Arc::new(ReplyKey {
            nonce: 1,
            context: 2,
            root: crate::ConfiguredRootIdentity {
                volume_serial: 1,
                file_index: 3,
            },
            generation: 1,
            authorization: crate::namespace_intent::CapturedAuthorization {
                agent_generation: 1,
                token_generation: 2,
            },
        })
    }
    #[test]
    fn equal_metadata_cannot_adopt_another_attempt_reply() {
        let original = key();
        let same = original.clone();
        let other = key();
        assert!(
            original.nonce == other.nonce
                && original.context == other.context
                && original.root == other.root
                && original.generation == other.generation
                && original.authorization == other.authorization
        );
        assert!(ReplyKey::accepts(
            &original,
            &same,
            Phase::Prepare,
            Phase::Prepare
        ));
        assert!(!ReplyKey::accepts(
            &original,
            &other,
            Phase::Prepare,
            Phase::Prepare
        ));
    }
    #[test]
    fn delayed_or_reordered_phase_reply_is_refused() {
        let original = key();
        assert!(!ReplyKey::accepts(
            &original,
            &original,
            Phase::Preflight,
            Phase::Prepare
        ));
        assert!(!ReplyKey::accepts(
            &original,
            &original,
            Phase::Send,
            Phase::Preflight
        ));
        assert!(!ReplyKey::accepts(
            &original,
            &original,
            Phase::Send,
            Phase::Prepare
        ));
        assert!(!ReplyKey::accepts(
            &original,
            &original,
            Phase::Refresh,
            Phase::Send
        ));
    }
    #[test]
    fn task_disposal_signal_follows_owned_body_disposal() {
        struct Body {
            done: Arc<AtomicBool>,
            dropped: Arc<AtomicBool>,
        }
        impl Drop for Body {
            fn drop(&mut self) {
                assert!(!self.done.load(Ordering::Acquire));
                self.dropped.store(true, Ordering::Release);
            }
        }
        struct Task {
            _body: Body,
            _flight: TaskFlight,
        }
        let (done, flight) = TaskFlight::new();
        let dropped = Arc::new(AtomicBool::new(false));
        let task = Task {
            _body: Body {
                done: done.clone(),
                dropped: dropped.clone(),
            },
            _flight: flight,
        };
        assert!(!done.load(Ordering::Acquire));
        std::thread::spawn(move || drop(task)).join().unwrap();
        assert!(dropped.load(Ordering::Acquire) && done.load(Ordering::Acquire));
    }
    #[test]
    fn canceled_original_job_and_closed_admission_retire_only_original_reply() {
        let original = key();
        let other = key();
        let job = crate::CancellationToken::for_recovery_job(
            crate::StreamedRecoveryPolicy::new(std::time::Duration::from_secs(60)).unwrap(),
        );
        let worker_job = job.clone();
        let deadline = worker_job.deadline();
        assert!(
            ReplyKey::disposition(
                &original,
                &original,
                Phase::Send,
                Phase::Send,
                true,
                worker_job.is_stopped(),
                false
            ) == ReplyDisposition::Accept
        );
        job.cancel();
        assert_eq!(worker_job.deadline(), deadline);
        assert!(
            ReplyKey::disposition(
                &original,
                &original,
                Phase::Send,
                Phase::Send,
                true,
                worker_job.is_stopped(),
                false
            ) == ReplyDisposition::Retire
        );
        assert!(
            ReplyKey::disposition(
                &original,
                &original,
                Phase::Refresh,
                Phase::Refresh,
                true,
                false,
                true
            ) == ReplyDisposition::Retire
        );
        assert!(
            ReplyKey::disposition(
                &other,
                &original,
                Phase::Send,
                Phase::Send,
                true,
                true,
                true
            ) == ReplyDisposition::Wrong
        );
    }
    #[test]
    fn actual_task_flight_blocks_reply_until_disposal() {
        let original = key();
        let (done, flight) = TaskFlight::new();
        assert!(
            ReplyKey::disposition(
                &original,
                &original,
                Phase::Prepare,
                Phase::Prepare,
                done.load(Ordering::Acquire),
                false,
                false
            ) == ReplyDisposition::Wrong
        );
        std::thread::spawn(move || drop(flight)).join().unwrap();
        assert!(
            ReplyKey::disposition(
                &original,
                &original,
                Phase::Prepare,
                Phase::Prepare,
                done.load(Ordering::Acquire),
                false,
                false
            ) == ReplyDisposition::Accept
        );
    }
    #[test]
    fn actual_original_tracker_keeps_one_owned_attempt_per_root() {
        let tracker = Arc::new(crate::close_capture_admission::CloseCaptureAdmission::default());
        let original = tracker.try_begin_directory().unwrap();
        assert!(
            tracker.try_begin_directory().is_none()
                && tracker.try_begin_create().is_none()
                && tracker.try_begin_rename().is_none()
        );
        drop(original);
        assert!(tracker.try_begin_directory().is_some());
    }
    #[test]
    fn distinct_directory_claim_is_one_use_and_close_or_retirement_revokes_probe() {
        let tracker = Arc::new(crate::close_capture_admission::CloseCaptureAdmission::default());
        let mut ticket = tracker.try_begin_directory().unwrap();
        let observation = ticket.observation_probe();
        assert!(ticket.is_current() && observation());
        let probe = ticket.dispatch_probe();
        assert!(!probe());
        assert!(ticket.claim_dispatch());
        assert!(probe());
        assert!(!ticket.claim_dispatch());
        assert!(ticket.claim_completion());
        assert!(!ticket.claim_completion());
        assert!(ticket.is_current() && observation());
        let mut close = tracker.begin_close();
        close.finish_clean();
        assert!(!probe() && !observation() && !ticket.is_current());
        drop(close);
        drop(ticket);
        let later = tracker.try_begin_create().unwrap();
        assert!(!probe());
        drop(later);
    }
}
