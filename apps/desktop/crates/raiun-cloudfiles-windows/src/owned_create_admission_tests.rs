use super::*;
use std::{sync::Barrier, thread};

#[test]
fn owned_custody_outlives_the_initial_arc_borrow_and_claims_once() {
    let tracker = Arc::new(CloseCaptureAdmission::default());
    let weak = Arc::downgrade(&tracker);
    let mut owned = {
        let temporary_owner = tracker.clone();
        temporary_owner.try_begin_create().unwrap()
    };
    drop(tracker);
    assert!(weak.upgrade().is_some());
    assert!(owned.is_current());
    let observation = owned.observation_probe();
    let dispatch = owned.dispatch_probe();
    assert!(observation());
    assert!(!dispatch());
    assert!(!owned.claim_completion());
    assert!(owned.claim_dispatch());
    assert!(dispatch());
    assert!(!owned.claim_dispatch());
    assert!(owned.claim_completion());
    assert!(!owned.claim_completion());
    drop(owned);
    assert!(!observation() && !dispatch());
    drop(observation);
    drop(dispatch);
    assert!(weak.upgrade().is_none());
}

#[test]
fn borrowed_and_owned_attempts_share_the_original_single_claim() {
    let tracker = Arc::new(CloseCaptureAdmission::default());
    let owned = tracker.try_begin_create().unwrap();
    assert!(tracker.try_begin_create().is_none());
    assert!(tracker.try_begin_rename().is_none());
    drop(owned);
    let borrowed = tracker.try_begin_rename().unwrap();
    assert!(tracker.try_begin_create().is_none());
    drop(borrowed);
    let next = tracker.try_begin_create().unwrap();
    assert!(next.is_current());
}

#[test]
fn clean_close_invalidates_owned_attempt_without_changing_borrowed_semantics() {
    let tracker = Arc::new(CloseCaptureAdmission::default());
    let mut owned = tracker.try_begin_create().unwrap();
    let observation = owned.observation_probe();
    let dispatch = owned.dispatch_probe();
    let mut close = tracker.begin_close();
    assert!(!owned.is_current());
    assert!(!owned.claim_dispatch());
    close.finish_clean();
    assert!(!owned.is_current());
    assert!(!owned.claim_dispatch());
    assert!(!observation() && !dispatch());
    assert!(!owned.observation_probe()(), "no refreshed observation");
    drop(owned);
    let borrowed = tracker.try_begin_rename().unwrap();
    let mut close = tracker.begin_close();
    close.finish_clean();
    assert!(borrowed.is_current());
    assert!(!observation());
}

#[test]
fn dirty_close_keeps_capture_live_but_refuses_owned_completion() {
    let tracker = Arc::new(CloseCaptureAdmission::default());
    let mut owned = tracker.try_begin_create().unwrap();
    let dispatch = owned.dispatch_probe();
    assert!(owned.claim_dispatch());
    let mut close = tracker.begin_close();
    close.mark_dirty_before_capture();
    assert_eq!(tracker.state.lock().unwrap().active_closes, 1);
    assert!(!dispatch());
    assert!(!owned.claim_completion());
    close.finish_durable();
    assert!(!owned.is_current());
    assert!(!owned.claim_completion());
    drop(owned);
    let mut next = tracker.try_begin_create().unwrap();
    assert!(next.claim_dispatch());
    assert!(!dispatch());
}

#[test]
fn atomic_worker_probes_retire_without_poison_or_resurrection() {
    let tracker = Arc::new(CloseCaptureAdmission::default());
    let mut owned = tracker.try_begin_create().unwrap();
    let dispatch = owned.dispatch_probe();
    let observation = owned.observation_probe();
    assert!(owned.claim_dispatch());
    let ready = Arc::new(Barrier::new(3));
    let retired = Arc::new(Barrier::new(3));
    let workers = (0..2)
        .map(|_| {
            let dispatch = dispatch.clone();
            let observation = observation.clone();
            let ready = ready.clone();
            let retired = retired.clone();
            thread::spawn(move || {
                for _ in 0..1000 {
                    assert!(dispatch() && observation());
                }
                ready.wait();
                retired.wait();
                assert!(!dispatch() && !observation());
            })
        })
        .collect::<Vec<_>>();
    ready.wait();
    assert!(!tracker.unknown.load(Ordering::Acquire));
    drop(owned);
    let mut next = tracker.try_begin_rename().unwrap();
    assert!(next.claim_dispatch());
    retired.wait();
    for worker in workers {
        worker.join().unwrap();
    }
    assert!(!tracker.unknown.load(Ordering::Acquire));
}

#[test]
fn active_unknown_and_observation_overflow_refuse_owned_authority() {
    let tracker = Arc::new(CloseCaptureAdmission::default());
    let mut close = tracker.begin_close();
    assert!(tracker.try_begin_create().is_none());
    close.finish_clean();
    let mut owned = tracker.try_begin_create().unwrap();
    assert!(owned.claim_dispatch());
    let dispatch = owned.dispatch_probe();
    tracker.mark_unknown();
    assert!(!owned.is_current() && !dispatch());
    assert!(!owned.claim_completion());
    drop(owned);
    assert!(tracker.try_begin_create().is_none());

    let tracker = Arc::new(CloseCaptureAdmission::default());
    tracker
        .create_observation
        .store(u64::MAX, Ordering::Release);
    let mut owned = tracker.try_begin_create().unwrap();
    let observation = owned.observation_probe();
    let mut close = tracker.begin_close();
    close.finish_clean();
    assert!(tracker.unknown.load(Ordering::Acquire));
    assert!(!owned.claim_dispatch() && !observation());
    drop(owned);
    assert!(tracker.try_begin_rename().is_none());
}

#[test]
fn failed_close_and_tracker_contention_stay_unknown() {
    let tracker = Arc::new(CloseCaptureAdmission::default());
    let mut owned = tracker.try_begin_create().unwrap();
    let dispatch = owned.dispatch_probe();
    assert!(owned.claim_dispatch());
    drop(tracker.begin_close());
    assert!(!owned.is_current() && !dispatch());
    drop(owned);
    assert!(tracker.try_begin_create().is_none());

    let tracker = Arc::new(CloseCaptureAdmission::default());
    let state = tracker.state.lock().unwrap();
    assert!(tracker.try_begin_create().is_none());
    drop(state);
    assert!(tracker.unknown.load(Ordering::Acquire));
    assert!(tracker.try_begin_rename().is_none());
}

#[test]
fn owned_custody_cannot_be_sent_or_shared_with_workers() {
    // Inference is ambiguous if the owned type ever implements either trait.
    trait AmbiguousIfSend<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfSend<()> for T {}
    impl<T: ?Sized + Send> AmbiguousIfSend<u8> for T {}
    trait AmbiguousIfSync<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfSync<()> for T {}
    impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for T {}
    let _ = <OwnedCreateAdmission as AmbiguousIfSend<_>>::check;
    let _ = <OwnedCreateAdmission as AmbiguousIfSync<_>>::check;
}
