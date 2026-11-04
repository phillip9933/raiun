use super::*;
use std::time::Duration;
struct Work {
    started: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
    dropped: Arc<AtomicBool>,
}
impl Drop for Work {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}
fn held(work: Work) -> u64 {
    work.started.send(()).unwrap();
    work.release.recv().unwrap();
    7
}
fn job() -> (Work, mpsc::Receiver<()>, mpsc::Sender<()>, Arc<AtomicBool>) {
    let (s, r) = mpsc::channel();
    let (a, b) = mpsc::channel();
    let d = Arc::new(AtomicBool::new(false));
    (
        Work {
            started: s,
            release: b,
            dropped: d.clone(),
        },
        r,
        a,
        d,
    )
}
#[test]
fn two_actual_workers_hold_and_completed_results_keep_capacity() {
    let mut pool = Executor::start(held).unwrap();
    let (a, sa, ra, da) = job();
    let (b, sb, rb, db) = job();
    assert_eq!(pool.submit(a).ok(), Some(1));
    assert_eq!(pool.submit(b).ok(), Some(2));
    sa.recv_timeout(Duration::from_secs(2)).unwrap();
    sb.recv_timeout(Duration::from_secs(2)).unwrap();
    let (c, _, _, dc) = job();
    let c = pool.submit(c).err().unwrap();
    assert!(!dc.load(Ordering::Acquire));
    ra.send(()).unwrap();
    rb.send(()).unwrap();
    while !(da.load(Ordering::Acquire) && db.load(Ordering::Acquire)) {
        thread::yield_now();
    }
    let c = pool.submit(c).err().unwrap();
    drop(c);
    assert!(dc.load(Ordering::Acquire));
    let mut done = Vec::new();
    while done.len() < 2 {
        if let Some(c) = pool.poll() {
            done.push(c.result.unwrap());
        } else {
            thread::yield_now();
        }
    }
    assert_eq!(done, vec![7, 7]);
    pool.stop_and_join();
}
#[test]
fn stop_joins_actual_held_work_and_drops_late_reply() {
    let mut pool = Executor::start(held).unwrap();
    let (a, sa, ra, d) = job();
    pool.submit(a).ok().unwrap();
    sa.recv_timeout(Duration::from_secs(2)).unwrap();
    let (finished, observed) = mpsc::channel();
    let worker = thread::spawn(move || {
        pool.stop_and_join();
        finished.send(()).unwrap();
    });
    assert!(observed.recv_timeout(Duration::from_millis(30)).is_err());
    assert!(!d.load(Ordering::Acquire));
    ra.send(()).unwrap();
    observed.recv_timeout(Duration::from_secs(2)).unwrap();
    worker.join().unwrap();
    assert!(d.load(Ordering::Acquire));
}
#[test]
fn panic_returns_failure_and_frees_slot_only_when_polled() {
    fn panic_task(_: ()) {
        panic!("owned test panic")
    }
    let mut pool = Executor::start(panic_task).unwrap();
    pool.submit(()).unwrap();
    loop {
        if let Some(done) = pool.poll() {
            assert_eq!(done.result, Err(Failure::Panicked));
            break;
        }
        thread::yield_now();
    }
    pool.stop_and_join();
    assert!(pool.submit(()).is_err());
}

#[test]
fn original_generation_and_cancel_epoch_are_not_rebased_in_worker_queue() {
    struct Scoped {
        started: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
        generation: Arc<std::sync::atomic::AtomicU64>,
        original: u64,
        cancelled: Arc<AtomicBool>,
    }
    fn execute(work: Scoped) -> bool {
        work.started.send(()).unwrap();
        work.release.recv().unwrap();
        work.generation.load(Ordering::Acquire) == work.original
            && !work.cancelled.load(Ordering::Acquire)
    }
    let mut pool = Executor::start(execute).unwrap();
    let generation = Arc::new(std::sync::atomic::AtomicU64::new(4));
    let old_cancel = Arc::new(AtomicBool::new(false));
    let (start, ready) = mpsc::channel();
    let (release, wait) = mpsc::channel();
    pool.submit(Scoped {
        started: start,
        release: wait,
        generation: generation.clone(),
        original: 4,
        cancelled: old_cancel.clone(),
    })
    .ok()
    .unwrap();
    ready.recv_timeout(Duration::from_secs(2)).unwrap();
    old_cancel.store(true, Ordering::Release);
    generation.store(5, Ordering::Release);
    // A resumed account obtains a distinct epoch. The queued task retains old_cancel.
    let new_cancel = Arc::new(AtomicBool::new(false));
    assert!(!new_cancel.load(Ordering::Acquire));
    release.send(()).unwrap();
    loop {
        if let Some(done) = pool.poll() {
            assert!(!done.result.unwrap());
            break;
        }
        thread::yield_now();
    }
    pool.stop_and_join();
}

#[test]
fn owner_unwind_cancels_before_joining_actual_worker() {
    struct Running {
        started: mpsc::Sender<()>,
        cancelled: Arc<AtomicBool>,
        done: mpsc::Sender<bool>,
    }
    fn execute(work: Running) {
        work.started.send(()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !work.cancelled.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
            thread::yield_now();
        }
        work.done
            .send(work.cancelled.load(Ordering::Acquire))
            .unwrap();
    }
    let cancelled = Arc::new(AtomicBool::new(false));
    let (start, ready) = mpsc::channel();
    let (done, finished) = mpsc::channel();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Same declaration order as the real owner: cancellation custody drops
        // before the executor, and native custody would remain below both.
        let mut workers = Executor::start(execute).unwrap();
        let cancel = cancelled.clone();
        let _owner = CancelOnDrop::new(Arc::new(move || cancel.store(true, Ordering::Release)));
        workers
            .submit(Running {
                started: start,
                cancelled: cancelled.clone(),
                done,
            })
            .ok()
            .unwrap();
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        panic!("owned lifecycle test panic");
    }));
    assert!(result.is_err());
    assert!(finished.recv_timeout(Duration::from_secs(2)).unwrap());
}

#[test]
fn mixed_kinds_share_two_workers_and_backpressure_preserves_original_task() {
    use super::super::windows_namespace_dispatcher::{CreateKind, matching_create_completion};
    struct Tagged {
        kind: CreateKind,
        original: Arc<()>,
        deadline: std::time::Instant,
        work: Work,
    }
    fn execute(task: Tagged) -> CreateKind {
        held(task.work);
        task.kind
    }
    let mut pool = Executor::start(execute).unwrap();
    let (file, file_started, release_file, file_dropped) = job();
    let (directory, directory_started, release_directory, directory_dropped) = job();
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let file_id = pool
        .submit(Tagged {
            kind: CreateKind::File,
            original: Arc::new(()),
            deadline,
            work: file,
        })
        .ok()
        .unwrap();
    let directory_id = pool
        .submit(Tagged {
            kind: CreateKind::Directory,
            original: Arc::new(()),
            deadline,
            work: directory,
        })
        .ok()
        .unwrap();
    file_started.recv_timeout(Duration::from_secs(2)).unwrap();
    directory_started
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    let (third, _, _, third_dropped) = job();
    let original = Arc::new(());
    let third = pool
        .submit(Tagged {
            kind: CreateKind::Directory,
            original: original.clone(),
            deadline,
            work: third,
        })
        .err()
        .unwrap();
    assert!(Arc::ptr_eq(&third.original, &original));
    assert_eq!(third.deadline, deadline);
    assert!(!third_dropped.load(Ordering::Acquire));
    release_file.send(()).unwrap();
    release_directory.send(()).unwrap();
    let wait_until = std::time::Instant::now() + Duration::from_secs(2);
    while !(file_dropped.load(Ordering::Acquire) && directory_dropped.load(Ordering::Acquire)) {
        assert!(std::time::Instant::now() < wait_until);
        thread::yield_now();
    }
    // Replies retain both permits until owner polling; the same unexecuted
    // directory task and its original deadline return under backpressure.
    let third = pool.submit(third).err().unwrap();
    assert!(Arc::ptr_eq(&third.original, &original));
    assert_eq!(third.deadline, deadline);
    drop(third);
    assert!(third_dropped.load(Ordering::Acquire));
    let mut completed = 0;
    while completed < 2 {
        assert!(std::time::Instant::now() < wait_until);
        if let Some(reply) = pool.poll() {
            let kind = reply.result.unwrap();
            let expected_id = if kind == CreateKind::File {
                file_id
            } else {
                directory_id
            };
            assert!(matching_create_completion(
                kind,
                expected_id,
                kind,
                reply.id
            ));
            let wrong = if kind == CreateKind::File {
                CreateKind::Directory
            } else {
                CreateKind::File
            };
            assert!(!matching_create_completion(
                wrong,
                expected_id,
                kind,
                reply.id
            ));
            assert!(!matching_create_completion(
                kind,
                expected_id + 2,
                kind,
                reply.id
            ));
            completed += 1;
        } else {
            thread::yield_now();
        }
    }
    pool.stop_and_join();
}

#[test]
fn mixed_owner_unwind_cancels_both_jobs_before_join_and_native_drop() {
    use super::super::windows_namespace_dispatcher::CreateKind;
    struct Running {
        kind: CreateKind,
        cancelled: Arc<AtomicBool>,
        started: mpsc::Sender<()>,
        completed: Arc<AtomicBool>,
    }
    fn execute(task: Running) -> CreateKind {
        task.started.send(()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !task.cancelled.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
            thread::yield_now();
        }
        task.completed
            .store(task.cancelled.load(Ordering::Acquire), Ordering::Release);
        task.kind
    }
    struct NativeCustody {
        completed: [Arc<AtomicBool>; 2],
        dropped_after_join: Arc<AtomicBool>,
    }
    impl Drop for NativeCustody {
        fn drop(&mut self) {
            self.dropped_after_join.store(
                self.completed
                    .iter()
                    .all(|done| done.load(Ordering::Acquire)),
                Ordering::Release,
            );
        }
    }
    let completed = [
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
    ];
    let dropped_after_join = Arc::new(AtomicBool::new(false));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _native = NativeCustody {
            completed: completed.clone(),
            dropped_after_join: dropped_after_join.clone(),
        };
        let mut workers = Executor::start(execute).unwrap();
        let cancelled = [
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        ];
        let cancel = cancelled.clone();
        let _owner = CancelOnDrop::new(Arc::new(move || {
            for job in &cancel {
                job.store(true, Ordering::Release);
            }
        }));
        for (index, kind) in [CreateKind::File, CreateKind::Directory]
            .into_iter()
            .enumerate()
        {
            let (start, ready) = mpsc::channel();
            workers
                .submit(Running {
                    kind,
                    cancelled: cancelled[index].clone(),
                    started: start,
                    completed: completed[index].clone(),
                })
                .ok()
                .unwrap();
            ready.recv_timeout(Duration::from_secs(2)).unwrap();
        }
        panic!("owned mixed lifecycle test panic");
    }));
    assert!(result.is_err());
    assert!(dropped_after_join.load(Ordering::Acquire));
    assert!(completed.iter().all(|done| done.load(Ordering::Acquire)));
}
