use super::*;
use futures_util::task::noop_waker;
use sha2::{Digest, Sha256};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};
use tokio::io::AsyncReadExt;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}
struct Generated {
    forbidden: thread::ThreadId,
    remaining: u64,
    calls: Arc<AtomicUsize>,
    max: Arc<AtomicUsize>,
}
impl Read for Generated {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        assert_ne!(thread::current().id(), self.forbidden);
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.max.fetch_max(out.len(), Ordering::Relaxed);
        let n = self.remaining.min(out.len() as u64) as usize;
        out[..n].fill(b'x');
        self.remaining -= n as u64;
        Ok(n)
    }
}
#[test]
fn generated_large_digest_eof_and_join_with_bounded_source_reads() {
    let length = 17 * 1024 * 1024 + 7;
    let calls = Arc::new(AtomicUsize::new(0));
    let max = Arc::new(AtomicUsize::new(0));
    let (mut guard, mut reader) = start(Generated {
        forbidden: thread::current().id(),
        remaining: length,
        calls: calls.clone(),
        max: max.clone(),
    })
    .unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    let mut total = 0;
    let mut hash = Sha256::new();
    runtime().block_on(async {
        let mut bytes = [0; 8191];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(3), reader.read(&mut bytes))
                .await
                .unwrap()
                .unwrap();
            if n == 0 {
                break;
            }
            hash.update(&bytes[..n]);
            total += n as u64;
        }
    });
    assert_eq!(total, length);
    let mut expected = Sha256::new();
    let mut left = length;
    while left > 0 {
        let n = left.min(CHUNK_BYTES as u64) as usize;
        expected.update(&[b'x'; CHUNK_BYTES][..n]);
        left -= n as u64;
    }
    assert_eq!(hash.finalize(), expected.finalize());
    assert!(max.load(Ordering::Relaxed) <= CHUNK_BYTES);
    assert_eq!(guard.cancel_and_join(), WorkerCompletion::Eof);
    assert_eq!(guard.cancel_and_join(), WorkerCompletion::Eof);
}
#[test]
fn tiny_buffers_do_not_read_ahead_and_empty_buffers_do_not_request() {
    let calls = Arc::new(AtomicUsize::new(0));
    let (mut guard, mut reader) = start(Generated {
        forbidden: thread::current().id(),
        remaining: CHUNK_BYTES as u64 * 2,
        calls: calls.clone(),
        max: Arc::new(AtomicUsize::new(0)),
    })
    .unwrap();
    runtime().block_on(async {
        assert_eq!(reader.read(&mut []).await.unwrap(), 0);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        let mut byte = [0];
        assert_eq!(reader.read(&mut byte).await.unwrap(), 1);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        for _ in 1..CHUNK_BYTES {
            assert_eq!(reader.read(&mut byte).await.unwrap(), 1);
            assert_eq!(byte[0], b'x');
        }
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        {
            let state = reader.shared.lock();
            assert!(state.response.is_none());
            assert!(!state.reading);
            assert!(!state.requested);
        }
        assert_eq!(reader.read(&mut byte).await.unwrap(), 1);
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    });
    assert_eq!(guard.cancel_and_join(), WorkerCompletion::Cancelled);
}
#[derive(Clone, Copy)]
enum Fault {
    Interrupted,
    Error,
    Panic,
}
struct Faulty {
    fault: Fault,
    calls: usize,
}
impl Read for Faulty {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.calls += 1;
        match self.fault {
            Fault::Interrupted if self.calls <= 3 => Err(io::ErrorKind::Interrupted.into()),
            Fault::Interrupted if self.calls == 4 => {
                out[0] = b'x';
                Ok(1)
            }
            Fault::Interrupted => Ok(0),
            Fault::Error => Err(io::Error::other("synthetic secret local path")),
            Fault::Panic => panic!("synthetic reader panic"),
        }
    }
}
#[test]
fn interrupted_source_reads_retry_but_error_and_panic_are_sticky() {
    let (mut guard, mut reader) = start(Faulty {
        fault: Fault::Interrupted,
        calls: 0,
    })
    .unwrap();
    runtime().block_on(async {
        let mut bytes = [0];
        assert_eq!(reader.read(&mut bytes).await.unwrap(), 1);
        assert_eq!(bytes, [b'x']);
        assert_eq!(reader.read(&mut bytes).await.unwrap(), 0);
    });
    assert_eq!(guard.cancel_and_join(), WorkerCompletion::Eof);
    for (fault, completion) in [
        (Fault::Error, WorkerCompletion::SourceError),
        (Fault::Panic, WorkerCompletion::Panicked),
    ] {
        let (mut guard, mut reader) = start(Faulty { fault, calls: 0 }).unwrap();
        runtime().block_on(async {
            let mut bytes = [0];
            for _ in 0..3 {
                let error = tokio::time::timeout(Duration::from_secs(3), reader.read(&mut bytes))
                    .await
                    .unwrap()
                    .unwrap_err();
                assert!(!error.to_string().contains("secret"));
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            }
            assert!(reader.read(&mut []).await.is_err());
        });
        assert_eq!(guard.cancel_and_join(), completion);
    }
}
struct Blocked {
    entered: mpsc::Sender<()>,
    release: Arc<(Mutex<bool>, Condvar)>,
    dropped: Arc<AtomicUsize>,
}
impl Read for Blocked {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.entered.send(()).unwrap();
        let (lock, cv) = &*self.release;
        let mut release = lock.lock().unwrap();
        while !*release {
            release = cv.wait(release).unwrap();
        }
        out[0] = b'x';
        Ok(1)
    }
}
impl Drop for Blocked {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Release);
    }
}
type BlockedFixture = (
    WorkerGuard,
    AsyncReader,
    mpsc::Receiver<()>,
    Arc<(Mutex<bool>, Condvar)>,
    Arc<AtomicUsize>,
);
fn block_fixture() -> BlockedFixture {
    let (entered, seen) = mpsc::channel();
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let dropped = Arc::new(AtomicUsize::new(0));
    let (guard, reader) = start(Blocked {
        entered,
        release: release.clone(),
        dropped: dropped.clone(),
    })
    .unwrap();
    (guard, reader, seen, release, dropped)
}
fn request(reader: &mut AsyncReader) {
    let waker = noop_waker();
    let mut context = Context::from_waker(&waker);
    let mut bytes = [0];
    assert!(
        Pin::new(reader)
            .poll_read(&mut context, &mut ReadBuf::new(&mut bytes))
            .is_pending()
    );
}
#[test]
fn adapter_drop_and_guard_join_retain_source_until_blocked_read_drains() {
    let (mut guard, mut reader, entered, release, dropped) = block_fixture();
    request(&mut reader);
    entered.recv_timeout(Duration::from_secs(3)).unwrap();
    drop(reader);
    assert_eq!(dropped.load(Ordering::Acquire), 0);
    let (done_tx, done_rx) = mpsc::channel();
    let joiner = thread::spawn(move || {
        let result = guard.cancel_and_join();
        done_tx.send(result).unwrap();
    });
    assert!(done_rx.recv_timeout(Duration::from_millis(30)).is_err());
    assert_eq!(dropped.load(Ordering::Acquire), 0);
    {
        let (lock, cv) = &*release;
        *lock.lock().unwrap() = true;
        cv.notify_all();
    }
    assert_eq!(
        done_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
        WorkerCompletion::Cancelled
    );
    joiner.join().unwrap();
    assert_eq!(dropped.load(Ordering::Acquire), 1);
}
#[test]
fn guard_drop_cancels_pending_wait_and_sticky_adapter_failure() {
    let (guard, mut reader) = start(io::empty()).unwrap();
    drop(guard);
    runtime().block_on(async {
        let mut byte = [0];
        for _ in 0..3 {
            assert_eq!(
                reader.read(&mut byte).await.unwrap_err().kind(),
                io::ErrorKind::ConnectionAborted
            );
        }
    });
}

struct Held<R> {
    source: R,
    dropped: Arc<AtomicUsize>,
}
impl<R: Read> Read for Held<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.source.read(out)
    }
}
impl<R> Drop for Held<R> {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::Release);
    }
}
#[test]
fn eof_error_panic_and_adapter_cancel_retain_pin_until_owner_join() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let (mut guard, mut reader) = start(Held {
        source: io::Cursor::new(b"x"),
        dropped: dropped.clone(),
    })
    .unwrap();
    runtime().block_on(async {
        let mut out = [0];
        assert_eq!(reader.read(&mut out).await.unwrap(), 1);
        assert_eq!(reader.read(&mut out).await.unwrap(), 0);
    });
    assert_eq!(dropped.load(Ordering::Acquire), 0);
    drop(reader);
    assert_eq!(dropped.load(Ordering::Acquire), 0);
    assert_eq!(guard.cancel_and_join(), WorkerCompletion::Eof);
    assert_eq!(dropped.load(Ordering::Acquire), 1);
    for (fault, completion) in [
        (Fault::Error, WorkerCompletion::SourceError),
        (Fault::Panic, WorkerCompletion::Panicked),
    ] {
        let dropped = Arc::new(AtomicUsize::new(0));
        let (mut guard, mut reader) = start(Held {
            source: Faulty { fault, calls: 0 },
            dropped: dropped.clone(),
        })
        .unwrap();
        runtime().block_on(async {
            let mut out = [0];
            assert!(reader.read(&mut out).await.is_err());
        });
        assert_eq!(dropped.load(Ordering::Acquire), 0);
        drop(reader);
        assert_eq!(dropped.load(Ordering::Acquire), 0);
        assert_eq!(guard.cancel_and_join(), completion);
        assert_eq!(dropped.load(Ordering::Acquire), 1);
    }
    let dropped = Arc::new(AtomicUsize::new(0));
    let (mut guard, reader) = start(Held {
        source: io::empty(),
        dropped: dropped.clone(),
    })
    .unwrap();
    drop(reader);
    assert_eq!(dropped.load(Ordering::Acquire), 0);
    assert_eq!(guard.cancel_and_join(), WorkerCompletion::Cancelled);
    assert_eq!(dropped.load(Ordering::Acquire), 1);
}

struct DropPanic;
impl Read for DropPanic {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}
impl Drop for DropPanic {
    fn drop(&mut self) {
        panic!("synthetic source destructor panic");
    }
}
#[test]
fn destructor_panic_during_owner_shutdown_invalidates_eof_completion() {
    let (mut guard, mut reader) = start(DropPanic).unwrap();
    runtime().block_on(async {
        let mut out = [0];
        assert_eq!(reader.read(&mut out).await.unwrap(), 0);
    });
    assert_eq!(guard.cancel_and_join(), WorkerCompletion::Panicked);
    assert_eq!(guard.cancel_and_join(), WorkerCompletion::Panicked);
}
