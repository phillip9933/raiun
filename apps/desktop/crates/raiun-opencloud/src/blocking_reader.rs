//! Demand-driven bridge for protected synchronous readers. This module supplies
//! no snapshot, remote verification, or native acknowledgement authority.
//!
//! Keep WorkerGuard on the synchronous caller side. After transport returns,
//! cancel_and_join must report Eof before accepting its result. Both explicit
//! shutdown and Drop join the source worker; they can block indefinitely if an
//! underlying synchronous source read never returns. There is no detached worker
//! or forced termination. Terminal EOF/error/cancellation and adapter Drop keep
//! the source/pin held until the guard requests owner shutdown and joins.
//!
//! Caught panics produce sanitized adapter errors. Rust's process-wide panic
//! hook still executes before catch_unwind; this module does not replace hooks.
use futures_util::task::AtomicWaker;
use std::{
    io::{self, Read},
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    sync::{Arc, Condvar, Mutex, MutexGuard},
    task::{Context, Poll},
    thread::{self, JoinHandle},
};
use tokio::io::{AsyncRead, ReadBuf};
use zeroize::{Zeroize, Zeroizing};

const CHUNK_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkerCompletion {
    Eof,
    SourceError,
    Panicked,
    Cancelled,
}

#[derive(Default)]
struct State {
    requested: bool,
    reading: bool,
    response: Option<Zeroizing<Vec<u8>>>,
    cancelled: bool,
    owner_stop: bool,
    completion: Option<WorkerCompletion>,
}
struct Shared {
    state: Mutex<State>,
    demand: Condvar,
    consumer: AtomicWaker,
}
impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }
    fn stop_owner(&self) {
        {
            let mut state = self.lock();
            state.owner_stop = true;
            state.cancelled = true;
        }
        self.demand.notify_all();
        self.consumer.wake();
    }
    fn cancel(&self) {
        self.lock().cancelled = true;
        self.demand.notify_all();
        self.consumer.wake();
    }
}

/// The source worker and its pin must be joined on the synchronous caller side.
pub(crate) struct WorkerGuard {
    shared: Arc<Shared>,
    worker: Option<JoinHandle<()>>,
}
impl WorkerGuard {
    /// Cancel pending demand and join. Eof means the worker actually read EOF,
    /// exited, and released its source; it is not independent transport proof.
    pub(crate) fn cancel_and_join(&mut self) -> WorkerCompletion {
        self.shared.stop_owner();
        if let Some(worker) = self.worker.take()
            && worker.join().is_err()
        {
            let mut state = self.shared.lock();
            state.response = None;
            state.completion = Some(WorkerCompletion::Panicked);
        }
        self.shared
            .lock()
            .completion
            .unwrap_or(WorkerCompletion::Panicked)
    }
}
impl Drop for WorkerGuard {
    fn drop(&mut self) {
        self.cancel_and_join();
    }
}

pub(crate) struct AsyncReader {
    shared: Arc<Shared>,
    buffered: Option<Zeroizing<Vec<u8>>>,
    offset: usize,
    failure: Option<WorkerCompletion>,
    eof: bool,
}
impl Drop for AsyncReader {
    fn drop(&mut self) {
        self.shared.cancel();
    }
}

pub(crate) fn start<R: Read + Send + 'static>(reader: R) -> io::Result<(WorkerGuard, AsyncReader)> {
    let shared = Arc::new(Shared {
        state: Mutex::new(State::default()),
        demand: Condvar::new(),
        consumer: AtomicWaker::new(),
    });
    let worker_shared = Arc::clone(&shared);
    let worker = thread::Builder::new()
        .name("raiun-protected-reader".into())
        .spawn(move || {
            let mut reader = reader;
            let result = catch_unwind(AssertUnwindSafe(|| produce(&mut reader, &worker_shared)))
                .unwrap_or(WorkerCompletion::Panicked);
            {
                let mut state = worker_shared.lock();
                state.reading = false;
                state.requested = false;
                state.response = None;
                state.completion = Some(result);
            }
            worker_shared.consumer.wake();
            // Terminal I/O is visible to the consumer before joining. Retain
            // the same source/pin through later remote readback until its
            // synchronous owner explicitly shuts down, even after adapter Drop.
            let mut state = worker_shared.lock();
            while !state.owner_stop {
                state = worker_shared
                    .demand
                    .wait(state)
                    .unwrap_or_else(|p| p.into_inner());
            }
            drop(state);
            drop(reader);
        })
        .map_err(|_| io::Error::other("protected reader worker could not start"))?;
    Ok((
        WorkerGuard {
            shared: Arc::clone(&shared),
            worker: Some(worker),
        },
        AsyncReader {
            shared,
            buffered: None,
            offset: 0,
            failure: None,
            eof: false,
        },
    ))
}

fn produce<R: Read>(reader: &mut R, shared: &Shared) -> WorkerCompletion {
    loop {
        {
            let mut state = shared.lock();
            while !state.requested && !state.cancelled {
                state = shared.demand.wait(state).unwrap_or_else(|p| p.into_inner());
            }
            if state.cancelled {
                return WorkerCompletion::Cancelled;
            }
            state.requested = false;
            state.reading = true;
        }
        let mut bytes = Zeroizing::new(vec![0; CHUNK_BYTES]);
        let count = loop {
            if shared.lock().cancelled {
                return WorkerCompletion::Cancelled;
            }
            match reader.read(&mut bytes) {
                Ok(count) if count <= bytes.len() => break count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Ok(_) | Err(_) => return WorkerCompletion::SourceError,
            }
        };
        {
            let mut state = shared.lock();
            if state.cancelled {
                return WorkerCompletion::Cancelled;
            }
            if count == 0 {
                return WorkerCompletion::Eof;
            }
            bytes[count..].zeroize();
            bytes.truncate(count);
            state.reading = false;
            state.response = Some(bytes);
        }
        shared.consumer.wake();
    }
}

fn adapter_error(failure: WorkerCompletion) -> io::Error {
    io::Error::new(
        if failure == WorkerCompletion::Cancelled {
            io::ErrorKind::ConnectionAborted
        } else {
            io::ErrorKind::InvalidData
        },
        "protected reader worker failed",
    )
}
impl AsyncReader {
    fn fail(&mut self, failure: WorkerCompletion) -> Poll<io::Result<()>> {
        self.failure = Some(failure);
        self.buffered = None;
        Poll::Ready(Err(adapter_error(failure)))
    }
}
impl AsyncRead for AsyncReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(failure) = self.failure {
            return Poll::Ready(Err(adapter_error(failure)));
        }
        // Register before inspecting shared state: a producer that wins either
        // side of the lock/release race cannot leave this task asleep forever.
        self.shared.consumer.register(cx.waker());
        let shared = Arc::clone(&self.shared);
        let mut state = shared.lock();
        if state.cancelled {
            drop(state);
            return self.fail(WorkerCompletion::Cancelled);
        }
        if let Some(completion) = state.completion {
            if completion != WorkerCompletion::Eof {
                drop(state);
                return self.fail(completion);
            }
            self.eof = true;
        }
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.buffered.is_none() {
            self.buffered = state.response.take();
            self.offset = 0;
        }
        if self.buffered.is_none() {
            if self.eof {
                return Poll::Ready(Ok(()));
            }
            if !state.requested && !state.reading {
                state.requested = true;
                shared.demand.notify_one();
            }
            return Poll::Pending;
        }
        drop(state);
        let offset = self.offset;
        let bytes = self.buffered.as_mut().expect("buffered response");
        let count = output.remaining().min(bytes.len() - offset);
        output.put_slice(&bytes[offset..offset + count]);
        bytes[offset..offset + count].zeroize();
        let exhausted = offset + count == bytes.len();
        self.offset += count;
        if exhausted {
            self.buffered = None;
            self.offset = 0;
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
#[path = "blocking_reader_tests.rs"]
mod tests;
