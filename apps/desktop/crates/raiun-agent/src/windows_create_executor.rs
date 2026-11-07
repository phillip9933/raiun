//! Four joined SDK workers. Undrained results retain their bounded capacity slot.
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread::{self, JoinHandle};
/// Owner-local unwind guard. Production callback only cancels an original job.
pub(crate) struct CancelOnDrop(Arc<dyn Fn() + Send + Sync>);
impl CancelOnDrop {
    pub(crate) fn new(cancel: Arc<dyn Fn() + Send + Sync>) -> Self {
        Self(cancel)
    }
}
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        (self.0)();
    }
}

pub(crate) const WORKERS: usize = 4;
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Failure {
    Cancelled,
    Panicked,
}
pub(crate) struct Completion<R> {
    pub(crate) id: u64,
    pub(crate) result: Result<R, Failure>,
}
#[derive(Clone, serde::Serialize)]
pub(crate) struct ExecutorActivity {
    pub(crate) outstanding: usize,
    pub(crate) collected_ready: usize,
    pub(crate) uncollected_or_running: Option<usize>,
}
pub(crate) struct Executor<T: Send + 'static, R: Send + 'static> {
    sender: Option<mpsc::SyncSender<(u64, T)>>,
    results: mpsc::Receiver<Completion<R>>,
    workers: Vec<JoinHandle<()>>,
    accepting: Arc<AtomicBool>,
    outstanding: Vec<u64>,
    ready: Vec<Completion<R>>,
    next: u64,
}
impl<T: Send + 'static, R: Send + 'static> Executor<T, R> {
    /// Last owner-collected state only. Never poll or consume a completion.
    pub(crate) fn activity_snapshot(&self) -> ExecutorActivity {
        ExecutorActivity {
            outstanding: self.outstanding.len(),
            collected_ready: self.ready.len(),
            uncollected_or_running: self.outstanding.len().checked_sub(self.ready.len()),
        }
    }

    pub(crate) fn start(execute: fn(T) -> R) -> Result<Self, std::io::Error> {
        let (sender, receiver) = mpsc::sync_channel::<(u64, T)>(WORKERS);
        let receiver = Arc::new(Mutex::new(receiver));
        let (results, result_receiver) = mpsc::channel();
        let accepting = Arc::new(AtomicBool::new(true));
        let mut workers = Vec::new();
        for index in 0..WORKERS {
            let input = receiver.clone();
            let output = results.clone();
            let open = accepting.clone();
            match thread::Builder::new()
                .name(format!("raiun-create-sdk-{index}"))
                .spawn(move || {
                    loop {
                        let task = match input.lock() {
                            Ok(input) => input.recv(),
                            Err(_) => return,
                        };
                        let Ok((id, task)) = task else { return };
                        let result = if open.load(Ordering::Acquire) {
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| execute(task)))
                                .map_err(|_| Failure::Panicked)
                        } else {
                            drop(task);
                            Err(Failure::Cancelled)
                        };
                        if output.send(Completion { id, result }).is_err() {
                            return;
                        }
                    }
                }) {
                Ok(worker) => workers.push(worker),
                Err(error) => {
                    accepting.store(false, Ordering::Release);
                    drop(sender);
                    for worker in workers {
                        let _ = worker.join();
                    }
                    return Err(error);
                }
            }
        }
        Ok(Self {
            sender: Some(sender),
            results: result_receiver,
            workers,
            accepting,
            outstanding: Vec::new(),
            ready: Vec::new(),
            next: 0,
        })
    }
    /// Backpressure retains the original unexecuted task with its original deadline.
    pub(crate) fn submit(&mut self, task: T) -> Result<u64, T> {
        if !self.accepting.load(Ordering::Acquire) || self.outstanding.len() == WORKERS {
            return Err(task);
        }
        let Some(id) = self.next.checked_add(1) else {
            return Err(task);
        };
        let Some(sender) = self.sender.as_ref() else {
            return Err(task);
        };
        match sender.try_send((id, task)) {
            Ok(()) => {
                self.next = id;
                self.outstanding.push(id);
                Ok(id)
            }
            Err(
                mpsc::TrySendError::Full((_, task)) | mpsc::TrySendError::Disconnected((_, task)),
            ) => Err(task),
        }
    }
    fn collect(&mut self) {
        while let Ok(result) = self.results.try_recv() {
            self.ready.push(result);
        }
    }
    /// A wave's metadata phases finish before any native capture is advanced.
    /// Buffered replies retain capacity until their exact owner consumes them.
    pub(crate) fn all_completed(&mut self) -> bool {
        self.collect();
        self.ready.len() == self.outstanding.len()
    }
    /// Scheduling observation only. Every outstanding task must have an actual
    /// collected reply unless its exact accepted ID is explicitly exempted.
    /// No reply is consumed and no outstanding capacity is released here.
    pub(crate) fn all_completed_except(&mut self, exempt: &[u64]) -> bool {
        self.collect();
        self.outstanding.iter().all(|id| {
            exempt.contains(id) || self.ready.iter().any(|completion| completion.id == *id)
        })
    }
    pub(crate) fn poll_for(&mut self, id: u64) -> Option<Completion<R>> {
        self.collect();
        let index = self.ready.iter().position(|result| result.id == id)?;
        let result = self.ready.remove(index);
        self.outstanding.retain(|value| *value != result.id);
        Some(result)
    }
    pub(crate) fn poll(&mut self) -> Option<Completion<R>> {
        self.collect();
        let result = self.ready.pop()?;
        self.outstanding.retain(|id| *id != result.id);
        Some(result)
    }
    pub(crate) fn stop_and_join(&mut self) {
        self.accepting.store(false, Ordering::Release);
        self.sender.take();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
        while self.poll().is_some() {}
    }
}
impl<T: Send + 'static, R: Send + 'static> Drop for Executor<T, R> {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}
#[cfg(test)]
#[path = "windows_create_executor_tests.rs"]
mod tests;
