//! Scheduling only: coordinate live fresh-file conditional PUTs that share
//! a Space/root revision. This provides no credential or mutation authority.
use crate::BackendError;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

const FREE: u8 = 0;
const HELD: u8 = 1;
const CLOSED: u8 = 2;

#[derive(Default)]
pub(crate) struct Gates {
    // The enclosing backend already binds the original account/origin. Weak
    // entries retain no historical gate; live entries are bounded by original
    // in-flight native create tasks, not by the number of past Spaces.
    entries: Mutex<HashMap<(String, String), Weak<AtomicU8>>>,
}
impl Gates {
    pub(crate) fn acquire(
        &self,
        space: &str,
        root: &str,
        mut check: impl FnMut() -> Result<(), BackendError>,
    ) -> Result<SendPermit, BackendError> {
        check()?;
        if space.is_empty() || root.is_empty() {
            return Err(BackendError::Unavailable);
        }
        let gate = {
            let mut entries = self.entries.lock().map_err(|_| BackendError::Unavailable)?;
            entries.retain(|_, gate| gate.strong_count() != 0);
            let key = (space.to_owned(), root.to_owned());
            match entries.get(&key).and_then(Weak::upgrade) {
                Some(gate) => gate,
                None => {
                    let gate = Arc::new(AtomicU8::new(FREE));
                    entries.insert(key, Arc::downgrade(&gate));
                    gate
                }
            }
        };
        loop {
            // The caller retains the SAME original job, cancellation, current
            // owner and deadline. Waiting creates no new timeout or SDK task.
            check()?;
            match gate.compare_exchange(FREE, HELD, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => {
                    let permit = SendPermit { gate: Some(gate) };
                    check()?;
                    return Ok(permit);
                }
                Err(HELD) => std::thread::sleep(Duration::from_millis(10)),
                _ => return Err(BackendError::Unavailable),
            }
        }
    }
}

/// Move-only, Sendable scheduling owner. It is not a verified cloud receipt.
pub(crate) struct SendPermit {
    gate: Option<Arc<AtomicU8>>,
}
impl SendPermit {
    /// Only the SDK's strict body-consumed + checked CREATED hook calls this.
    /// Postflight hash/readback and native/journal verification are still due.
    pub(crate) fn accepted(mut self) {
        if let Some(gate) = self.gate.take() {
            gate.store(FREE, Ordering::Release);
        }
    }
}
impl Drop for SendPermit {
    fn drop(&mut self) {
        if let Some(gate) = self.gate.take() {
            // Refusal/cancellation/panic before acceptance stops waiting peers.
            // Nothing is retried, and all original captures remain protected.
            gate.store(CLOSED, Ordering::Release);
        }
    }
}
