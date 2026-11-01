//! One attempt's local close-capture ordering, never remote/native authority.
use crate::close_capture_admission::SaveRenameTicket;
use crate::namespace_file_rename::{
    FileRenameCompletionError, FileRenameDispatch, FileRenameLocal, FileRenameObservation,
    FileRenameReadback, FileRenameRemote, FileRenameSend,
};
use crate::namespace_intent::NamespaceIntent;
use crate::streamed_store::StoreError;
use raiun_core::backend::{CloudError, ErrorKind};
use std::cell::{Cell, RefCell};

pub(crate) struct SaveRenameAdmission<'a> {
    ticket: RefCell<SaveRenameTicket<'a>>,
}

fn deferred() -> CloudError {
    CloudError::new(
        ErrorKind::Offline,
        "local close capture changed rename admission",
    )
}

impl<'a> SaveRenameAdmission<'a> {
    pub(crate) fn new(ticket: SaveRenameTicket<'a>) -> Self {
        Self {
            ticket: RefCell::new(ticket),
        }
    }

    pub(crate) fn check(&self) -> Result<(), CloudError> {
        if self
            .ticket
            .try_borrow()
            .is_ok_and(|ticket| ticket.is_current())
        {
            Ok(())
        } else {
            Err(deferred())
        }
    }

    /// Owner-thread only. The supplied bounded health read must be outside a
    /// backend lease, HTTP and callbacks; no tracker borrow survives the read.
    pub(crate) fn probe_clean<E>(&self, probe: impl FnOnce() -> Result<bool, E>) -> bool {
        self.check().is_ok() && matches!(probe(), Ok(false)) && self.check().is_ok()
    }

    pub(crate) fn claim_send(&self) -> Result<(), CloudError> {
        if self
            .ticket
            .try_borrow_mut()
            .is_ok_and(|mut ticket| ticket.claim_dispatch())
        {
            Ok(())
        } else {
            Err(deferred())
        }
    }

    fn claim_completion(&self) -> Result<(), StoreError> {
        if self
            .ticket
            .try_borrow_mut()
            .is_ok_and(|mut ticket| ticket.claim_completion())
        {
            Ok(())
        } else {
            Err(StoreError::Busy)
        }
    }
}

pub(crate) struct GuardedRemote<'a, 'ticket> {
    pub(crate) remote: &'a dyn FileRenameRemote,
    pub(crate) admission: &'a SaveRenameAdmission<'ticket>,
}

impl FileRenameRemote for GuardedRemote<'_, '_> {
    fn ensure_authorized(&self, intent: &NamespaceIntent) -> Result<(), CloudError> {
        self.admission.check()?;
        self.remote.ensure_authorized(intent)?;
        self.admission.check()
    }
    fn preflight(&self, intent: &NamespaceIntent) -> Result<(), CloudError> {
        self.admission.check()?;
        self.remote.preflight(intent)?;
        self.admission.check()
    }
    fn rename(&self, dispatch: &FileRenameDispatch<'_>) -> Result<FileRenameSend, CloudError> {
        self.admission.check()?;
        // The live adapter alone knows the final SDK send point. No tracker
        // borrow or mutex is held while its remote proofs or request run.
        let result = self
            .remote
            .rename_with_send_guard(dispatch, &mut || self.admission.claim_send());
        if result.is_ok() && self.admission.check().is_err() {
            return Ok(FileRenameSend::Uncertain);
        }
        result
    }
    fn observe(&self, intent: &NamespaceIntent) -> Result<FileRenameObservation, CloudError> {
        self.admission.check()?;
        let result = self.remote.observe(intent)?;
        self.admission.check()?;
        Ok(result)
    }
}

pub(crate) struct GuardedLocal<'a, 'ticket, L: FileRenameLocal + ?Sized> {
    pub(crate) local: &'a mut L,
    pub(crate) admission: &'a SaveRenameAdmission<'ticket>,
}

impl<L: FileRenameLocal + ?Sized> FileRenameLocal for GuardedLocal<'_, '_, L> {
    fn admit(&mut self, intent: &NamespaceIntent) -> Result<(), CloudError> {
        self.admission.check()?;
        self.local.admit(intent)?;
        self.admission.check()
    }
    fn record_completion<F>(
        &mut self,
        intent: &NamespaceIntent,
        readback: &FileRenameReadback,
        record: F,
    ) -> Result<(), FileRenameCompletionError>
    where
        F: FnOnce() -> Result<(), StoreError>,
    {
        self.admission
            .check()
            .map_err(|_| FileRenameCompletionError::Unavailable)?;
        let refused = Cell::new(false);
        let result = self.local.record_completion(intent, readback, || {
            // The short claim orders this commit before subsequently starting
            // closes. Capture remains enabled; no mutex spans journal I/O.
            // Once granted, do not undo a factual append because of later work.
            #[cfg(all(windows, debug_assertions, feature = "synthetic-agent-integration"))]
            completion_fixture::run(intent);
            if self.admission.claim_completion().is_err() {
                refused.set(true);
                return Err(StoreError::Busy);
            }
            record()
        });
        if refused.get() {
            // The real journal callback was never invoked. Retain the existing
            // RemoteVerified prefix; do not label local admission as disk Busy.
            Err(FileRenameCompletionError::Unavailable)
        } else {
            result
        }
    }
}

#[cfg(test)]
#[path = "save_rename_admission_tests.rs"]
mod tests;

/// Diagnostic ordering only. Exact semantic operation and generation include
/// original scope/account/authorization/physical root. Publication replaces the
/// caller's record ID; the barrier receives that factual live intent and must
/// authenticate it against the retained store before acting. No capability.
#[cfg(all(windows, debug_assertions, feature = "synthetic-agent-integration"))]
pub(crate) mod completion_fixture {
    use super::*;
    use std::{marker::PhantomData, rc::Rc};
    type Barrier = Box<dyn FnOnce(&NamespaceIntent)>;
    struct Armed {
        id: u64,
        expected: NamespaceIntent,
        barrier: Barrier,
    }
    thread_local! {
        static ARMED: RefCell<Option<Armed>> = const { RefCell::new(None) };
    }
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    pub struct Guard {
        id: u64,
        _owner_thread: PhantomData<Rc<()>>,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            ARMED.with(|slot| {
                let mut slot = slot.borrow_mut();
                if slot.as_ref().is_some_and(|armed| armed.id == self.id) {
                    slot.take();
                }
            });
        }
    }
    pub fn arm(
        expected: NamespaceIntent,
        barrier: impl FnOnce(&NamespaceIntent) + 'static,
    ) -> Result<Guard, crate::Error> {
        expected
            .validate()
            .map_err(|_| crate::Error::EditRecoveryUnavailable)?;
        let mut id = NEXT.load(std::sync::atomic::Ordering::Relaxed);
        loop {
            let next = id
                .checked_add(1)
                .ok_or(crate::Error::EditRecoveryUnavailable)?;
            match NEXT.compare_exchange_weak(
                id,
                next,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => id = actual,
            }
        }
        ARMED.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.is_some() {
                return Err(crate::Error::EditRecoveryUnavailable);
            }
            *slot = Some(Armed {
                id,
                expected,
                barrier: Box::new(barrier),
            });
            Ok(Guard {
                id,
                _owner_thread: PhantomData,
            })
        })
    }
    pub(super) fn run(intent: &NamespaceIntent) {
        let armed = ARMED.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.as_ref().is_some_and(|armed| {
                armed.expected.schema_version == intent.schema_version
                    && armed.expected.record_generation == intent.record_generation
                    && armed.expected.operation == intent.operation
            }) {
                slot.take()
            } else {
                None
            }
        });
        if let Some(armed) = armed {
            (armed.barrier)(intent);
        }
    }
}
