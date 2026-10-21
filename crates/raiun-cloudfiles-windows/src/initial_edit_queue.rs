//! Bounded fresh-close handoff. Only opaque receipts are queued, never bodies
//! or recovered journal scans. A dropped/full queue leaves durable edits intact.

#[cfg(any(windows, test))]
use crate::BackendError;
use crate::{
    ConfiguredRootIdentity, EditJournalScope, InitialEditReceipt, JournalError,
    PreparedEditRecovery, ProviderScope, ReconciliationOutcome, RecoveryRemote,
};
use std::sync::Arc;
#[cfg(any(windows, test))]
use std::{collections::VecDeque, sync::Mutex};

pub const MAX_PENDING_INITIAL_EDITS: usize = 16;

/// One fresh append and the exact prepared instance that published it. No
/// serialization or cloning is available; dispatch consumes the handoff.
pub struct PendingInitialEdit {
    recovery: Arc<dyn PreparedEditRecovery>,
    receipt: InitialEditReceipt,
}

impl PendingInitialEdit {
    /// Trusted routing metadata; do not display or log account values.
    pub fn scope(&self) -> &EditJournalScope {
        self.receipt.scope()
    }

    pub fn matches_provider(&self, scope: &ProviderScope, root: ConfiguredRootIdentity) -> bool {
        self.recovery.provider_scope() == scope && self.recovery.root_identity() == root
    }

    /// Caller must retain the current account/root lease and generation-checked
    /// remote throughout this invocation. Failures retain the durable body.
    pub fn dispatch(
        self,
        remote: &dyn RecoveryRemote,
    ) -> Result<ReconciliationOutcome, JournalError> {
        self.recovery.dispatch_initial_receipt(self.receipt, remote)
    }
}

#[cfg(any(windows, test))]
#[derive(Default)]
pub(crate) struct InitialEditQueue {
    pending: Mutex<VecDeque<PendingInitialEdit>>,
}

#[cfg(any(windows, test))]
impl InitialEditQueue {
    pub(crate) fn push(
        &self,
        recovery: Arc<dyn PreparedEditRecovery>,
        receipt: InitialEditReceipt,
    ) -> Result<(), BackendError> {
        let mut pending = self
            .pending
            .try_lock()
            .map_err(|_| BackendError::Unavailable)?;
        if pending.len() >= MAX_PENDING_INITIAL_EDITS {
            return Err(BackendError::Unavailable);
        }
        pending.push_back(PendingInitialEdit { recovery, receipt });
        Ok(())
    }

    pub(crate) fn take(&self) -> Result<Option<PendingInitialEdit>, BackendError> {
        Ok(self
            .pending
            .lock()
            .map_err(|_| BackendError::Unavailable)?
            .pop_front())
    }
}

#[cfg(test)]
#[path = "initial_edit_queue_tests.rs"]
mod tests;
