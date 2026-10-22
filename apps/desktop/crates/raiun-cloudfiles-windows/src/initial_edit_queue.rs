//! Bounded fresh-close handoff. Only opaque receipts are queued, never bodies
//! or recovered journal scans. A dropped/full queue leaves durable edits intact.

#[cfg(any(windows, test))]
use crate::BackendError;
use crate::{
    ConfiguredRootIdentity, EditJournalScope, InitialEditReceipt, JournalError, LocalFileIdentity,
    PreparedEditRecovery, ProviderScope, ReconciliationOutcome, RecoveryRemote,
    VerifiedEditReadback,
};
use std::sync::Arc;
#[cfg(any(windows, test))]
use std::{collections::VecDeque, sync::Mutex};

pub const MAX_PENDING_INITIAL_EDITS: usize = 16;

/// Captured local callback location, never derived from a remote object path.
/// Non-cloneable, nonserializable, and not acknowledgement authority.
pub struct InitialEditLocation {
    components: Vec<String>,
    identity: [u8; 16],
    root: ConfiguredRootIdentity,
    local_file: LocalFileIdentity,
    #[cfg(any(windows, test))]
    receipt_owner: Arc<()>,
    #[cfg(any(windows, test))]
    receipt_key: (String, u64),
}

impl InitialEditLocation {
    #[cfg(any(windows, test))]
    #[allow(dead_code)] // Native capture wiring is a separate reviewed change.
    pub(crate) fn new(
        components: Vec<String>,
        identity: [u8; 16],
        root: ConfiguredRootIdentity,
        local_file: LocalFileIdentity,
        receipt: &InitialEditReceipt,
    ) -> Result<Self, BackendError> {
        let scope = receipt.scope();
        if components.is_empty()
            || components.len() > 256
            || components.iter().any(|part| {
                part.is_empty()
                    || part.len() > 255
                    || matches!(part.as_str(), "." | "..")
                    || part
                        .chars()
                        .any(|ch| ch.is_control() || matches!(ch, '/' | '\\' | ':'))
            })
            || components.iter().map(String::len).sum::<usize>() + components.len() - 1 > 32 * 1024
            || root.volume_serial != scope.root_volume_serial
            || root.file_index != scope.root_file_index
            || local_file.volume_serial != root.volume_serial
            || local_file.file_index == 0
            || local_file != receipt.local_file()
        {
            return Err(BackendError::Unavailable);
        }
        Ok(Self {
            components,
            identity,
            root,
            local_file,
            receipt_owner: Arc::clone(receipt.owner()),
            receipt_key: (receipt.record_key().0.to_owned(), receipt.record_key().1),
        })
    }

    pub fn components(&self) -> &[String] {
        &self.components
    }
    pub fn identity(&self) -> &[u8; 16] {
        &self.identity
    }
    pub fn root_identity(&self) -> ConfiguredRootIdentity {
        self.root
    }
    pub fn local_file_identity(&self) -> LocalFileIdentity {
        self.local_file
    }

    #[cfg(any(windows, test))]
    fn matches_receipt(&self, receipt: &InitialEditReceipt) -> bool {
        Arc::ptr_eq(&self.receipt_owner, receipt.owner())
            && self.receipt_key.0 == receipt.record_key().0
            && self.receipt_key.1 == receipt.record_key().1
            && self.root.volume_serial == receipt.scope().root_volume_serial
            && self.root.file_index == receipt.scope().root_file_index
            && self.local_file == receipt.local_file()
    }
}

/// The outcome and still-owned local location from one consumed fresh handoff.
/// Only a fresh proof from the recovery implementation can authorize the next
/// acknowledgement step; an outcome enum alone is insufficient.
pub struct InitialEditDispatch {
    pub outcome: ReconciliationOutcome,
    pub proof: Option<VerifiedEditReadback>,
    pub location: Option<InitialEditLocation>,
}

/// One fresh append and the exact prepared instance that published it. No
/// serialization or cloning is available; dispatch consumes the handoff.
pub struct PendingInitialEdit {
    recovery: Arc<dyn PreparedEditRecovery>,
    receipt: InitialEditReceipt,
    location: Option<InitialEditLocation>,
}

impl PendingInitialEdit {
    pub fn location(&self) -> Option<&InitialEditLocation> {
        self.location.as_ref()
    }

    /// Trusted routing metadata; do not display or log account values.
    pub fn scope(&self) -> &EditJournalScope {
        self.receipt.scope()
    }

    pub fn matches_provider(&self, scope: &ProviderScope, root: ConfiguredRootIdentity) -> bool {
        self.recovery.provider_scope() == scope && self.recovery.root_identity() == root
    }

    /// Dispatch once and retain the owned local callback location for a later
    /// independently guarded completion. Older recovery implementations return
    /// no proof and therefore grant no acknowledgement authority.
    pub fn dispatch_verified(
        self,
        remote: &dyn RecoveryRemote,
    ) -> Result<InitialEditDispatch, JournalError> {
        let (outcome, proof) = self
            .recovery
            .dispatch_initial_receipt_verified(self.receipt, remote)?;
        Ok(InitialEditDispatch {
            outcome,
            proof,
            location: self.location,
        })
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
    // Legacy location-free handoffs remain available to queue compatibility tests.
    #[cfg(test)]
    pub(crate) fn push(
        &self,
        recovery: Arc<dyn PreparedEditRecovery>,
        receipt: InitialEditReceipt,
    ) -> Result<(), BackendError> {
        self.push_inner(recovery, receipt, None)
    }

    #[allow(dead_code)] // Native capture wiring is a separate reviewed change.
    pub(crate) fn push_with_location(
        &self,
        recovery: Arc<dyn PreparedEditRecovery>,
        receipt: InitialEditReceipt,
        location: InitialEditLocation,
    ) -> Result<(), BackendError> {
        if !location.matches_receipt(&receipt) || location.root != recovery.root_identity() {
            return Err(BackendError::Unavailable);
        }
        self.push_inner(recovery, receipt, Some(location))
    }

    fn push_inner(
        &self,
        recovery: Arc<dyn PreparedEditRecovery>,
        receipt: InitialEditReceipt,
        location: Option<InitialEditLocation>,
    ) -> Result<(), BackendError> {
        let mut pending = self
            .pending
            .try_lock()
            .map_err(|_| BackendError::Unavailable)?;
        if pending.len() >= MAX_PENDING_INITIAL_EDITS {
            return Err(BackendError::Unavailable);
        }
        pending.push_back(PendingInitialEdit {
            recovery,
            receipt,
            location,
        });
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
