//! Explicit owner-thread entry for one fresh ordinary-file rename attempt.
//! Observation and serialized history alone never grant native authority.

use crate::namespace_file_rename::{FileRenameOutcome, reconcile_file_rename};
use crate::namespace_intent::{CapturedAuthorization, NamespaceIntent};
use crate::streamed_store::StoreError;
use crate::streamed_store::namespace_rename_store::{FileRenamePublishResult, FileRenameStore};
use crate::{
    BackendError, ConfiguredRootConnection, Error, OpaqueIdentity, OpenCloudPlaceholderBackend,
};
use std::sync::Arc;

/// Preserve the failing layer. A failed fresh publication or dispatch is
/// retained; calling this entry again cannot adopt that record or resend it.
#[derive(Debug)]
pub enum NativeFileRenameError {
    Backend(BackendError),
    Local(Error),
    Store(StoreError),
}

impl ConfiguredRootConnection {
    /// Reconcile one already observed same-parent Personal file rename.
    ///
    /// `candidate` and `parent_identity` are hints. This call first pins the
    /// actual destination and ordinary ancestry against a current session,
    /// then publishes a fresh intent. A second current session supplies the
    /// source/destination content proofs and the one-send coordinator. Pins
    /// survive the journal wait; no backend read lease is nested across it.
    /// Existing or conflicting history is retained without dispatch. This
    /// explicit entry does not activate an observer loop or replay work.
    pub fn reconcile_fresh_file_rename(
        &self,
        backend: &Arc<OpenCloudPlaceholderBackend>,
        store: &Arc<FileRenameStore>,
        candidate: NamespaceIntent,
        parent_identity: OpaqueIdentity,
        owner_current: &dyn Fn(CapturedAuthorization) -> bool,
    ) -> Result<FileRenameOutcome, NativeFileRenameError> {
        let mut pinned = backend
            .with_file_rename_session(&candidate, parent_identity, owner_current, |session| {
                self.inner
                    .prepare_pinned_file_rename(backend, session, &candidate)
            })
            .map_err(NativeFileRenameError::Backend)?
            .map_err(NativeFileRenameError::Local)?;
        let fresh = match store
            .publish_intent(candidate)
            .map_err(NativeFileRenameError::Store)?
        {
            FileRenamePublishResult::Fresh(fresh) => fresh,
            FileRenamePublishResult::Retained => return Ok(FileRenameOutcome::Retained),
        };
        let mut lease = fresh
            .acquire_dispatch()
            .map_err(NativeFileRenameError::Store)?;
        let intent = lease.intent().clone();
        backend
            .with_file_rename_session(&intent, parent_identity, owner_current, |session| {
                let mut local = pinned.local(session);
                reconcile_file_rename(&mut lease, session.remote(), &mut local)
            })
            .map_err(NativeFileRenameError::Backend)?
            .map_err(NativeFileRenameError::Store)
    }
}
