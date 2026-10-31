//! Explicit owner-thread entry for one fresh ordinary-file rename attempt.
//! Observation and serialized history alone never grant native authority.

use crate::namespace_file_rename::{FileRenameOutcome, reconcile_file_rename};
use crate::namespace_intent::{CapturedAuthorization, NamespaceIntent};
use crate::save_rename_admission::{GuardedLocal, GuardedRemote, SaveRenameAdmission};
use crate::streamed_store::StoreError;
use crate::streamed_store::namespace_rename_store::{FileRenamePublishResult, FileRenameStore};
use crate::{
    BackendError, ConfiguredRootConnection, Error, FileRenameBindingCandidate, OpaqueIdentity,
    OpenCloudPlaceholderBackend,
};
use std::sync::Arc;

/// Preserve the failing layer. A failed fresh publication or dispatch is
/// retained; calling this entry again cannot adopt that record or resend it.
#[derive(Debug)]
pub enum NativeFileRenameError {
    /// This invocation published no intent and sent no MOVE. Its caller may
    /// defer a volatile observation, but this supplies no historical custody.
    DeferredBeforePublication,
    /// This invocation retained its own published intent but did not enter
    /// dispatch. It cannot be adopted or replayed by another invocation.
    AdmissionAfterPublication,
    Backend(BackendError),
    Local(Error),
    Store(StoreError),
}

impl ConfiguredRootConnection {
    /// Complete one partial observer candidate using a fresh remote parent
    /// capture and native pins, then enter the existing explicit producer.
    /// This is an opt-in call only; it does not activate observation or replay.
    pub fn reconcile_fresh_file_rename_candidate(
        &self,
        backend: &Arc<OpenCloudPlaceholderBackend>,
        candidate: &FileRenameBindingCandidate<'_>,
        record_generation: u64,
        owner_current: &dyn Fn(CapturedAuthorization) -> bool,
    ) -> Result<FileRenameOutcome, NativeFileRenameError> {
        let (tracker, recovery) = self
            .inner
            .file_rename_guard_context(backend)
            .map_err(NativeFileRenameError::Local)?;
        let ticket = tracker
            .try_begin_rename()
            .ok_or(NativeFileRenameError::DeferredBeforePublication)?;
        let admission = SaveRenameAdmission::new(ticket);
        let guarded_owner =
            |authorization| admission.check().is_ok() && owner_current(authorization);
        self.probe_file_rename_admission(backend, &recovery, &admission, true)?;
        self.inner
            .preflight_file_rename_candidate(backend, candidate, record_generation, owner_current)
            .map_err(NativeFileRenameError::Local)?;
        admission
            .check()
            .map_err(|_| NativeFileRenameError::DeferredBeforePublication)?;
        let intent = backend
            .with_file_rename_candidate_parent(candidate, &guarded_owner, |captured| {
                self.inner.intent_from_file_rename_candidate(
                    backend,
                    candidate,
                    captured,
                    record_generation,
                )
            })
            .map_err(NativeFileRenameError::Backend)?
            .map_err(NativeFileRenameError::Local)?;
        self.probe_file_rename_admission(backend, &recovery, &admission, true)?;
        let scope = match &intent.operation {
            crate::namespace_intent::NamespaceOperation::MoveWithinScope { source, .. } => {
                &source.local.parent.scope
            }
            _ => return Err(NativeFileRenameError::Local(Error::EditRecoveryUnavailable)),
        };
        let store = self
            .file_rename_store(backend, scope, candidate.authorization())
            .map_err(NativeFileRenameError::Local)?
            .ok_or(NativeFileRenameError::Local(Error::EditRecoveryUnavailable))?;
        self.reconcile_fresh_file_rename_admitted(
            backend,
            &store,
            intent,
            candidate.parent_identity(),
            owner_current,
            &recovery,
            &admission,
        )
    }

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
        let (tracker, recovery) = self
            .inner
            .file_rename_guard_context(backend)
            .map_err(NativeFileRenameError::Local)?;
        let ticket = tracker
            .try_begin_rename()
            .ok_or(NativeFileRenameError::DeferredBeforePublication)?;
        let admission = SaveRenameAdmission::new(ticket);
        self.probe_file_rename_admission(backend, &recovery, &admission, true)?;
        let (scope, authorization) = match &candidate.operation {
            crate::namespace_intent::NamespaceOperation::MoveWithinScope { source, .. } => (
                &source.local.parent.scope,
                source.local.parent.authorization,
            ),
            _ => return Err(NativeFileRenameError::Local(Error::EditRecoveryUnavailable)),
        };
        let expected = self
            .file_rename_store(backend, scope, authorization)
            .map_err(NativeFileRenameError::Local)?
            .ok_or(NativeFileRenameError::Local(Error::EditRecoveryUnavailable))?;
        if !store
            .same_admitted_binding(&expected)
            .map_err(NativeFileRenameError::Store)?
        {
            return Err(NativeFileRenameError::Local(Error::EditRecoveryUnavailable));
        }
        self.reconcile_fresh_file_rename_admitted(
            backend,
            store,
            candidate,
            parent_identity,
            owner_current,
            &recovery,
            &admission,
        )
    }

    /// Both entries retain the same ticket through every wait. Health scans
    /// occur only outside session closures, and whole history only before this
    /// attempt publishes its own Pending record.
    #[allow(clippy::too_many_arguments)]
    fn reconcile_fresh_file_rename_admitted(
        &self,
        backend: &Arc<OpenCloudPlaceholderBackend>,
        store: &Arc<FileRenameStore>,
        candidate: NamespaceIntent,
        parent_identity: OpaqueIdentity,
        owner_current: &dyn Fn(CapturedAuthorization) -> bool,
        recovery: &Arc<dyn crate::PreparedEditRecovery>,
        admission: &SaveRenameAdmission<'_>,
    ) -> Result<FileRenameOutcome, NativeFileRenameError> {
        self.probe_file_rename_admission(backend, recovery, admission, true)?;
        let guarded_owner =
            |authorization| admission.check().is_ok() && owner_current(authorization);
        let mut pinned = backend
            .with_file_rename_session(&candidate, parent_identity, &guarded_owner, |session| {
                self.inner
                    .prepare_pinned_file_rename(backend, session, &candidate)
            })
            .map_err(NativeFileRenameError::Backend)?
            .map_err(NativeFileRenameError::Local)?;
        // Parent/session/native pin waits are over. Re-authenticate persisted
        // recovery before publication, with no backend read lease held.
        self.probe_file_rename_admission(backend, recovery, admission, true)?;
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
        // Publication is factual now: failure retains it and never grants the
        // early no-publication deferral variant. Exclude our own namespace row.
        self.probe_file_rename_admission(backend, recovery, admission, false)
            .map_err(|_| NativeFileRenameError::AdmissionAfterPublication)?;
        backend
            .with_file_rename_session(&intent, parent_identity, &guarded_owner, |session| {
                let mut local = pinned.local(session);
                let remote = GuardedRemote {
                    remote: session.remote(),
                    admission,
                };
                let mut local = GuardedLocal {
                    local: &mut local,
                    admission,
                };
                reconcile_file_rename(&mut lease, &remote, &mut local)
            })
            .map_err(NativeFileRenameError::Backend)?
            .map_err(NativeFileRenameError::Store)
    }

    fn probe_file_rename_admission(
        &self,
        backend: &Arc<OpenCloudPlaceholderBackend>,
        recovery: &Arc<dyn crate::PreparedEditRecovery>,
        admission: &SaveRenameAdmission<'_>,
        whole_history: bool,
    ) -> Result<(), NativeFileRenameError> {
        let (_, current) = self
            .inner
            .file_rename_guard_context(backend)
            .map_err(NativeFileRenameError::Local)?;
        if !Arc::ptr_eq(recovery, &current)
            || !admission.probe_clean(|| {
                if whole_history && recovery.has_unresolved()? {
                    return Ok(true);
                }
                recovery.has_unresolved_content_authenticated_legacy()
            })
        {
            return Err(NativeFileRenameError::DeferredBeforePublication);
        }
        Ok(())
    }
}
