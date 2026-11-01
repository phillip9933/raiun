//! One ordinary directory-create attempt. Stored progress and readback reports
//! never grant native conversion, clean-state or destructive authority.
use crate::namespace_intent::{
    NamespaceDestinationReport, NamespaceEventKind, NamespaceIntent, NamespaceOperation,
    NamespacePhase, NamespaceProgressSnapshot,
};
use crate::streamed_store::StoreError;
use raiun_core::backend::{CloudError, ErrorKind};
use raiun_opencloud::DirectoryCreateResponse;

/// Must retain the store's exclusive per-record operation lease through this
/// entire call. append_event authenticates context and publishes durably.
pub trait DirectoryCreateJournal {
    fn intent(&self) -> &NamespaceIntent;
    fn progress(&self) -> NamespaceProgressSnapshot;
    fn append_event(&mut self, event: NamespaceEventKind) -> Result<(), StoreError>;
}
impl DirectoryCreateJournal for crate::namespace_store::DirectoryIntentLease {
    fn intent(&self) -> &NamespaceIntent {
        self.intent()
    }
    fn progress(&self) -> NamespaceProgressSnapshot {
        self.progress()
    }
    fn append_event(&mut self, event: NamespaceEventKind) -> Result<(), StoreError> {
        self.append_event(event).map(|_| ())
    }
}

/// Nonserializable permit minted by this coordinator only after the journal
/// confirms durable Submitted. It authorizes one qualified create attempt,
/// never native conversion or replay. Serialized progress cannot construct it.
pub struct DirectoryCreateDispatch<'a> {
    intent: &'a NamespaceIntent,
}
impl DirectoryCreateDispatch<'_> {
    pub fn intent(&self) -> &NamespaceIntent {
        self.intent
    }
}
#[cfg(test)]
impl<'a> DirectoryCreateDispatch<'a> {
    pub(crate) fn for_test(intent: &'a NamespaceIntent) -> Self {
        Self { intent }
    }
}

/// A trusted live adapter must retain authorization through the complete route.
/// Test implementations inject server failures, never native capabilities.
pub trait DirectoryCreateRemote {
    fn ensure_authorized(&self, intent: &NamespaceIntent) -> Result<(), CloudError>;
    fn preflight(&self, intent: &NamespaceIntent) -> Result<(), CloudError>;
    fn create(
        &self,
        dispatch: &DirectoryCreateDispatch<'_>,
    ) -> Result<DirectoryCreateResponse, CloudError>;
    fn observe(&self, intent: &NamespaceIntent) -> Result<NamespaceDestinationReport, CloudError>;
}
/// Fresh exact native identity/ancestry checks are supplied by the owner. This
/// interface cannot manufacture them from stored ordinary classification.
pub trait DirectoryCreateLocal {
    fn admit(&mut self, intent: &NamespaceIntent) -> Result<(), CloudError>;
    /// Independently obtain native publication authority. The readback argument
    /// is only live remote evidence; it is not a native capability.
    fn publish(
        &mut self,
        intent: &NamespaceIntent,
        readback: &DirectoryCreateReadback,
    ) -> Result<(), CloudError>;
    /// Admit the final factual report under the implementation's current
    /// local publication fence. No unguarded default implementation exists.
    fn record_completion<F>(
        &mut self,
        intent: &NamespaceIntent,
        readback: &DirectoryCreateReadback,
        record: F,
    ) -> Result<(), DirectoryCompletionError>
    where
        F: FnOnce() -> Result<(), StoreError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryCompletionError {
    Unavailable,
    Store(StoreError),
    /// The append may already be durable; preserve its factual history.
    Uncertain,
}

/// Nonserializable live report of201 plus repeated observed path identity. This
/// does NOT prove atomic created-ID ownership or authorize native completion.
pub struct DirectoryCreateReadback {
    report: NamespaceDestinationReport,
}
impl DirectoryCreateReadback {
    pub fn report(&self) -> &NamespaceDestinationReport {
        &self.report
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryCreateOutcome {
    LocalCompleted,
    RemoteVerifiedLocalPending,
    Deferred,
    Conflict,
    Uncertain,
    Retained,
}
fn attention(error: &CloudError) -> NamespaceEventKind {
    if error.kind == ErrorKind::Conflict {
        NamespaceEventKind::Conflict
    } else {
        NamespaceEventKind::Deferred
    }
}
fn finish(
    journal: &mut impl DirectoryCreateJournal,
    event: NamespaceEventKind,
) -> Result<DirectoryCreateOutcome, StoreError> {
    let outcome = match &event {
        NamespaceEventKind::Conflict => DirectoryCreateOutcome::Conflict,
        NamespaceEventKind::Uncertain => DirectoryCreateOutcome::Uncertain,
        _ => DirectoryCreateOutcome::Deferred,
    };
    journal.append_event(event)?;
    Ok(outcome)
}

fn valid_directory_report(intent: &NamespaceIntent, report: &NamespaceDestinationReport) -> bool {
    if report.remote.resource_id.starts_with("http://")
        || report.remote.resource_id.starts_with("https://")
        || report.remote.byte_len != 0
    {
        return false;
    }
    // Validate the adapter's report against the complete original context with
    // the same portable checker used to validate authenticated store histories.
    let Ok(mut check) = crate::namespace_intent::NamespaceIntentProgress::new(intent.clone())
    else {
        return false;
    };
    let Ok(context) = intent.event_context() else {
        return false;
    };
    for (sequence, event) in [
        (1, NamespaceEventKind::RemoteSubmitted),
        (
            2,
            NamespaceEventKind::RemoteVerified {
                report: report.clone(),
            },
        ),
    ] {
        if check
            .record(&crate::namespace_intent::NamespaceEvent {
                context: context.clone(),
                sequence,
                event,
            })
            .is_err()
        {
            return false;
        }
    }
    true
}
// Shared owner-side journal ordering. No native permission is minted here.
pub(crate) fn submit_directory_create(
    journal: &mut impl DirectoryCreateJournal,
) -> Result<(), StoreError> {
    let p = journal.progress();
    if p.sequence != 0
        || p.remote != NamespacePhase::Pending
        || p.attention.is_some()
        || p.local_completed
    {
        return Err(StoreError::CorruptEvidence);
    }
    journal.append_event(NamespaceEventKind::RemoteSubmitted)
}
#[cfg(any(windows, test))]
pub(crate) fn submitted_directory_dispatch<'a>(
    intent: &'a NamespaceIntent,
    progress: NamespaceProgressSnapshot,
) -> Result<DirectoryCreateDispatch<'a>, StoreError> {
    if progress.sequence != 1
        || progress.remote != NamespacePhase::Submitted
        || progress.attention.is_some()
        || progress.local_completed
    {
        return Err(StoreError::CorruptEvidence);
    }
    Ok(DirectoryCreateDispatch { intent })
}
pub(crate) fn record_directory_verified(
    journal: &mut impl DirectoryCreateJournal,
    report: NamespaceDestinationReport,
) -> Result<DirectoryCreateReadback, StoreError> {
    let intent = journal.intent().clone();
    if !valid_directory_report(&intent, &report) {
        return Err(StoreError::CorruptEvidence);
    }
    journal.append_event(NamespaceEventKind::RemoteVerified {
        report: report.clone(),
    })?;
    Ok(DirectoryCreateReadback { report })
}
/// At most one send. There is no retry/rebase path, including after a durable
/// Submitted record or a failure to durably publish subsequent verification.
pub fn reconcile_directory_create(
    journal: &mut impl DirectoryCreateJournal,
    remote: &(impl DirectoryCreateRemote + ?Sized),
    local: &mut impl DirectoryCreateLocal,
) -> Result<DirectoryCreateOutcome, StoreError> {
    let intent = journal.intent().clone();
    intent.validate().map_err(|_| StoreError::CorruptEvidence)?;
    let NamespaceOperation::CreateDirectory { destination } = &intent.operation else {
        return Err(StoreError::CorruptEvidence);
    };
    let progress = journal.progress();
    if progress.sequence != 0
        || progress.remote != NamespacePhase::Pending
        || progress.attention.is_some()
        || progress.local_completed
    {
        return Ok(DirectoryCreateOutcome::Retained);
    }
    if let Err(error) = remote
        .ensure_authorized(&intent)
        .and_then(|()| local.admit(&intent))
        .and_then(|()| remote.preflight(&intent))
        .and_then(|()| remote.ensure_authorized(&intent))
    {
        return finish(journal, attention(&error));
    }
    submit_directory_create(journal)?;
    let dispatch = DirectoryCreateDispatch { intent: &intent };
    match remote.create(&dispatch) {
        Err(error) | Ok(DirectoryCreateResponse::Rejected(error)) => {
            // The adapter's Err contract explicitly guarantees no send. A
            // known server rejection cannot be treated as successful adoption.
            if remote.ensure_authorized(&intent).is_err() {
                return finish(journal, NamespaceEventKind::Uncertain);
            }
            return finish(journal, attention(&error));
        }
        Ok(DirectoryCreateResponse::Uncertain(_)) => {
            return finish(journal, NamespaceEventKind::Uncertain);
        }
        Ok(DirectoryCreateResponse::Created) => (),
    }
    let report = match remote
        .ensure_authorized(&intent)
        .and_then(|()| remote.observe(&intent))
        .and_then(|report| {
            remote.ensure_authorized(&intent)?;
            Ok(report)
        }) {
        Ok(report) => report,
        Err(_) => return finish(journal, NamespaceEventKind::Uncertain),
    };
    if !valid_directory_report(&intent, &report) {
        return finish(journal, NamespaceEventKind::Uncertain);
    }
    let readback = record_directory_verified(journal, report)?;
    // Failure preserves remote verification but grants no local completion.
    if remote.ensure_authorized(&intent).is_err()
        || local.admit(&intent).is_err()
        || local.publish(&intent, &readback).is_err()
        || remote.ensure_authorized(&intent).is_err()
    {
        return Ok(DirectoryCreateOutcome::RemoteVerifiedLocalPending);
    }
    match local.record_completion(&intent, &readback, || {
        journal.append_event(NamespaceEventKind::LocalCompleted {
            destination: destination.clone(),
        })
    }) {
        Ok(()) => Ok(DirectoryCreateOutcome::LocalCompleted),
        Err(DirectoryCompletionError::Unavailable) => {
            Ok(DirectoryCreateOutcome::RemoteVerifiedLocalPending)
        }
        Err(DirectoryCompletionError::Store(error)) => Err(error),
        Err(DirectoryCompletionError::Uncertain) => Err(StoreError::PublicationUncertain),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespace_intent::*;
    use crate::{EditJournalScope, LocalFileIdentity, RemoteEditBaseline};
    use std::cell::Cell;
    use std::rc::Rc;
    fn intent() -> NamespaceIntent {
        NamespaceIntent {
            schema_version: 1,
            record_id: "a".repeat(32),
            record_generation: 1,
            operation: NamespaceOperation::CreateDirectory {
                destination: LocalNamespaceEntry {
                    name: "new-directory".into(),
                    object_kind: NamespaceObjectKind::Directory,
                    local_file: LocalFileIdentity {
                        volume_serial: 7,
                        file_index: 13,
                    },
                    parent: NamespaceParent {
                        scope: EditJournalScope {
                            profile_id: "default".into(),
                            server_origin: "https://cloud.example.test".into(),
                            account_subject: "account".into(),
                            space_id: "space".into(),
                            root_resource_id: "root".into(),
                            root_volume_serial: 7,
                            root_file_index: 11,
                        },
                        authorization: CapturedAuthorization {
                            agent_generation: 3,
                            token_generation: 2,
                        },
                        classification: StorageClassification::Ordinary,
                        local_file: LocalFileIdentity {
                            volume_serial: 7,
                            file_index: 12,
                        },
                        local_components: vec!["Personal".into()],
                        remote: RemoteEditBaseline {
                            resource_id: "parent".into(),
                            etag: "\"parent-v1\"".into(),
                            byte_len: 0,
                        },
                    },
                },
            },
        }
    }
    struct Journal {
        intent: NamespaceIntent,
        progress: NamespaceIntentProgress,
        submitted: Rc<Cell<bool>>,
        fail: bool,
        fail_completion: bool,
    }
    impl Journal {
        fn new() -> Self {
            let intent = intent();
            Self {
                progress: NamespaceIntentProgress::new(intent.clone()).unwrap(),
                intent,
                submitted: Rc::new(Cell::new(false)),
                fail: false,
                fail_completion: false,
            }
        }
    }
    impl DirectoryCreateJournal for Journal {
        fn intent(&self) -> &NamespaceIntent {
            &self.intent
        }
        fn progress(&self) -> NamespaceProgressSnapshot {
            self.progress.snapshot()
        }
        fn append_event(&mut self, event: NamespaceEventKind) -> Result<(), StoreError> {
            if self.fail
                || (self.fail_completion
                    && matches!(event, NamespaceEventKind::LocalCompleted { .. }))
            {
                return Err(StoreError::Io);
            }
            let submitted = matches!(event, NamespaceEventKind::RemoteSubmitted);
            self.progress
                .record(&NamespaceEvent {
                    context: self.intent.event_context().unwrap(),
                    sequence: self.progress.snapshot().sequence + 1,
                    event,
                })
                .map_err(|_| StoreError::CorruptEvidence)?;
            if submitted {
                self.submitted.set(true);
            }
            Ok(())
        }
    }
    struct Remote {
        submitted: Rc<Cell<bool>>,
        sends: Cell<usize>,
        reject: Option<ErrorKind>,
        preflight: Option<ErrorKind>,
        loss: bool,
        uncertain: bool,
        revoke: bool,
        active: Cell<bool>,
        report: NamespaceDestinationReport,
    }
    impl Remote {
        fn new(j: &Journal) -> Self {
            let NamespaceOperation::CreateDirectory { destination } = &j.intent.operation else {
                unreachable!()
            };
            Self {
                submitted: j.submitted.clone(),
                sends: Cell::new(0),
                reject: None,
                preflight: None,
                loss: false,
                uncertain: false,
                revoke: false,
                active: Cell::new(true),
                report: NamespaceDestinationReport {
                    destination: destination.clone(),
                    content: None,
                    remote: RemoteEditBaseline {
                        resource_id: "created-child".into(),
                        etag: "\"child-v1\"".into(),
                        byte_len: 0,
                    },
                },
            }
        }
    }
    fn error(kind: ErrorKind) -> CloudError {
        CloudError::new(kind, "injected")
    }
    impl DirectoryCreateRemote for Remote {
        fn ensure_authorized(&self, _: &NamespaceIntent) -> Result<(), CloudError> {
            if self.active.get() {
                Ok(())
            } else {
                Err(error(ErrorKind::Unauthorized))
            }
        }
        fn preflight(&self, _: &NamespaceIntent) -> Result<(), CloudError> {
            self.preflight.map_or(Ok(()), |e| Err(error(e)))
        }
        fn create(
            &self,
            _: &DirectoryCreateDispatch<'_>,
        ) -> Result<DirectoryCreateResponse, CloudError> {
            assert!(self.submitted.get(), "durable submission must precede send");
            self.sends.set(self.sends.get() + 1);
            if self.revoke {
                self.active.set(false);
            }
            if self.uncertain {
                return Ok(DirectoryCreateResponse::Uncertain(error(
                    ErrorKind::Offline,
                )));
            }
            Ok(self.reject.map_or(DirectoryCreateResponse::Created, |e| {
                DirectoryCreateResponse::Rejected(error(e))
            }))
        }
        fn observe(&self, _: &NamespaceIntent) -> Result<NamespaceDestinationReport, CloudError> {
            if self.loss {
                Err(error(ErrorKind::Offline))
            } else {
                Ok(self.report.clone())
            }
        }
    }
    #[derive(Default)]
    struct Local {
        admission_refused: bool,
        publication_refused: bool,
        published: usize,
        completion_refused: bool,
        completion_uncertain: bool,
    }
    impl DirectoryCreateLocal for Local {
        fn admit(&mut self, _: &NamespaceIntent) -> Result<(), CloudError> {
            if self.admission_refused {
                Err(error(ErrorKind::Conflict))
            } else {
                Ok(())
            }
        }
        fn publish(
            &mut self,
            _: &NamespaceIntent,
            _: &DirectoryCreateReadback,
        ) -> Result<(), CloudError> {
            if self.publication_refused {
                Err(error(ErrorKind::Conflict))
            } else {
                self.published += 1;
                Ok(())
            }
        }
        fn record_completion<F>(
            &mut self,
            _: &NamespaceIntent,
            _: &DirectoryCreateReadback,
            record: F,
        ) -> Result<(), DirectoryCompletionError>
        where
            F: FnOnce() -> Result<(), StoreError>,
        {
            if self.completion_refused {
                return Err(DirectoryCompletionError::Unavailable);
            }
            record().map_err(DirectoryCompletionError::Store)?;
            if self.completion_uncertain {
                return Err(DirectoryCompletionError::Uncertain);
            }
            Ok(())
        }
    }
    #[test]
    fn phased_submission_and_verified_helpers_preserve_actual_journal_order() {
        let mut journal = Journal::new();
        let remote = Remote::new(&journal);
        assert!(submitted_directory_dispatch(journal.intent(), journal.progress()).is_err());
        submit_directory_create(&mut journal).unwrap();
        assert!(submit_directory_create(&mut journal).is_err());
        let dispatch = submitted_directory_dispatch(journal.intent(), journal.progress()).unwrap();
        assert!(matches!(
            remote.create(&dispatch).unwrap(),
            DirectoryCreateResponse::Created
        ));
        assert_eq!(remote.sends.get(), 1);
        record_directory_verified(&mut journal, remote.report.clone()).unwrap();
        assert_eq!(journal.progress().remote, NamespacePhase::Verified);
        assert!(!journal.progress().local_completed);
        assert!(submitted_directory_dispatch(journal.intent(), journal.progress()).is_err());
    }
    #[test]
    fn phased_verified_append_failure_does_not_claim_verified_or_completion() {
        let mut journal = Journal::new();
        let report = Remote::new(&journal).report;
        submit_directory_create(&mut journal).unwrap();
        journal.fail = true;
        assert!(record_directory_verified(&mut journal, report).is_err());
        assert_eq!(journal.progress().remote, NamespacePhase::Submitted);
        assert!(!journal.progress().local_completed);
    }
    #[test]
    fn one_send_after_durable_submission_and_no_replay_from_completed_or_submitted() {
        let mut j = Journal::new();
        let r = Remote::new(&j);
        let mut l = Local::default();
        assert_eq!(
            reconcile_directory_create(&mut j, &r, &mut l).unwrap(),
            DirectoryCreateOutcome::LocalCompleted
        );
        assert_eq!((r.sends.get(), l.published), (1, 1));
        assert_eq!(
            reconcile_directory_create(&mut j, &r, &mut l).unwrap(),
            DirectoryCreateOutcome::Retained
        );
        assert_eq!(r.sends.get(), 1);
        let mut j = Journal::new();
        let r = Remote::new(&j);
        j.append_event(NamespaceEventKind::RemoteSubmitted).unwrap();
        assert_eq!(
            reconcile_directory_create(&mut j, &r, &mut l).unwrap(),
            DirectoryCreateOutcome::Retained
        );
        assert_eq!(r.sends.get(), 0);
    }
    #[test]
    fn durable_submission_failure_and_local_refusal_send_nothing() {
        for failed_store in [false, true] {
            let mut j = Journal::new();
            let r = Remote::new(&j);
            j.fail = failed_store;
            let mut l = Local {
                admission_refused: !failed_store,
                ..Local::default()
            };
            let result = reconcile_directory_create(&mut j, &r, &mut l);
            if failed_store {
                assert_eq!(result, Err(StoreError::Io));
            } else {
                assert_eq!(result.unwrap(), DirectoryCreateOutcome::Conflict);
            }
            assert_eq!(r.sends.get(), 0);
        }
    }
    #[test]
    fn collision_and_forbidden_are_not_adopted() {
        for (kind, outcome) in [
            (ErrorKind::Conflict, DirectoryCreateOutcome::Conflict),
            (ErrorKind::Forbidden, DirectoryCreateOutcome::Deferred),
        ] {
            let mut j = Journal::new();
            let mut r = Remote::new(&j);
            r.reject = Some(kind);
            let mut l = Local::default();
            assert_eq!(
                reconcile_directory_create(&mut j, &r, &mut l).unwrap(),
                outcome
            );
            assert_eq!((r.sends.get(), l.published), (1, 0));
        }
    }
    #[test]
    fn preflight_denial_never_submits_and_post201_loss_or_revocation_is_uncertain() {
        for post in [false, true] {
            let mut j = Journal::new();
            let mut r = Remote::new(&j);
            let mut l = Local::default();
            if post {
                r.loss = true;
            } else {
                r.preflight = Some(ErrorKind::Forbidden);
            }
            assert_eq!(
                reconcile_directory_create(&mut j, &r, &mut l).unwrap(),
                if post {
                    DirectoryCreateOutcome::Uncertain
                } else {
                    DirectoryCreateOutcome::Deferred
                }
            );
            assert_eq!(r.sends.get(), usize::from(post));
            assert_eq!(l.published, 0);
        }
        let mut j = Journal::new();
        let mut r = Remote::new(&j);
        r.revoke = true;
        assert_eq!(
            reconcile_directory_create(&mut j, &r, &mut Local::default()).unwrap(),
            DirectoryCreateOutcome::Uncertain
        );
    }
    #[test]
    fn wrong_report_scope_parent_generation_fileid_url_or_weak_validator_is_uncertain() {
        for variant in 0..8 {
            let mut j = Journal::new();
            let mut r = Remote::new(&j);
            match variant {
                0 => r.report.destination.parent.scope.account_subject.push('x'),
                1 => r.report.destination.parent.scope.root_resource_id.push('x'),
                2 => r.report.destination.parent.local_file.file_index += 1,
                3 => r.report.destination.parent.authorization.token_generation += 1,
                4 => r.report.destination.local_file.file_index += 1,
                5 => r.report.remote.resource_id = "https://server/dav/path".into(),
                6 => r.report.remote.etag = "W/\"weak\"".into(),
                _ => r.report.destination.parent.classification = StorageClassification::Encrypted,
            }
            assert_eq!(
                reconcile_directory_create(&mut j, &r, &mut Local::default()).unwrap(),
                DirectoryCreateOutcome::Uncertain
            );
        }
    }
    #[test]
    fn possible_send_transport_failure_is_uncertain_and_never_replayed() {
        let mut j = Journal::new();
        let mut r = Remote::new(&j);
        r.uncertain = true;
        let mut l = Local::default();
        assert_eq!(
            reconcile_directory_create(&mut j, &r, &mut l).unwrap(),
            DirectoryCreateOutcome::Uncertain
        );
        assert_eq!(
            reconcile_directory_create(&mut j, &r, &mut l).unwrap(),
            DirectoryCreateOutcome::Retained
        );
        assert_eq!((r.sends.get(), l.published), (1, 0));
    }

    #[test]
    fn native_publication_refusal_retains_remote_verified_without_local_completion() {
        let mut j = Journal::new();
        let r = Remote::new(&j);
        let mut l = Local {
            publication_refused: true,
            ..Local::default()
        };
        assert_eq!(
            reconcile_directory_create(&mut j, &r, &mut l).unwrap(),
            DirectoryCreateOutcome::RemoteVerifiedLocalPending
        );
        assert_eq!(j.progress().remote, NamespacePhase::Verified);
        assert!(!j.progress().local_completed);
        assert_eq!(
            reconcile_directory_create(&mut j, &r, &mut l).unwrap(),
            DirectoryCreateOutcome::Retained
        );
        assert_eq!(r.sends.get(), 1);
    }
    #[test]
    fn final_fence_refusal_and_append_failure_never_report_success() {
        let mut j = Journal::new();
        let r = Remote::new(&j);
        let mut l = Local {
            completion_refused: true,
            ..Local::default()
        };
        assert_eq!(
            reconcile_directory_create(&mut j, &r, &mut l).unwrap(),
            DirectoryCreateOutcome::RemoteVerifiedLocalPending
        );
        assert_eq!(j.progress().sequence, 2);
        assert!(!j.progress().local_completed);
        let mut j = Journal::new();
        j.fail_completion = true;
        let r = Remote::new(&j);
        let mut l = Local::default();
        assert_eq!(
            reconcile_directory_create(&mut j, &r, &mut l),
            Err(StoreError::Io)
        );
        assert_eq!(j.progress().sequence, 2);
        assert!(!j.progress().local_completed);
    }
    #[test]
    fn post_admission_uncertainty_preserves_already_written_factual_completion() {
        let mut j = Journal::new();
        let r = Remote::new(&j);
        let mut l = Local {
            completion_uncertain: true,
            ..Local::default()
        };
        assert_eq!(
            reconcile_directory_create(&mut j, &r, &mut l),
            Err(StoreError::PublicationUncertain)
        );
        assert!(j.progress().local_completed);
        assert_eq!(j.progress().sequence, 3);
    }
}
