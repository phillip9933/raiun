use super::*;
use crate::namespace_intent::{CapturedAuthorization, NamespaceParent, StorageClassification};
use crate::{EditJournalScope, LocalFileIdentity, RemoteEditBaseline};
use std::{cell::Cell, rc::Rc};

struct Journal {
    intent: NamespaceIntent,
    progress: NamespaceIntentProgress,
    events: Vec<NamespaceEventKind>,
    append_count: usize,
    fail_append_at: Option<usize>,
    submitted: Rc<Cell<bool>>,
    freshly_published_here: bool,
}
impl Journal {
    fn new(intent: NamespaceIntent) -> Self {
        let progress = NamespaceIntentProgress::new(intent.clone()).unwrap();
        Self {
            intent,
            progress,
            events: Vec::new(),
            append_count: 0,
            fail_append_at: None,
            submitted: Rc::new(Cell::new(false)),
            freshly_published_here: true,
        }
    }
}
impl FileRenameJournal for Journal {
    fn owns_fresh_publication(&self) -> bool {
        self.freshly_published_here
    }
    fn intent(&self) -> &NamespaceIntent {
        &self.intent
    }
    fn progress(&self) -> NamespaceProgressSnapshot {
        self.progress.snapshot()
    }
    fn append_event(&mut self, event: NamespaceEventKind) -> Result<(), StoreError> {
        let result = (|| {
            self.append_count += 1;
            if self.fail_append_at == Some(self.append_count) {
                return Err(StoreError::Io);
            }
            let context = self
                .intent
                .event_context()
                .map_err(|_| StoreError::CorruptEvidence)?;
            let sequence = self.progress.snapshot().sequence + 1;
            self.progress
                .record(&NamespaceEvent {
                    context,
                    sequence,
                    event: event.clone(),
                })
                .map_err(|_| StoreError::CorruptEvidence)?;
            if matches!(&event, NamespaceEventKind::RemoteSubmitted) {
                self.submitted.set(true);
            }
            self.events.push(event);
            Ok(())
        })();
        if result.is_err() {
            self.freshly_published_here = false;
        }
        result
    }
}

#[derive(Clone, Copy)]
enum SendMode {
    Renamed,
    Rejected(ErrorKind),
    Uncertain,
    RevokeAfterSend,
}
#[derive(Clone, Copy)]
enum ObservationMode {
    Valid,
    WrongId,
    WrongLength,
    SourcePresent,
    UrlId,
    Error,
}
struct Remote {
    mode: SendMode,
    observation: ObservationMode,
    sends: Cell<usize>,
    preflights: Cell<usize>,
    observations: Cell<usize>,
    auth_checks: Cell<usize>,
    revoked: Cell<bool>,
    preflight_error: Cell<bool>,
    submitted: Rc<Cell<bool>>,
}
impl Remote {
    fn new(submitted: Rc<Cell<bool>>) -> Self {
        Self {
            mode: SendMode::Renamed,
            observation: ObservationMode::Valid,
            sends: Cell::new(0),
            preflights: Cell::new(0),
            observations: Cell::new(0),
            auth_checks: Cell::new(0),
            revoked: Cell::new(false),
            preflight_error: Cell::new(false),
            submitted,
        }
    }
}
impl FileRenameRemote for Remote {
    fn ensure_authorized(&self, _: &NamespaceIntent) -> Result<(), CloudError> {
        self.auth_checks.set(self.auth_checks.get() + 1);
        if self.revoked.get() {
            Err(CloudError::new(ErrorKind::Unauthorized, "revoked"))
        } else {
            Ok(())
        }
    }
    fn preflight(&self, _: &NamespaceIntent) -> Result<(), CloudError> {
        self.preflights.set(self.preflights.get() + 1);
        if self.preflight_error.get() {
            Err(CloudError::new(ErrorKind::Conflict, "preflight conflict"))
        } else {
            Ok(())
        }
    }
    fn rename(&self, dispatch: &FileRenameDispatch<'_>) -> Result<FileRenameSend, CloudError> {
        assert_eq!(dispatch.intent(), &intent());
        assert!(self.submitted.get(), "dispatch requires durable Submitted");
        self.sends.set(self.sends.get() + 1);
        match self.mode {
            SendMode::Renamed => Ok(FileRenameSend::Renamed),
            SendMode::Rejected(kind) => Ok(FileRenameSend::Rejected(CloudError::new(
                kind,
                "known rejection",
            ))),
            SendMode::Uncertain => Ok(FileRenameSend::Uncertain),
            SendMode::RevokeAfterSend => {
                self.revoked.set(true);
                Ok(FileRenameSend::Renamed)
            }
        }
    }
    fn observe(&self, intent: &NamespaceIntent) -> Result<FileRenameObservation, CloudError> {
        self.observations.set(self.observations.get() + 1);
        if matches!(self.observation, ObservationMode::Error) {
            return Err(CloudError::new(ErrorKind::Offline, "readback unavailable"));
        }
        let NamespaceOperation::MoveWithinScope {
            source,
            destination,
        } = &intent.operation
        else {
            panic!("test intent must be a file move");
        };
        let mut remote = source.remote.clone();
        remote.etag = "\"new-etag\"".into();
        match self.observation {
            ObservationMode::WrongId => remote.resource_id = "different-file".into(),
            ObservationMode::WrongLength => remote.byte_len += 1,
            ObservationMode::UrlId => remote.resource_id = "https://example.invalid/id".into(),
            _ => (),
        }
        Ok(FileRenameObservation {
            destination: NamespaceDestinationReport {
                destination: destination.clone(),
                remote,
                content: None,
            },
            source_absent: !matches!(self.observation, ObservationMode::SourcePresent),
        })
    }
}
fn remote_for(journal: &Journal) -> Remote {
    Remote::new(journal.submitted.clone())
}

#[derive(Clone, Copy)]
enum CompletionMode {
    Run,
    Unavailable,
    UncertainAfterClosure,
}
struct Local {
    admissions: Cell<usize>,
    fail_admission_at: Option<usize>,
    mode: CompletionMode,
    completion_calls: Cell<usize>,
}
impl Local {
    fn new() -> Self {
        Self {
            admissions: Cell::new(0),
            fail_admission_at: None,
            mode: CompletionMode::Run,
            completion_calls: Cell::new(0),
        }
    }
}
impl FileRenameLocal for Local {
    fn admit(&mut self, _: &NamespaceIntent) -> Result<(), CloudError> {
        self.admissions.set(self.admissions.get() + 1);
        if self.fail_admission_at == Some(self.admissions.get()) {
            Err(CloudError::new(ErrorKind::Conflict, "local fence changed"))
        } else {
            Ok(())
        }
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
        self.completion_calls.set(self.completion_calls.get() + 1);
        assert!(readback.source_absent());
        let NamespaceOperation::MoveWithinScope { destination, .. } = &intent.operation else {
            panic!("test intent must be a file move");
        };
        assert_eq!(&readback.destination().destination, destination);
        match self.mode {
            CompletionMode::Unavailable => Err(FileRenameCompletionError::Unavailable),
            CompletionMode::Run => record().map_err(FileRenameCompletionError::Store),
            CompletionMode::UncertainAfterClosure => {
                record().map_err(FileRenameCompletionError::Store)?;
                Err(FileRenameCompletionError::Uncertain)
            }
        }
    }
}

fn intent() -> NamespaceIntent {
    NamespaceIntent {
        schema_version: 1,
        record_id: "a".repeat(32),
        record_generation: 4,
        operation: NamespaceOperation::MoveWithinScope {
            source: ExistingNamespaceEntry {
                local: LocalNamespaceEntry {
                    parent: parent(),
                    name: "before.txt".into(),
                    local_file: LocalFileIdentity {
                        volume_serial: 1,
                        file_index: 9,
                    },
                    object_kind: NamespaceObjectKind::File,
                },
                remote: RemoteEditBaseline {
                    resource_id: "remote-file-id".into(),
                    etag: "\"old-etag\"".into(),
                    byte_len: 17,
                },
            },
            destination: LocalNamespaceEntry {
                parent: parent(),
                name: "after.txt".into(),
                local_file: LocalFileIdentity {
                    volume_serial: 1,
                    file_index: 9,
                },
                object_kind: NamespaceObjectKind::File,
            },
        },
    }
}
fn parent() -> NamespaceParent {
    NamespaceParent {
        scope: EditJournalScope {
            profile_id: "profile".into(),
            server_origin: "https://sync.example.invalid".into(),
            account_subject: "account".into(),
            space_id: "personal-space".into(),
            root_resource_id: "root-id".into(),
            root_volume_serial: 1,
            root_file_index: 2,
        },
        authorization: CapturedAuthorization {
            agent_generation: 4,
            token_generation: 7,
        },
        classification: StorageClassification::Ordinary,
        local_file: LocalFileIdentity {
            volume_serial: 1,
            file_index: 5,
        },
        local_components: vec!["Personal".into(), "Documents".into()],
        remote: RemoteEditBaseline {
            resource_id: "parent-id".into(),
            etag: "\"parent-etag\"".into(),
            byte_len: 0,
        },
    }
}

#[test]
fn recovered_pristine_history_has_no_fresh_publication_custody() {
    let mut journal = Journal::new(intent());
    journal.freshly_published_here = false;
    let remote = remote_for(&journal);
    let mut local = Local::new();
    assert_eq!(
        reconcile_file_rename(&mut journal, &remote, &mut local).unwrap(),
        FileRenameOutcome::Retained
    );
    assert_eq!(journal.progress().sequence, 0);
    assert!(journal.events.is_empty());
    assert_eq!(remote.auth_checks.get(), 0);
    assert_eq!(remote.sends.get(), 0);
    assert_eq!(local.admissions.get(), 0);
}

#[test]
fn successful_move_records_factual_order_and_one_send() {
    let mut journal = Journal::new(intent());
    let remote = remote_for(&journal);
    let mut local = Local::new();
    assert_eq!(
        reconcile_file_rename(&mut journal, &remote, &mut local).unwrap(),
        FileRenameOutcome::Completed
    );
    assert_eq!(remote.sends.get(), 1);
    assert_eq!(remote.preflights.get(), 1);
    assert_eq!(remote.observations.get(), 1);
    assert_eq!(local.admissions.get(), 3);
    assert_eq!(journal.events[0], NamespaceEventKind::RemoteSubmitted);
    assert!(matches!(
        &journal.events[1],
        NamespaceEventKind::RemoteVerified { .. }
    ));
    assert!(matches!(
        &journal.events[2],
        NamespaceEventKind::LocalCompleted { .. }
    ));
    assert!(matches!(
        &journal.events[3],
        NamespaceEventKind::SourceRemovalVerified { .. }
    ));
    assert_eq!(
        journal.progress().sequence,
        4,
        "Submitted, Verified, LocalCompleted, SourceRemovalVerified"
    );
    assert!(journal.progress().recorded_complete);
}

#[test]
fn preflight_conflict_is_durable_and_sends_nothing() {
    let mut journal = Journal::new(intent());
    let remote = remote_for(&journal);
    remote.preflight_error.set(true);
    let mut local = Local::new();
    assert_eq!(
        reconcile_file_rename(&mut journal, &remote, &mut local).unwrap(),
        FileRenameOutcome::Conflict
    );
    assert_eq!(remote.sends.get(), 0);
    assert_eq!(
        journal.progress().attention,
        Some(crate::namespace_intent::NamespaceAttention::Conflict)
    );
}

#[test]
fn known_forbidden_rejection_is_deferred_and_keeps_server_error_class() {
    let mut journal = Journal::new(intent());
    let mut remote = remote_for(&journal);
    remote.mode = SendMode::Rejected(ErrorKind::Forbidden);
    let mut local = Local::new();
    assert_eq!(
        reconcile_file_rename(&mut journal, &remote, &mut local).unwrap(),
        FileRenameOutcome::Deferred
    );
    assert_eq!(remote.sends.get(), 1);
    assert_eq!(remote.observations.get(), 0);
    assert_eq!(
        journal.progress().attention,
        Some(crate::namespace_intent::NamespaceAttention::Deferred)
    );
}

#[test]
fn failed_submitted_append_never_sends() {
    let mut journal = Journal::new(intent());
    journal.fail_append_at = Some(1);
    let remote = remote_for(&journal);
    let mut local = Local::new();
    assert_eq!(
        reconcile_file_rename(&mut journal, &remote, &mut local),
        Err(StoreError::Io)
    );
    assert_eq!(remote.sends.get(), 0);
    assert_eq!(journal.progress().sequence, 0);
    assert!(!journal.owns_fresh_publication());
    let prior_auth_checks = remote.auth_checks.get();
    let prior_admissions = local.admissions.get();
    assert_eq!(
        reconcile_file_rename(&mut journal, &remote, &mut local).unwrap(),
        FileRenameOutcome::Retained
    );
    assert_eq!(remote.sends.get(), 0);
    assert_eq!(remote.auth_checks.get(), prior_auth_checks);
    assert_eq!(local.admissions.get(), prior_admissions);
    assert_eq!(journal.append_count, 1);
}

#[test]
fn bad_readback_or_revocation_is_uncertain_and_never_replayed() {
    for (mode, observation) in [
        (SendMode::Renamed, ObservationMode::WrongId),
        (SendMode::Renamed, ObservationMode::WrongLength),
        (SendMode::Renamed, ObservationMode::SourcePresent),
        (SendMode::Renamed, ObservationMode::UrlId),
        (SendMode::Renamed, ObservationMode::Error),
        (SendMode::RevokeAfterSend, ObservationMode::Valid),
    ] {
        let mut journal = Journal::new(intent());
        let mut remote = remote_for(&journal);
        remote.mode = mode;
        remote.observation = observation;
        let mut local = Local::new();
        assert_eq!(
            reconcile_file_rename(&mut journal, &remote, &mut local).unwrap(),
            FileRenameOutcome::Uncertain
        );
        assert_eq!(remote.sends.get(), 1);
        assert_eq!(local.completion_calls.get(), 0);
        assert_eq!(
            reconcile_file_rename(&mut journal, &remote, &mut local).unwrap(),
            FileRenameOutcome::Retained
        );
        assert_eq!(remote.sends.get(), 1);
    }
}

#[test]
fn post_send_journal_failure_and_local_fence_refusal_preserve_prefix() {
    let mut journal = Journal::new(intent());
    journal.fail_append_at = Some(2);
    let remote = remote_for(&journal);
    let mut local = Local::new();
    assert_eq!(
        reconcile_file_rename(&mut journal, &remote, &mut local),
        Err(StoreError::Io)
    );
    assert_eq!(remote.sends.get(), 1);
    assert_eq!(local.completion_calls.get(), 0);
    assert_eq!(journal.progress().sequence, 1);
    assert_eq!(
        reconcile_file_rename(&mut journal, &remote, &mut local).unwrap(),
        FileRenameOutcome::Retained
    );
    assert_eq!(remote.sends.get(), 1);

    let mut journal = Journal::new(intent());
    let remote = remote_for(&journal);
    let mut local = Local::new();
    local.fail_admission_at = Some(2);
    assert_eq!(
        reconcile_file_rename(&mut journal, &remote, &mut local).unwrap(),
        FileRenameOutcome::Conflict
    );
    assert_eq!(remote.sends.get(), 0);
    assert_eq!(journal.progress().remote, NamespacePhase::Submitted);
}

#[test]
fn completion_refusal_keeps_remote_verified_and_invalid_shape_never_calls_adapters() {
    let mut journal = Journal::new(intent());
    let remote = remote_for(&journal);
    let mut local = Local::new();
    local.mode = CompletionMode::Unavailable;
    assert_eq!(
        reconcile_file_rename(&mut journal, &remote, &mut local).unwrap(),
        FileRenameOutcome::RemoteVerifiedLocalPending
    );
    assert_eq!(remote.sends.get(), 1);
    assert_eq!(journal.progress().remote, NamespacePhase::Verified);
    assert!(!journal.progress().local_completed);

    let mut unsupported = intent();
    let NamespaceOperation::MoveWithinScope {
        source,
        destination,
    } = &mut unsupported.operation
    else {
        unreachable!();
    };
    source.local.parent.local_components[0] = "Spaces".into();
    destination.parent.local_components[0] = "Spaces".into();
    let mut journal = Journal::new(unsupported);
    let remote = remote_for(&journal);
    let mut local = Local::new();
    assert_eq!(
        reconcile_file_rename(&mut journal, &remote, &mut local).unwrap(),
        FileRenameOutcome::Retained
    );
    assert_eq!(remote.auth_checks.get(), 0);
    assert_eq!(remote.preflights.get(), 0);
    assert_eq!(remote.sends.get(), 0);
    assert_eq!(local.admissions.get(), 0);

    let mut url_id_intent = intent();
    let NamespaceOperation::MoveWithinScope { source, .. } = &mut url_id_intent.operation else {
        unreachable!();
    };
    source.remote.resource_id = "HTTPS://example.invalid/id".into();
    let mut journal = Journal::new(url_id_intent);
    let remote = remote_for(&journal);
    let mut local = Local::new();
    assert_eq!(
        reconcile_file_rename(&mut journal, &remote, &mut local).unwrap(),
        FileRenameOutcome::Retained
    );
    assert_eq!(remote.auth_checks.get(), 0);
    assert_eq!(remote.sends.get(), 0);
}

#[test]
fn final_local_fence_refusal_preserves_verified_remote_without_completion() {
    let mut journal = Journal::new(intent());
    let remote = remote_for(&journal);
    let mut local = Local::new();
    local.fail_admission_at = Some(3);
    assert_eq!(
        reconcile_file_rename(&mut journal, &remote, &mut local).unwrap(),
        FileRenameOutcome::RemoteVerifiedLocalPending
    );
    assert_eq!(remote.sends.get(), 1);
    assert_eq!(journal.progress().remote, NamespacePhase::Verified);
    assert!(!journal.progress().local_completed);
    assert_eq!(local.completion_calls.get(), 0);
}

#[test]
fn completion_append_failure_keeps_partial_factual_prefix_and_no_resend() {
    for failed_append in [3, 4] {
        let mut journal = Journal::new(intent());
        journal.fail_append_at = Some(failed_append);
        let remote = remote_for(&journal);
        let mut local = Local::new();
        assert_eq!(
            reconcile_file_rename(&mut journal, &remote, &mut local),
            Err(StoreError::Io)
        );
        assert_eq!(remote.sends.get(), 1);
        assert_eq!(journal.progress().sequence, (failed_append - 1) as u64);
        assert_eq!(journal.progress().local_completed, failed_append == 4);
        assert_eq!(
            journal.progress().source_removal,
            Some(NamespacePhase::Pending)
        );
        assert_eq!(
            reconcile_file_rename(&mut journal, &remote, &mut local).unwrap(),
            FileRenameOutcome::Retained
        );
        assert_eq!(remote.sends.get(), 1);
    }
}

#[test]
fn mismatched_context_or_unsupported_shape_never_calls_adapters() {
    for variant in 0..8 {
        let mut journal = Journal::new(intent());
        let NamespaceOperation::MoveWithinScope {
            source,
            destination,
        } = &mut journal.intent.operation
        else {
            unreachable!();
        };
        match variant {
            0 => destination.parent.scope.account_subject.push('x'),
            1 => destination.parent.scope.root_file_index += 1,
            2 => destination.parent.authorization.token_generation += 1,
            3 => destination.local_file.file_index += 1,
            4 => destination.object_kind = NamespaceObjectKind::Directory,
            5 => source.local.parent.classification = StorageClassification::Encrypted,
            6 => destination.parent.local_components.push("Elsewhere".into()),
            _ => destination.name = source.local.name.to_ascii_uppercase(),
        }
        let remote = remote_for(&journal);
        let mut local = Local::new();
        assert_eq!(
            reconcile_file_rename(&mut journal, &remote, &mut local).unwrap(),
            FileRenameOutcome::Retained
        );
        assert_eq!(remote.auth_checks.get(), 0);
        assert_eq!(remote.sends.get(), 0);
        assert_eq!(local.admissions.get(), 0);
        assert!(journal.events.is_empty());
    }
}

#[test]
fn uncertain_send_and_unavailable_completion_keep_their_factual_frontiers() {
    let mut journal = Journal::new(intent());
    let mut remote = remote_for(&journal);
    remote.mode = SendMode::Uncertain;
    let mut local = Local::new();
    assert_eq!(
        reconcile_file_rename(&mut journal, &remote, &mut local).unwrap(),
        FileRenameOutcome::Uncertain
    );
    assert_eq!(remote.sends.get(), 1);
    assert_eq!(remote.observations.get(), 0);
    assert_eq!(
        journal.progress().attention,
        Some(crate::namespace_intent::NamespaceAttention::Uncertain)
    );

    let mut journal = Journal::new(intent());
    let remote = remote_for(&journal);
    let mut local = Local::new();
    local.mode = CompletionMode::UncertainAfterClosure;
    assert_eq!(
        reconcile_file_rename(&mut journal, &remote, &mut local).unwrap(),
        FileRenameOutcome::Uncertain
    );
    assert!(journal.progress().recorded_complete);
    assert_eq!(
        reconcile_file_rename(&mut journal, &remote, &mut local).unwrap(),
        FileRenameOutcome::Retained
    );
    assert_eq!(remote.sends.get(), 1);
}
