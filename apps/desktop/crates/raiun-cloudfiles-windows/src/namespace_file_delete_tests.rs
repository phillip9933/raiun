use super::*;
use crate::namespace_intent::{
    CapturedAuthorization, LocalNamespaceEntry, NamespaceEvent, NamespaceParent,
};
use crate::{EditJournalScope, LocalFileIdentity, RemoteEditBaseline};
use std::{cell::Cell, rc::Rc};

// Portable seam fixtures only: this is not a persistent/DPAPI journal or SDK ACK.
struct Journal {
    intent: NamespaceIntent,
    check: NamespaceIntentProgress,
    events: Vec<NamespaceEventKind>,
    fresh_user_delete: bool,
    fail_submission: bool,
    submitted: Rc<Cell<bool>>,
}
impl Journal {
    fn new() -> Self {
        let intent = intent();
        Self {
            check: NamespaceIntentProgress::new(intent.clone()).unwrap(),
            intent,
            events: vec![],
            fresh_user_delete: true,
            fail_submission: false,
            submitted: Rc::new(Cell::new(false)),
        }
    }
}
impl FileDeleteJournal for Journal {
    fn owns_fresh_user_delete(&self) -> bool {
        self.fresh_user_delete
    }
    fn intent(&self) -> &NamespaceIntent {
        &self.intent
    }
    fn progress(&self) -> NamespaceProgressSnapshot {
        self.check.snapshot()
    }
    fn append_event(&mut self, event: NamespaceEventKind) -> Result<(), StoreError> {
        if self.fail_submission && matches!(event, NamespaceEventKind::RemoteSubmitted) {
            self.fresh_user_delete = false;
            return Err(StoreError::Io);
        }
        let result = self.check.record(&NamespaceEvent {
            context: self.intent.event_context().unwrap(),
            sequence: self.check.snapshot().sequence + 1,
            event: event.clone(),
        });
        if result.is_err() {
            self.fresh_user_delete = false;
            return Err(StoreError::CorruptEvidence);
        }
        if matches!(event, NamespaceEventKind::RemoteSubmitted) {
            self.submitted.set(true);
        }
        self.events.push(event);
        Ok(())
    }
}
#[derive(Clone, Copy)]
enum Mode {
    Success,
    StaleAtSend,
    CancelBeforeSend,
    ResponseLost,
    RepeatedGuardAfterSend,
}
struct Remote {
    original: ExistingNamespaceEntry,
    mode: Mode,
    authorized: Cell<bool>,
    present: Cell<bool>,
    sends: Cell<usize>,
    observations: Cell<usize>,
    submitted: Rc<Cell<bool>>,
}
impl Remote {
    fn new(journal: &Journal, mode: Mode) -> Self {
        Self {
            original: source(journal.intent()).unwrap().clone(),
            mode,
            authorized: Cell::new(true),
            present: Cell::new(true),
            sends: Cell::new(0),
            observations: Cell::new(0),
            submitted: journal.submitted.clone(),
        }
    }
}
impl FileDeleteRemote for Remote {
    fn ensure_authorized(&self, _: &NamespaceIntent) -> Result<(), CloudError> {
        if self.authorized.get() {
            Ok(())
        } else {
            Err(unavailable())
        }
    }
    fn preflight(&self, _: &NamespaceIntent) -> Result<ExistingNamespaceEntry, CloudError> {
        assert!(self.present.get());
        Ok(self.original.clone())
    }
    fn delete_with_send_guard(
        &self,
        dispatch: &FileDeleteDispatch<'_>,
        guard: &mut dyn FnMut() -> Result<(), CloudError>,
    ) -> Result<FileDeleteSend, CloudError> {
        assert!(
            self.submitted.get(),
            "no request before submitted journal event"
        );
        assert_eq!(source(dispatch.intent()), Some(&self.original));
        if matches!(self.mode, Mode::CancelBeforeSend) {
            self.authorized.set(false);
        }
        guard()?;
        self.sends.set(self.sends.get() + 1);
        if matches!(self.mode, Mode::StaleAtSend) {
            // Server refuses the original If-Match; the newer object survives.
            return Ok(FileDeleteSend::Rejected(CloudError::new(
                ErrorKind::Conflict,
                "synthetic ETag mismatch",
            )));
        }
        self.present.set(false);
        if matches!(self.mode, Mode::RepeatedGuardAfterSend) {
            // Malformed adapter: a later guard refusal follows an actual send.
            guard()?;
        }
        if matches!(self.mode, Mode::ResponseLost) {
            return Ok(FileDeleteSend::Uncertain);
        }
        Ok(FileDeleteSend::Deleted)
    }
    fn observe_absence(&self, _: &NamespaceIntent) -> Result<FileDeleteAbsence, CloudError> {
        self.observations.set(self.observations.get() + 1);
        Ok(FileDeleteAbsence {
            source: self.original.clone(),
            original_path_absent: !self.present.get(),
        })
    }
}
struct Local {
    original: ExistingNamespaceEntry,
    dirty: bool,
    pending: bool,
    completions: usize,
}
impl Local {
    fn new(journal: &Journal) -> Self {
        Self {
            original: source(journal.intent()).unwrap().clone(),
            dirty: false,
            pending: false,
            completions: 0,
        }
    }
}
impl FileDeleteLocal for Local {
    fn observe_clean(
        &mut self,
        _: &NamespaceIntent,
    ) -> Result<FileDeleteLocalObservation, CloudError> {
        Ok(FileDeleteLocalObservation {
            source: self.original.clone(),
            ancestry: StorageClassification::Ordinary,
            dirty: self.dirty,
            pending: self.pending,
        })
    }
    fn record_completion<F>(
        &mut self,
        _: &NamespaceIntent,
        readback: &FileDeleteReadback,
        record: F,
    ) -> Result<(), FileDeleteCompletionError>
    where
        F: FnOnce() -> Result<(), StoreError>,
    {
        assert_eq!(readback.source(), &self.original);
        if self.dirty || self.pending {
            return Err(FileDeleteCompletionError::Unavailable);
        }
        record().map_err(FileDeleteCompletionError::Store)?;
        self.completions += 1;
        Ok(())
    }
}
fn intent() -> NamespaceIntent {
    NamespaceIntent {
        schema_version: 1,
        record_id: "d".repeat(32),
        record_generation: 4,
        operation: NamespaceOperation::DeleteFile {
            source: ExistingNamespaceEntry {
                local: LocalNamespaceEntry {
                    parent: NamespaceParent {
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
                    },
                    name: "document.txt".into(),
                    local_file: LocalFileIdentity {
                        volume_serial: 1,
                        file_index: 9,
                    },
                    object_kind: NamespaceObjectKind::File,
                },
                remote: RemoteEditBaseline {
                    resource_id: "file-id".into(),
                    etag: "\"original-etag\"".into(),
                    byte_len: 17,
                },
            },
        },
    }
}

#[test]
fn success_requires_submitted_then_qualified_absence_before_local_receipt() {
    let mut journal = Journal::new();
    let remote = Remote::new(&journal, Mode::Success);
    let mut local = Local::new(&journal);
    assert_eq!(
        reconcile_file_delete(&mut journal, &remote, &mut local).unwrap(),
        FileDeleteOutcome::Completed
    );
    assert_eq!(remote.sends.get(), 1);
    assert_eq!(remote.observations.get(), 1);
    assert!(!remote.present.get());
    assert_eq!(local.completions, 1);
    assert!(matches!(
        journal.events.as_slice(),
        [
            NamespaceEventKind::RemoteSubmitted,
            NamespaceEventKind::RemoteDeleted { .. },
            NamespaceEventKind::LocalDeleted { .. }
        ]
    ));
    assert!(journal.progress().recorded_complete);
    // A failed durable submission must leave the remote file untouched.
    let mut failed = Journal::new();
    failed.fail_submission = true;
    let remote = Remote::new(&failed, Mode::Success);
    let mut local = Local::new(&failed);
    assert_eq!(
        reconcile_file_delete(&mut failed, &remote, &mut local),
        Err(StoreError::Io)
    );
    assert_eq!(remote.sends.get(), 0);
    assert!(remote.present.get());
    assert!(!failed.owns_fresh_user_delete());
}
#[test]
fn stale_etag_preserves_remote_file_and_never_completes_local_delete() {
    let mut journal = Journal::new();
    let remote = Remote::new(&journal, Mode::StaleAtSend);
    let mut local = Local::new(&journal);
    assert_eq!(
        reconcile_file_delete(&mut journal, &remote, &mut local).unwrap(),
        FileDeleteOutcome::Conflict
    );
    assert!(remote.present.get());
    assert_eq!(remote.sends.get(), 1);
    assert_eq!(remote.observations.get(), 0);
    assert_eq!(local.completions, 0);
    assert_eq!(
        reconcile_file_delete(&mut journal, &remote, &mut local).unwrap(),
        FileDeleteOutcome::Retained
    );
    assert_eq!(remote.sends.get(), 1);
}
#[test]
fn dirty_or_pending_edit_refuses_before_dispatch_and_preserves_bytes() {
    for pending in [false, true] {
        let mut journal = Journal::new();
        let remote = Remote::new(&journal, Mode::Success);
        let mut local = Local::new(&journal);
        local.dirty = !pending;
        local.pending = pending;
        assert_eq!(
            reconcile_file_delete(&mut journal, &remote, &mut local).unwrap(),
            FileDeleteOutcome::Deferred
        );
        assert!(remote.present.get());
        assert_eq!(remote.sends.get(), 0);
        assert!(!journal.submitted.get());
        assert_eq!(local.completions, 0);
    }
}
#[test]
fn cancellation_at_send_boundary_leaves_submitted_history_without_sending() {
    let mut journal = Journal::new();
    let remote = Remote::new(&journal, Mode::CancelBeforeSend);
    let mut local = Local::new(&journal);
    assert_eq!(
        reconcile_file_delete(&mut journal, &remote, &mut local).unwrap(),
        FileDeleteOutcome::Deferred
    );
    assert!(journal.submitted.get());
    assert!(remote.present.get());
    assert_eq!(remote.sends.get(), 0);
    assert_eq!(local.completions, 0);
    remote.authorized.set(true);
    assert_eq!(
        reconcile_file_delete(&mut journal, &remote, &mut local).unwrap(),
        FileDeleteOutcome::Retained
    );
    assert_eq!(remote.sends.get(), 0);
}
#[test]
fn lost_delete_response_retains_uncertainty_without_absence_adoption_or_replay() {
    for mode in [Mode::ResponseLost, Mode::RepeatedGuardAfterSend] {
        let mut journal = Journal::new();
        let remote = Remote::new(&journal, mode);
        let mut local = Local::new(&journal);
        assert_eq!(
            reconcile_file_delete(&mut journal, &remote, &mut local).unwrap(),
            FileDeleteOutcome::Uncertain
        );
        assert!(!remote.present.get());
        assert_eq!(remote.sends.get(), 1);
        assert_eq!(remote.observations.get(), 0);
        assert_eq!(local.completions, 0);
        assert!(matches!(
            journal.events.as_slice(),
            [
                NamespaceEventKind::RemoteSubmitted,
                NamespaceEventKind::Uncertain
            ]
        ));
        assert_eq!(
            reconcile_file_delete(&mut journal, &remote, &mut local).unwrap(),
            FileDeleteOutcome::Retained
        );
        journal.fresh_user_delete = false; // Reopened authenticated history has no live custody.
        assert_eq!(
            reconcile_file_delete(&mut journal, &remote, &mut local).unwrap(),
            FileDeleteOutcome::Retained
        );
        assert_eq!(remote.sends.get(), 1);
        assert_eq!(remote.observations.get(), 0);
    }
}
#[test]
fn eviction_origin_cannot_obtain_user_delete_dispatch_even_with_matching_metadata() {
    let mut journal = Journal::new();
    // Provider cleanup/eviction cannot attest explicit fresh user-delete custody.
    journal.fresh_user_delete = false;
    let remote = Remote::new(&journal, Mode::Success);
    let mut local = Local::new(&journal);
    assert_eq!(
        reconcile_file_delete(&mut journal, &remote, &mut local).unwrap(),
        FileDeleteOutcome::Retained
    );
    assert!(journal.events.is_empty());
    assert!(remote.present.get());
    assert_eq!(remote.sends.get(), 0);
    assert_eq!(remote.observations.get(), 0);
    assert_eq!(local.completions, 0);
}
