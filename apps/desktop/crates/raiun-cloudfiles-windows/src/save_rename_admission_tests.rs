use super::*;
use crate::{
    EditJournalScope, LocalFileIdentity, RemoteEditBaseline,
    close_capture_admission::CloseCaptureAdmission,
    namespace_file_rename::{FileRenameJournal, FileRenameOutcome, reconcile_file_rename},
    namespace_intent::{
        CapturedAuthorization, ExistingNamespaceEntry, LocalNamespaceEntry,
        NamespaceDestinationReport, NamespaceEvent, NamespaceEventKind, NamespaceIntentProgress,
        NamespaceObjectKind, NamespaceOperation, NamespaceParent, NamespacePhase,
        NamespaceProgressSnapshot, StorageClassification,
    },
};
use raiun_core::backend::{CloudError, ErrorKind};
use std::{cell::Cell, rc::Rc};

fn intent() -> NamespaceIntent {
    NamespaceIntent {
        schema_version: 1,
        record_id: "b".repeat(32),
        record_generation: 7,
        operation: NamespaceOperation::MoveWithinScope {
            source: ExistingNamespaceEntry {
                local: LocalNamespaceEntry {
                    parent: parent(),
                    name: "source.txt".into(),
                    local_file: LocalFileIdentity {
                        volume_serial: 2,
                        file_index: 17,
                    },
                    object_kind: NamespaceObjectKind::File,
                },
                remote: RemoteEditBaseline {
                    resource_id: "remote-file".into(),
                    etag: "\"v1\"".into(),
                    byte_len: 5,
                },
            },
            destination: LocalNamespaceEntry {
                parent: parent(),
                name: "renamed.txt".into(),
                local_file: LocalFileIdentity {
                    volume_serial: 2,
                    file_index: 17,
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
            space_id: "personal".into(),
            root_resource_id: "root".into(),
            root_volume_serial: 2,
            root_file_index: 3,
        },
        authorization: CapturedAuthorization {
            agent_generation: 9,
            token_generation: 11,
        },
        classification: StorageClassification::Ordinary,
        local_file: LocalFileIdentity {
            volume_serial: 2,
            file_index: 12,
        },
        local_components: vec!["Personal".into(), "Folder".into()],
        remote: RemoteEditBaseline {
            resource_id: "parent".into(),
            etag: "\"parent-v1\"".into(),
            byte_len: 0,
        },
    }
}

struct Journal {
    intent: NamespaceIntent,
    progress: NamespaceIntentProgress,
    events: Vec<NamespaceEventKind>,
    owns_fresh: bool,
    submitted: Rc<Cell<bool>>,
}

impl Journal {
    fn new(intent: NamespaceIntent, submitted: Rc<Cell<bool>>) -> Self {
        Self {
            progress: NamespaceIntentProgress::new(intent.clone()).unwrap(),
            intent,
            events: Vec::new(),
            owns_fresh: true,
            submitted,
        }
    }
}

impl FileRenameJournal for Journal {
    fn owns_fresh_publication(&self) -> bool {
        self.owns_fresh
    }

    fn intent(&self) -> &NamespaceIntent {
        &self.intent
    }

    fn progress(&self) -> NamespaceProgressSnapshot {
        self.progress.snapshot()
    }

    fn append_event(&mut self, event: NamespaceEventKind) -> Result<(), StoreError> {
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
    }
}

struct Remote<'a> {
    tracker: &'a CloseCaptureAdmission,
    submitted: Rc<Cell<bool>>,
    invalidate_preflight: bool,
    close_after_send_claim: bool,
    sends: Cell<usize>,
    observations: Cell<usize>,
    legacy_sends: Cell<usize>,
}

impl<'a> Remote<'a> {
    fn new(tracker: &'a CloseCaptureAdmission, submitted: Rc<Cell<bool>>) -> Self {
        Self {
            tracker,
            submitted,
            invalidate_preflight: false,
            close_after_send_claim: false,
            sends: Cell::new(0),
            observations: Cell::new(0),
            legacy_sends: Cell::new(0),
        }
    }

    fn invalidate_by_dirty_close(&self) {
        let mut close = self.tracker.begin_close();
        close.mark_dirty_before_capture();
        close.finish_durable();
    }
}

impl FileRenameRemote for Remote<'_> {
    fn ensure_authorized(&self, _: &NamespaceIntent) -> Result<(), CloudError> {
        Ok(())
    }

    fn preflight(&self, _: &NamespaceIntent) -> Result<(), CloudError> {
        if self.invalidate_preflight {
            self.invalidate_by_dirty_close();
        }
        Ok(())
    }

    fn rename(&self, _: &FileRenameDispatch<'_>) -> Result<FileRenameSend, CloudError> {
        self.legacy_sends.set(self.legacy_sends.get() + 1);
        Ok(FileRenameSend::Renamed)
    }

    fn rename_with_send_guard(
        &self,
        dispatch: &FileRenameDispatch<'_>,
        before_send: &mut dyn FnMut() -> Result<(), CloudError>,
    ) -> Result<FileRenameSend, CloudError> {
        assert!(
            self.submitted.get(),
            "RemoteSubmitted must precede the guarded send"
        );
        assert_eq!(dispatch.intent(), &intent());
        before_send()?;
        self.sends.set(self.sends.get() + 1);
        if self.close_after_send_claim {
            self.invalidate_by_dirty_close();
        }
        Ok(FileRenameSend::Renamed)
    }

    fn observe(&self, intent: &NamespaceIntent) -> Result<FileRenameObservation, CloudError> {
        self.observations.set(self.observations.get() + 1);
        let NamespaceOperation::MoveWithinScope {
            source,
            destination,
        } = &intent.operation
        else {
            return Err(CloudError::new(ErrorKind::Conflict, "wrong operation"));
        };
        let mut remote = source.remote.clone();
        remote.etag = "\"v2\"".into();
        Ok(FileRenameObservation {
            destination: NamespaceDestinationReport {
                destination: destination.clone(),
                remote,
                content: None,
            },
            source_absent: true,
        })
    }
}

struct LegacyOnlyRemote<'a>(Remote<'a>);

impl FileRenameRemote for LegacyOnlyRemote<'_> {
    fn ensure_authorized(&self, intent: &NamespaceIntent) -> Result<(), CloudError> {
        self.0.ensure_authorized(intent)
    }
    fn preflight(&self, intent: &NamespaceIntent) -> Result<(), CloudError> {
        self.0.preflight(intent)
    }
    fn rename(&self, dispatch: &FileRenameDispatch<'_>) -> Result<FileRenameSend, CloudError> {
        self.0.rename(dispatch)
    }
    fn observe(&self, intent: &NamespaceIntent) -> Result<FileRenameObservation, CloudError> {
        self.0.observe(intent)
    }
}

struct Local<'a> {
    completions: Cell<usize>,
    close_before_record: Option<&'a CloseCaptureAdmission>,
}

impl<'a> Local<'a> {
    fn new() -> Self {
        Self {
            completions: Cell::new(0),
            close_before_record: None,
        }
    }

    fn with_late_close(tracker: &'a CloseCaptureAdmission) -> Self {
        Local {
            completions: Cell::new(0),
            close_before_record: Some(tracker),
        }
    }
}

impl FileRenameLocal for Local<'_> {
    fn admit(&mut self, _: &NamespaceIntent) -> Result<(), CloudError> {
        Ok(())
    }

    fn record_completion<F>(
        &mut self,
        _: &NamespaceIntent,
        _: &FileRenameReadback,
        record: F,
    ) -> Result<(), FileRenameCompletionError>
    where
        F: FnOnce() -> Result<(), StoreError>,
    {
        self.completions.set(self.completions.get() + 1);
        if let Some(tracker) = self.close_before_record {
            let mut close = tracker.begin_close();
            close.mark_dirty_before_capture();
            close.finish_durable();
        }
        record().map_err(FileRenameCompletionError::Store)
    }
}

fn fresh_admission(tracker: &CloseCaptureAdmission) -> SaveRenameAdmission<'_> {
    SaveRenameAdmission::new(
        tracker
            .try_begin_rename()
            .expect("no close or prior rename attempt is active"),
    )
}

fn run(
    admission: &SaveRenameAdmission<'_>,
    journal: &mut Journal,
    remote: &Remote<'_>,
    local: &mut Local<'_>,
) -> Result<FileRenameOutcome, StoreError> {
    let guarded_remote = GuardedRemote { remote, admission };
    let mut guarded_local = GuardedLocal { local, admission };
    reconcile_file_rename(journal, &guarded_remote, &mut guarded_local)
}

fn fixture<'a>(tracker: &'a CloseCaptureAdmission) -> (Journal, Remote<'a>) {
    let submitted = Rc::new(Cell::new(false));
    (
        Journal::new(intent(), Rc::clone(&submitted)),
        Remote::new(tracker, submitted),
    )
}

#[test]
fn r55_pending_or_unknown_health_does_not_enter_rename_coordinator() {
    for health in [Ok(true), Err(())] {
        let tracker = CloseCaptureAdmission::default();
        let admission = fresh_admission(&tracker);
        let (mut journal, remote) = fixture(&tracker);
        let mut local = Local::new();
        let mut entered = false;
        if admission.probe_clean(|| health) {
            entered = true;
            let _ = run(&admission, &mut journal, &remote, &mut local);
        }
        assert!(!entered);
        assert!(journal.events.is_empty());
        assert_eq!(remote.sends.get(), 0);
        assert_eq!(local.completions.get(), 0);
    }
}

#[test]
fn r55_health_wait_invalidation_refuses_ticket_and_no_replacement_ticket() {
    let tracker = CloseCaptureAdmission::default();
    let admission = fresh_admission(&tracker);
    let (journal, remote) = fixture(&tracker);
    let local = Local::new();
    let clean = admission.probe_clean(|| {
        let mut close = tracker.begin_close();
        close.mark_dirty_before_capture();
        close.finish_durable();
        Ok::<_, ()>(false)
    });
    assert!(!clean);
    assert!(admission.check().is_err());
    assert!(tracker.try_begin_rename().is_none());
    assert!(journal.events.is_empty());
    assert_eq!(remote.sends.get(), 0);
    assert_eq!(local.completions.get(), 0);
}

#[test]
fn r55_close_during_remote_preflight_blocks_send_and_replacement() {
    let tracker = CloseCaptureAdmission::default();
    let admission = fresh_admission(&tracker);
    assert!(admission.probe_clean(|| Ok::<_, ()>(false)));
    let (mut journal, mut remote) = fixture(&tracker);
    remote.invalidate_preflight = true;
    let mut local = Local::new();
    let outcome = run(&admission, &mut journal, &remote, &mut local).unwrap();
    assert_eq!(outcome, FileRenameOutcome::Deferred);
    assert_eq!(remote.sends.get(), 0);
    assert_eq!(local.completions.get(), 0);
    assert_eq!(journal.progress().sequence, 1);
    assert!(matches!(
        journal.events.as_slice(),
        [NamespaceEventKind::Deferred]
    ));
    assert!(admission.check().is_err());
    assert!(tracker.try_begin_rename().is_none());
}

#[test]
fn r55_close_after_send_claim_is_uncertain_without_local_ack() {
    let tracker = CloseCaptureAdmission::default();
    let admission = fresh_admission(&tracker);
    assert!(admission.probe_clean(|| Ok::<_, ()>(false)));
    let (mut journal, mut remote) = fixture(&tracker);
    remote.close_after_send_claim = true;
    let mut local = Local::new();
    let outcome = run(&admission, &mut journal, &remote, &mut local).unwrap();
    assert_eq!(outcome, FileRenameOutcome::Uncertain);
    assert_eq!(remote.sends.get(), 1);
    assert_eq!(remote.observations.get(), 0);
    assert_eq!(local.completions.get(), 0);
    assert_eq!(journal.progress().sequence, 2);
    assert!(matches!(
        journal.events.as_slice(),
        [
            NamespaceEventKind::RemoteSubmitted,
            NamespaceEventKind::Uncertain
        ]
    ));
}

#[test]
fn r55_quiescent_ticket_completes_with_one_send_and_completion_claim() {
    let tracker = CloseCaptureAdmission::default();
    let admission = fresh_admission(&tracker);
    assert!(admission.probe_clean(|| Ok::<_, ()>(false)));
    let (mut journal, remote) = fixture(&tracker);
    let mut local = Local::new();
    assert_eq!(
        run(&admission, &mut journal, &remote, &mut local).unwrap(),
        FileRenameOutcome::Completed
    );
    assert_eq!(remote.sends.get(), 1);
    assert_eq!(remote.observations.get(), 1);
    assert_eq!(local.completions.get(), 1);
    assert_eq!(journal.progress().sequence, 4);
    assert!(journal.progress().recorded_complete);
    assert!(
        admission.check().is_ok(),
        "post-append authority remains current"
    );
    assert!(admission.claim_send().is_err(), "dispatch claim is one-use");
    assert!(
        admission.claim_completion().is_err(),
        "completion claim is one-use"
    );
}

#[test]
fn r55_late_close_before_ack_refuses_completion_claim_and_preserves_verified_prefix() {
    let tracker = CloseCaptureAdmission::default();
    let admission = fresh_admission(&tracker);
    assert!(admission.probe_clean(|| Ok::<_, ()>(false)));
    let (mut journal, remote) = fixture(&tracker);
    let mut local = Local::with_late_close(&tracker);
    assert_eq!(
        run(&admission, &mut journal, &remote, &mut local).unwrap(),
        FileRenameOutcome::RemoteVerifiedLocalPending
    );
    assert_eq!(remote.sends.get(), 1);
    assert_eq!(remote.observations.get(), 1);
    assert_eq!(local.completions.get(), 1);
    assert_eq!(journal.progress().sequence, 2);
    assert_eq!(journal.progress().remote, NamespacePhase::Verified);
    assert!(!journal.progress().local_completed);
    assert!(!journal.progress().recorded_complete);
    assert!(matches!(
        journal.events.as_slice(),
        [
            NamespaceEventKind::RemoteSubmitted,
            NamespaceEventKind::RemoteVerified { .. }
        ]
    ));
}

#[test]
fn r55_guarded_default_never_falls_back_to_legacy_rename() {
    let tracker = CloseCaptureAdmission::default();
    let admission = fresh_admission(&tracker);
    let (mut journal, remote_inner) = fixture(&tracker);
    let remote = LegacyOnlyRemote(remote_inner);
    let mut local = Local::new();
    let guarded_remote = GuardedRemote {
        remote: &remote,
        admission: &admission,
    };
    let mut guarded_local = GuardedLocal {
        local: &mut local,
        admission: &admission,
    };
    assert_eq!(
        reconcile_file_rename(&mut journal, &guarded_remote, &mut guarded_local).unwrap(),
        FileRenameOutcome::Deferred
    );
    assert_eq!(remote.0.legacy_sends.get(), 0);
    assert_eq!(remote.0.sends.get(), 0);
    assert_eq!(local.completions.get(), 0);
    assert_eq!(journal.progress().sequence, 2);
}
