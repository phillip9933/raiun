use super::*;
use crate::namespace_file_rename::{FileRenameCompletionError, FileRenameJournal, FileRenameLocal};

struct FailAtSequenceJournal {
    inner: Journal,
    fail_sequence: u64,
}

impl FailAtSequenceJournal {
    fn new(intent: NamespaceIntent, fail_sequence: u64) -> Self {
        Self {
            inner: Journal::new(intent),
            fail_sequence,
        }
    }
}

impl FileRenameJournal for FailAtSequenceJournal {
    fn owns_fresh_publication(&self) -> bool {
        self.inner.owns_fresh_publication()
    }

    fn intent(&self) -> &NamespaceIntent {
        self.inner.intent()
    }

    fn progress(&self) -> crate::namespace_intent::NamespaceProgressSnapshot {
        self.inner.progress()
    }

    fn append_event(&mut self, event: NamespaceEventKind) -> Result<(), StoreError> {
        if self.inner.progress().sequence + 1 == self.fail_sequence {
            return Err(StoreError::Busy);
        }
        self.inner.append_event(event)
    }
}

#[derive(Clone, Copy)]
enum CallbackMode {
    Record,
    Unavailable,
    Uncertain,
    RevokeAfterRecord,
}

struct TypedCompletionLocal<'session, 'backend> {
    session: &'session FileRenameSession<'backend>,
    calls: Arc<AtomicUsize>,
    owner_live: Arc<AtomicBool>,
    mode: CallbackMode,
}

impl FileRenameLocal for TypedCompletionLocal<'_, '_> {
    fn admit(&mut self, _: &NamespaceIntent) -> Result<(), raiun_core::backend::CloudError> {
        Ok(())
    }

    fn record_completion<F>(
        &mut self,
        _: &NamespaceIntent,
        readback: &FileRenameReadback,
        record: F,
    ) -> Result<(), FileRenameCompletionError>
    where
        F: FnOnce() -> Result<(), StoreError>,
    {
        let capability = self
            .session
            .prepare_verified_file_rename(readback)
            .map_err(|_| FileRenameCompletionError::Unavailable)?;
        let calls = self.calls.clone();
        let owner_live = self.owner_live.clone();
        let mode = self.mode;
        capability.publish_file_rename_completion(move || {
            calls.fetch_add(1, Ordering::AcqRel);
            match mode {
                CallbackMode::Record => record().map_err(FileRenameCompletionError::Store),
                CallbackMode::Unavailable => Err(FileRenameCompletionError::Unavailable),
                CallbackMode::Uncertain => Err(FileRenameCompletionError::Uncertain),
                CallbackMode::RevokeAfterRecord => {
                    record().map_err(FileRenameCompletionError::Store)?;
                    owner_live.store(false, Ordering::Release);
                    Ok(())
                }
            }
        })
    }
}

fn run_with_typed_completion<J: FileRenameJournal>(
    fixture: &Fixture,
    journal: &mut J,
    mode: CallbackMode,
) -> (Result<FileRenameOutcome, StoreError>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let owner_live = fixture.owner_live.clone();
    let outcome = fixture
        .backend
        .with_file_rename_session(
            &fixture.intent,
            fixture.parent,
            &|auth| auth.agent_generation == 3 && owner_live.load(Ordering::Acquire),
            |session| {
                let mut local = TypedCompletionLocal {
                    session,
                    calls: calls.clone(),
                    owner_live: owner_live.clone(),
                    mode,
                };
                reconcile_file_rename(journal, session.remote(), &mut local)
            },
        )
        .map_err(|_| StoreError::CorruptEvidence)
        .and_then(|result| result);
    (outcome, calls)
}

#[test]
fn completion_typed_store_error_preserves_exact_factual_prefix() {
    let mut fixture = Fixture::new();
    let mut journal = FailAtSequenceJournal::new(fixture.intent.clone(), 4);
    let (outcome, calls) = run_with_typed_completion(&fixture, &mut journal, CallbackMode::Record);

    assert_eq!(outcome, Err(StoreError::Busy));
    assert_eq!(calls.load(Ordering::Acquire), 1);
    assert_eq!(fixture.moves.load(Ordering::Acquire), 1);
    assert_eq!(journal.inner.events.len(), 3);
    assert!(matches!(
        journal.inner.events[0],
        NamespaceEventKind::RemoteSubmitted
    ));
    assert!(matches!(
        journal.inner.events[1],
        NamespaceEventKind::RemoteVerified { .. }
    ));
    assert!(matches!(
        journal.inner.events[2],
        NamespaceEventKind::LocalCompleted { .. }
    ));
    let progress = journal.inner.progress.snapshot();
    assert_eq!(progress.remote, NamespacePhase::Verified);
    assert!(progress.local_completed);
    assert!(!progress.recorded_complete);
    fixture.finish();
}

#[test]
fn completion_typed_callback_errors_preserve_their_kind_without_final_events() {
    for (mode, expected) in [
        (
            CallbackMode::Unavailable,
            FileRenameOutcome::RemoteVerifiedLocalPending,
        ),
        (CallbackMode::Uncertain, FileRenameOutcome::Uncertain),
    ] {
        let mut fixture = Fixture::new();
        let mut journal = Journal::new(fixture.intent.clone());
        let (outcome, calls) = run_with_typed_completion(&fixture, &mut journal, mode);

        assert_eq!(outcome, Ok(expected));
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(fixture.moves.load(Ordering::Acquire), 1);
        assert_eq!(journal.events.len(), 2);
        assert_eq!(journal.progress.snapshot().remote, NamespacePhase::Verified);
        assert!(!journal.progress.snapshot().local_completed);
        fixture.finish();
    }
}

#[test]
fn completion_catalog_rejection_is_unavailable_before_callback() {
    let mut fixture = Fixture::new();
    fixture.catalog.fail_next.store(1, Ordering::Release);
    let mut journal = Journal::new(fixture.intent.clone());
    let (outcome, calls) = run_with_typed_completion(&fixture, &mut journal, CallbackMode::Record);

    assert_eq!(outcome, Ok(FileRenameOutcome::RemoteVerifiedLocalPending));
    assert_eq!(calls.load(Ordering::Acquire), 0);
    assert_eq!(fixture.moves.load(Ordering::Acquire), 1);
    assert_eq!(journal.events.len(), 2);
    assert_eq!(journal.progress.snapshot().remote, NamespacePhase::Verified);
    assert_eq!(fixture.catalog.count_file_paths("/parent/renamed.txt"), 0);
    fixture.finish();
}

#[test]
fn completion_postcallback_revocation_is_uncertain_with_final_prefix_retained() {
    let mut fixture = Fixture::new();
    let mut journal = Journal::new(fixture.intent.clone());
    let (outcome, calls) =
        run_with_typed_completion(&fixture, &mut journal, CallbackMode::RevokeAfterRecord);

    assert_eq!(outcome, Ok(FileRenameOutcome::Uncertain));
    assert_eq!(calls.load(Ordering::Acquire), 1);
    assert_eq!(fixture.moves.load(Ordering::Acquire), 1);
    assert_eq!(journal.events.len(), 4);
    assert!(journal.progress.snapshot().recorded_complete);
    fixture.finish();
}
