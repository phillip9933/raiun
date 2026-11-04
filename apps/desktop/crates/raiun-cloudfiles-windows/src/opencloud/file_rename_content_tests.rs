use super::*;
use crate::namespace_file_rename::{
    FileRenameCompletionError, FileRenameOutcome, reconcile_file_rename,
};
use crate::opencloud::{FileRenameSession, VerifiedRenameSourceContent};
use crate::streamed_store::StoreError;
use sha2::{Digest, Sha256};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

enum ContentRun {
    SourceRejected(raiun_core::backend::ErrorKind),
    Reconciled(Result<FileRenameOutcome, StoreError>),
}

struct ContentLocal<'session, 'proof, 'backend> {
    session: &'session FileRenameSession<'backend>,
    source: &'proof VerifiedRenameSourceContent<'session, 'backend>,
    callback_calls: Arc<AtomicUsize>,
    conditional_gets: Arc<Mutex<Vec<(String, String)>>>,
    gets_at_callback: Arc<AtomicUsize>,
}

impl FileRenameLocal for ContentLocal<'_, '_, '_> {
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
        let publication = self
            .session
            .prepare_content_verified_file_rename(readback, self.source)
            .map_err(|_| FileRenameCompletionError::Unavailable)?;
        assert_eq!(publication.byte_len(), 4);
        assert_eq!(publication.digest(), self.source.digest());
        publication.publish_file_rename_completion(|| {
            self.gets_at_callback.store(
                self.conditional_gets.lock().unwrap().len(),
                Ordering::Release,
            );
            self.callback_calls.fetch_add(1, Ordering::AcqRel);
            record().map_err(FileRenameCompletionError::Store)
        })
    }
}

fn expected_digest() -> [u8; 32] {
    Sha256::digest(b"data").into()
}

fn run_content(
    fixture: &Fixture,
    journal: &mut Journal,
) -> Result<(ContentRun, usize, usize), StoreError> {
    let calls = Arc::new(AtomicUsize::new(0));
    let gets_at_callback = Arc::new(AtomicUsize::new(0));
    let conditional_gets = Arc::clone(&fixture.conditional_gets);
    let callback_gets = Arc::clone(&gets_at_callback);
    fixture
        .backend
        .with_file_rename_session(
            &fixture.intent,
            fixture.parent,
            &|auth| auth.agent_generation == 3 && fixture.owner_live.load(Ordering::Acquire),
            |session| {
                let source = match session.verify_source_content(expected_digest()) {
                    Ok(source) => source,
                    Err(error) => return (ContentRun::SourceRejected(error.kind), 0, 0),
                };
                let mut local = ContentLocal {
                    session,
                    source: &source,
                    callback_calls: Arc::clone(&calls),
                    conditional_gets: Arc::clone(&conditional_gets),
                    gets_at_callback: Arc::clone(&callback_gets),
                };
                let outcome = reconcile_file_rename(journal, session.remote(), &mut local);
                (
                    ContentRun::Reconciled(outcome),
                    calls.load(Ordering::Acquire),
                    gets_at_callback.load(Ordering::Acquire),
                )
            },
        )
        .map_err(|_| StoreError::CorruptEvidence)
}

#[test]
fn content_proof_binds_both_revisions_before_typed_completion() {
    let mut fixture = Fixture::new();
    let mut journal = Journal::new(fixture.intent.clone());
    let (run, calls, gets_at_callback) = run_content(&fixture, &mut journal).unwrap();
    assert!(matches!(
        run,
        ContentRun::Reconciled(Ok(FileRenameOutcome::Completed))
    ));
    assert_eq!(calls, 1);
    assert_eq!(gets_at_callback, 2);
    assert_eq!(fixture.moves.load(Ordering::Acquire), 1);
    assert!(journal.progress.snapshot().recorded_complete);
    assert_eq!(journal.events.len(), 4);
    let gets = fixture.conditional_gets.lock().unwrap();
    assert_eq!(gets.len(), 2);
    assert_eq!(
        gets[0],
        (
            "/dav/personal/parent/source.txt".into(),
            "\"source-etag\"".into()
        )
    );
    assert_eq!(
        gets[1],
        (
            "/dav/personal/parent/renamed.txt".into(),
            "\"source-v2\"".into()
        )
    );
    drop(gets);
    assert_eq!(fixture.catalog.count_file_paths("/parent/renamed.txt"), 1);
    assert_eq!(
        fixture.catalog.file_etag("/parent/renamed.txt").as_deref(),
        Some("\"source-v2\"")
    );
    assert_eq!(
        fixture.catalog.file_etag("/parent/source.txt").as_deref(),
        Some("\"source-etag\"")
    );
    fixture.finish();
}

#[test]
fn content_proof_rejects_wrong_source_body_before_move() {
    let mut fixture = Fixture::new();
    fixture.mode.store(SOURCE_BODY_BAD, Ordering::Release);
    let mut journal = Journal::new(fixture.intent.clone());
    let (run, calls, gets_at_callback) = run_content(&fixture, &mut journal).unwrap();
    assert!(matches!(
        run,
        ContentRun::SourceRejected(raiun_core::backend::ErrorKind::Conflict)
    ));
    assert_eq!(calls, 0);
    assert_eq!(gets_at_callback, 0);
    assert_eq!(fixture.moves.load(Ordering::Acquire), 0);
    assert!(journal.events.is_empty());
    assert!(!fixture.catalog.contains_file_path("/parent/renamed.txt"));
    assert_eq!(fixture.conditional_gets.lock().unwrap().len(), 1);
    fixture.finish();
}

#[test]
fn content_proof_rejects_wrong_destination_body_without_publication() {
    let mut fixture = Fixture::new();
    fixture.mode.store(DESTINATION_BODY_BAD, Ordering::Release);
    let mut journal = Journal::new(fixture.intent.clone());
    let (run, calls, gets_at_callback) = run_content(&fixture, &mut journal).unwrap();
    assert!(matches!(
        run,
        ContentRun::Reconciled(Ok(FileRenameOutcome::RemoteVerifiedLocalPending))
    ));
    assert_eq!(calls, 0);
    assert_eq!(gets_at_callback, 0);
    assert_eq!(fixture.moves.load(Ordering::Acquire), 1);
    assert!(!journal.progress.snapshot().recorded_complete);
    assert!(!fixture.catalog.contains_file_path("/parent/renamed.txt"));
    assert_eq!(fixture.conditional_gets.lock().unwrap().len(), 2);
    fixture.finish();
}

#[test]
fn content_proof_rejects_destination_revision_change_after_body_without_publication() {
    let mut fixture = Fixture::new();
    fixture
        .mode
        .store(DESTINATION_REVISION_CHANGES, Ordering::Release);
    let mut journal = Journal::new(fixture.intent.clone());
    let (run, calls, gets_at_callback) = run_content(&fixture, &mut journal).unwrap();
    assert!(matches!(
        run,
        ContentRun::Reconciled(Ok(FileRenameOutcome::RemoteVerifiedLocalPending))
    ));
    assert_eq!(calls, 0);
    assert_eq!(gets_at_callback, 0);
    assert_eq!(fixture.moves.load(Ordering::Acquire), 1);
    assert!(!journal.progress.snapshot().recorded_complete);
    assert!(!fixture.catalog.contains_file_path("/parent/renamed.txt"));
    assert_eq!(fixture.conditional_gets.lock().unwrap().len(), 2);
    fixture.finish();
}
