//! Unwired, single-file same-parent rename reconciliation.
//!
//! This coordinator sequences one attempt through trusted interfaces. It implements no
//! store, remote client, native operation, or automatic replay. A production
//! caller must supply an authenticated journal holding its exclusive
//! per-record lease for this call, a live remote adapter, and fresh native
//! checks. Any non-pristine history is retained without adoption or resend.
use crate::namespace_intent::{
    ExistingNamespaceEntry, LocalNamespaceEntry, NamespaceDestinationReport, NamespaceEvent,
    NamespaceEventKind, NamespaceIntent, NamespaceIntentProgress, NamespaceObjectKind,
    NamespaceOperation, NamespacePhase, NamespaceProgressSnapshot,
};
use crate::streamed_store::StoreError;
use raiun_core::backend::{CloudError, ErrorKind};

pub trait FileRenameJournal {
    /// Live, nonserialized custody of this producer's own newly published
    /// intent under the same admission. Discovery or recovered Pending/0
    /// history must return false; a parsed record cannot grant this custody.
    fn owns_fresh_publication(&self) -> bool;
    /// The authenticated intent pinned by the held exclusive record lease.
    fn intent(&self) -> &NamespaceIntent;
    fn progress(&self) -> NamespaceProgressSnapshot;
    /// Authenticate context and durably append before returning success.
    /// On any append error, the journal/caller must poison this attempt and
    /// permanently revoke owns_fresh_publication for this intent/attempt and
    /// never retry or resend, even if a subsequent read shows an older prefix.
    fn append_event(&mut self, event: NamespaceEventKind) -> Result<(), StoreError>;
}

/// Private, non-serializable one-send permit. Only this coordinator can mint
/// it, after RemoteSubmitted has been durably appended.
pub struct FileRenameDispatch<'a> {
    intent: &'a NamespaceIntent,
}
impl FileRenameDispatch<'_> {
    pub fn intent(&self) -> &NamespaceIntent {
        self.intent
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileRenameSend {
    Renamed,
    Rejected(CloudError),
    Uncertain,
}

/// `Err` from `rename` must mean the request was not sent. Any possibly-sent
/// result must be `Uncertain`; this coordinator never retries either case.
/// The adapter must retain its live authorization/context lease through the
/// entire coordinator call, including observation and fenced local completion.
pub trait FileRenameRemote {
    fn ensure_authorized(&self, intent: &NamespaceIntent) -> Result<(), CloudError>;
    /// Fresh source id/strong-ETag, ordinary ancestry and account/root checks;
    /// destination must be absent and overwrite disabled by the adapter.
    fn preflight(&self, intent: &NamespaceIntent) -> Result<(), CloudError>;
    fn rename(&self, dispatch: &FileRenameDispatch<'_>) -> Result<FileRenameSend, CloudError>;
    /// A guarded caller requires an adapter that invokes this callback after
    /// its last remote proof, immediately before the actual send. The default
    /// refuses without invoking the legacy method, whose send boundary is unknown.
    fn rename_with_send_guard(
        &self,
        _dispatch: &FileRenameDispatch<'_>,
        _before_send: &mut dyn FnMut() -> Result<(), CloudError>,
    ) -> Result<FileRenameSend, CloudError> {
        Err(CloudError::new(
            ErrorKind::Unsupported,
            "guarded rename send is unavailable",
        ))
    }
    /// Freshly observe destination and independently establish source absence.
    fn observe(&self, intent: &NamespaceIntent) -> Result<FileRenameObservation, CloudError>;
}

pub struct FileRenameObservation {
    pub destination: NamespaceDestinationReport,
    /// Adapter's fresh factual report only; this is never deletion authority.
    pub source_absent: bool,
}

/// Fresh admission must check exact local file identity and the completed
/// same-parent path change. The completion closure must run under a fresh
/// native fence and append both final factual events before returning success.
pub trait FileRenameLocal {
    fn admit(&mut self, intent: &NamespaceIntent) -> Result<(), CloudError>;
    fn record_completion<F>(
        &mut self,
        intent: &NamespaceIntent,
        readback: &FileRenameReadback,
        record: F,
    ) -> Result<(), FileRenameCompletionError>
    where
        F: FnOnce() -> Result<(), StoreError>;
}

pub struct FileRenameReadback {
    observation: FileRenameObservation,
}
impl FileRenameReadback {
    pub fn destination(&self) -> &NamespaceDestinationReport {
        &self.observation.destination
    }
    pub fn source_absent(&self) -> bool {
        self.observation.source_absent
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileRenameCompletionError {
    /// The closure was not called; remote verification remains the factual tip.
    Unavailable,
    /// The closure ran and returned this journal error; preserve its exact prefix.
    Store(StoreError),
    /// The append may have become durable; never infer whether it did.
    Uncertain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileRenameOutcome {
    Completed,
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
fn attention_outcome(error: &CloudError) -> FileRenameOutcome {
    if error.kind == ErrorKind::Conflict {
        FileRenameOutcome::Conflict
    } else {
        FileRenameOutcome::Deferred
    }
}
fn finish_attention(
    journal: &mut impl FileRenameJournal,
    error: &CloudError,
) -> Result<FileRenameOutcome, StoreError> {
    journal.append_event(attention(error))?;
    Ok(attention_outcome(error))
}
fn finish_uncertain(journal: &mut impl FileRenameJournal) -> Result<FileRenameOutcome, StoreError> {
    journal.append_event(NamespaceEventKind::Uncertain)?;
    Ok(FileRenameOutcome::Uncertain)
}

fn move_intent(
    intent: &NamespaceIntent,
) -> Option<(&ExistingNamespaceEntry, &LocalNamespaceEntry)> {
    match &intent.operation {
        NamespaceOperation::MoveWithinScope {
            source,
            destination,
        } => Some((source, destination)),
        _ => None,
    }
}

fn looks_like_url_resource_id(value: &str) -> bool {
    value
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
        || value
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
}

fn supported(intent: &NamespaceIntent) -> bool {
    let Some((source, destination)) = move_intent(intent) else {
        return false;
    };
    let parent = &source.local.parent;
    source.local.object_kind == destination.object_kind
        && matches!(
            source.local.object_kind,
            NamespaceObjectKind::File | NamespaceObjectKind::Directory
        )
        && (source.local.object_kind != NamespaceObjectKind::Directory
            || source.remote.byte_len == 0)
        && (source.local.parent == destination.parent
            || (source.local.object_kind == NamespaceObjectKind::File
                && source.local.parent.scope == destination.parent.scope
                && source.local.parent.authorization == destination.parent.authorization
                && source.local.parent.classification
                    == crate::namespace_intent::StorageClassification::Ordinary
                && destination.parent.classification
                    == crate::namespace_intent::StorageClassification::Ordinary
                && match destination
                    .parent
                    .local_components
                    .first()
                    .map(String::as_str)
                {
                    Some("Personal") => true,
                    Some("Spaces") => destination.parent.local_components.len() >= 2,
                    _ => false,
                }))
        && match parent.local_components.first().map(String::as_str) {
            Some("Personal") => true,
            Some("Spaces") => parent.local_components.len() >= 2,
            _ => false,
        }
        && source.local.local_file == destination.local_file
        && (source.local.parent != destination.parent
            || !source.local.name.eq_ignore_ascii_case(&destination.name))
        && source.remote.etag.starts_with('"')
        && source.remote.etag.ends_with('"')
        && !looks_like_url_resource_id(&source.remote.resource_id)
}

/// Attempt one ordinary file rename/move within one verified Space/root, or
/// the existing same-parent empty-directory rename.
///
/// The only accepted entry state is the exact authenticated intent at sequence
/// zero with Pending remote/source-removal phases, no attention, and no local
/// completion. A live adapter must bind `rename` to one conditional,
/// non-overwriting request. No error or history state authorizes a replay.
pub fn reconcile_file_rename(
    journal: &mut impl FileRenameJournal,
    remote: &(impl FileRenameRemote + ?Sized),
    local: &mut (impl FileRenameLocal + ?Sized),
) -> Result<FileRenameOutcome, StoreError> {
    let intent = journal.intent().clone();
    if !journal.owns_fresh_publication()
        || NamespaceIntentProgress::new(intent.clone()).is_err()
        || !supported(&intent)
    {
        return Ok(FileRenameOutcome::Retained);
    }
    let progress = journal.progress();
    if progress.sequence != 0
        || progress.remote != NamespacePhase::Pending
        || progress.source_removal != Some(NamespacePhase::Pending)
        || progress.attention.is_some()
        || progress.local_completed
        || progress.recorded_complete
    {
        return Ok(FileRenameOutcome::Retained);
    }

    if let Err(error) = remote
        .ensure_authorized(&intent)
        .and_then(|()| local.admit(&intent))
        .and_then(|()| remote.preflight(&intent))
        .and_then(|()| remote.ensure_authorized(&intent))
    {
        return finish_attention(journal, &error);
    }

    journal.append_event(NamespaceEventKind::RemoteSubmitted)?;
    let dispatch = FileRenameDispatch { intent: &intent };
    if let Err(error) = remote
        .ensure_authorized(&intent)
        .and_then(|()| local.admit(&intent))
        .and_then(|()| remote.ensure_authorized(&intent))
    {
        return finish_attention(journal, &error);
    }
    match remote.rename(&dispatch) {
        Ok(FileRenameSend::Renamed) => (),
        Ok(FileRenameSend::Rejected(error)) => return finish_attention(journal, &error),
        Ok(FileRenameSend::Uncertain) => return finish_uncertain(journal),
        // The trait contract says Err is definitely pre-send, but Submitted is
        // still retained as a terminal attention record; it is never replayed.
        Err(error) => return finish_attention(journal, &error),
    }

    // Submitted is durable now. Recheck both live authorities immediately
    // before observation and again before completion; any failure is uncertain.
    if remote.ensure_authorized(&intent).is_err() {
        return finish_uncertain(journal);
    }
    let observation = match remote.observe(&intent) {
        Ok(value) => value,
        Err(_) => return finish_uncertain(journal),
    };
    if remote.ensure_authorized(&intent).is_err() || !observation.source_absent {
        return finish_uncertain(journal);
    }
    let Some((source, destination)) = move_intent(&intent) else {
        return finish_uncertain(journal);
    };
    if observation.destination.destination != *destination
        || observation.destination.content.is_some()
        || observation.destination.remote.resource_id != source.remote.resource_id
        || observation.destination.remote.byte_len != source.remote.byte_len
        || observation.destination.remote.etag.starts_with("W/")
        || !observation.destination.remote.etag.starts_with('"')
        || !observation.destination.remote.etag.ends_with('"')
    {
        return finish_uncertain(journal);
    }

    // Use the same portable checker as authenticated history readers before
    // making the report durable. Its result is consistency evidence only.
    let mut check =
        NamespaceIntentProgress::new(intent.clone()).map_err(|_| StoreError::CorruptEvidence)?;
    let context = intent
        .event_context()
        .map_err(|_| StoreError::CorruptEvidence)?;
    check
        .record(&NamespaceEvent {
            context: context.clone(),
            sequence: 1,
            event: NamespaceEventKind::RemoteSubmitted,
        })
        .map_err(|_| StoreError::CorruptEvidence)?;
    let report = observation.destination.clone();
    if check
        .record(&NamespaceEvent {
            context,
            sequence: 2,
            event: NamespaceEventKind::RemoteVerified {
                report: report.clone(),
            },
        })
        .is_err()
    {
        return finish_uncertain(journal);
    }
    journal.append_event(NamespaceEventKind::RemoteVerified {
        report: report.clone(),
    })?;

    let readback = FileRenameReadback { observation };
    if remote
        .ensure_authorized(&intent)
        .and_then(|()| local.admit(&intent))
        .and_then(|()| remote.ensure_authorized(&intent))
        .is_err()
    {
        return Ok(FileRenameOutcome::RemoteVerifiedLocalPending);
    }
    match local.record_completion(&intent, &readback, || {
        journal.append_event(NamespaceEventKind::LocalCompleted {
            destination: destination.clone(),
        })?;
        journal.append_event(NamespaceEventKind::SourceRemovalVerified {
            source: source.clone(),
        })
    }) {
        Ok(()) if journal.progress().recorded_complete => Ok(FileRenameOutcome::Completed),
        Ok(()) => Ok(FileRenameOutcome::RemoteVerifiedLocalPending),
        Err(FileRenameCompletionError::Unavailable) => {
            Ok(FileRenameOutcome::RemoteVerifiedLocalPending)
        }
        Err(FileRenameCompletionError::Store(error)) => Err(error),
        Err(FileRenameCompletionError::Uncertain) => Ok(FileRenameOutcome::Uncertain),
    }
}

#[cfg(test)]
#[path = "namespace_file_rename_tests.rs"]
mod tests;
