//! Unwired, one-attempt deletion of an ordinary clean Personal file.
//!
//! This safe coordinator implements no persistent store, HTTP request, SDK ACK,
//! observer, worker or eviction path. Its trusted adapters must retain the
//! original live authorization/native leases throughout the call. Authenticated
//! history is factual evidence, never authority to replay a deletion.
use crate::namespace_intent::{
    ExistingNamespaceEntry, NamespaceEventKind, NamespaceIntent, NamespaceIntentProgress,
    NamespaceObjectKind, NamespaceOperation, NamespacePhase, NamespaceProgressSnapshot,
    StorageClassification,
};
use crate::streamed_store::StoreError;
use raiun_core::backend::{CloudError, ErrorKind};

pub trait FileDeleteJournal {
    /// Fresh, explicit user-delete custody under the original admission and
    /// exclusive record lease. Discovery, recovered Pending/0 records, provider
    /// cleanup and cache eviction MUST return false, even for identical metadata.
    fn owns_fresh_user_delete(&self) -> bool;
    fn intent(&self) -> &NamespaceIntent;
    fn progress(&self) -> NamespaceProgressSnapshot;
    /// Authenticate context and durably append before success. Any append error
    /// must poison this attempt and permanently revoke fresh custody, including
    /// when a subsequent read exposes an older prefix. Never retry the append/send.
    fn append_event(&mut self, event: NamespaceEventKind) -> Result<(), StoreError>;
}

/// Nonserializable, noncloneable one-attempt context, minted only after the
/// original journal confirms durable RemoteSubmitted. Not a native capability.
pub struct FileDeleteDispatch<'a> {
    intent: &'a NamespaceIntent,
}
impl FileDeleteDispatch<'_> {
    pub fn intent(&self) -> &NamespaceIntent {
        self.intent
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileDeleteSend {
    Deleted,
    Rejected(CloudError),
    Uncertain,
}

/// Fresh reports from a trusted adapter, not serialized mutation authority.
/// `source` must bind the full ORIGINAL account, generation, root, ancestry,
/// local object and remote strong ETag, not a current name-based replacement.
pub struct FileDeleteLocalObservation {
    pub source: ExistingNamespaceEntry,
    pub ancestry: StorageClassification,
    pub dirty: bool,
    pub pending: bool,
}

pub struct FileDeleteAbsence {
    pub source: ExistingNamespaceEntry,
    pub original_path_absent: bool,
}

pub trait FileDeleteRemote {
    /// Fresh original account/generation/root currentness, permission and
    /// cancellation checks. Hold that original lease throughout this call.
    fn ensure_authorized(&self, intent: &NamespaceIntent) -> Result<(), CloudError>;
    /// Fresh full ordinary ancestry and writable root/parent/file metadata.
    /// Return the exact original source only after checking remote id/strong
    /// ETag. Root/directory/encrypted/unknown targets are not admissible.
    fn preflight(&self, intent: &NamespaceIntent) -> Result<ExistingNamespaceEntry, CloudError>;
    /// One conditional DELETE with the ORIGINAL strong If-Match. Invoke the
    /// guard exactly once after final remote proof and immediately before send;
    /// if it fails, do not send. Err means definitely NOT sent. Any lost response
    /// or possibly-sent failure MUST be Uncertain, never Rejected/Err/retried.
    fn delete_with_send_guard(
        &self,
        dispatch: &FileDeleteDispatch<'_>,
        before_send: &mut dyn FnMut() -> Result<(), CloudError>,
    ) -> Result<FileDeleteSend, CloudError>;
    /// Only after a successful conditioned DELETE: independently establish the
    /// original path's absence under the same verified account/root/parent.
    /// A generic404, missing parent, expired authorization or same-path new
    /// replacement is NOT qualified absence. Never adopt already-missing files.
    fn observe_absence(&self, intent: &NamespaceIntent) -> Result<FileDeleteAbsence, CloudError>;
}

pub trait FileDeleteLocal {
    /// Fresh native exact-object/full-ancestry proof and authoritative dirty and
    /// pending-capture/upload/recovery checks under the original operation's
    /// fence. A name lookup or cached clean bit cannot satisfy this contract.
    fn observe_clean(
        &mut self,
        intent: &NamespaceIntent,
    ) -> Result<FileDeleteLocalObservation, CloudError>;
    /// Revalidate the original local operation/object/ancestry, cancellation and
    /// no replacement under a live native completion fence; only then invoke
    /// record. This factual receipt grants no SDK ACK authority on its own.
    /// Unavailable means record was NOT called. Store preserves its exact error;
    /// Uncertain means record/completion may already have happened. No replay.
    fn record_completion<F>(
        &mut self,
        intent: &NamespaceIntent,
        readback: &FileDeleteReadback,
        record: F,
    ) -> Result<(), FileDeleteCompletionError>
    where
        F: FnOnce() -> Result<(), StoreError>;
}

pub struct FileDeleteReadback {
    absence: FileDeleteAbsence,
}
impl FileDeleteReadback {
    pub fn source(&self) -> &ExistingNamespaceEntry {
        &self.absence.source
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileDeleteCompletionError {
    Unavailable,
    Store(StoreError),
    Uncertain,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileDeleteOutcome {
    Completed,
    RemoteVerifiedLocalPending,
    Deferred,
    Conflict,
    Uncertain,
    Retained,
}

fn source(intent: &NamespaceIntent) -> Option<&ExistingNamespaceEntry> {
    match &intent.operation {
        NamespaceOperation::DeleteFile { source } => Some(source),
        _ => None,
    }
}
fn supported(intent: &NamespaceIntent) -> bool {
    let Some(source) = source(intent) else {
        return false;
    };
    let parent = &source.local.parent;
    source.local.object_kind == NamespaceObjectKind::File
        && parent.local_components.first().map(String::as_str) == Some("Personal")
        && [
            &source.remote.resource_id,
            &parent.remote.resource_id,
            &parent.scope.root_resource_id,
        ]
        .iter()
        .all(|id| {
            !id.to_ascii_lowercase().starts_with("http://")
                && !id.to_ascii_lowercase().starts_with("https://")
        })
}
fn unavailable() -> CloudError {
    CloudError::new(
        ErrorKind::Forbidden,
        "ordinary file delete admission unavailable",
    )
}
fn admit_clean(
    local: &mut (impl FileDeleteLocal + ?Sized),
    intent: &NamespaceIntent,
) -> Result<(), CloudError> {
    let observation = local.observe_clean(intent)?;
    if observation.ancestry != StorageClassification::Ordinary
        || observation.dirty
        || observation.pending
        || source(intent) != Some(&observation.source)
    {
        return Err(unavailable());
    }
    Ok(())
}
fn finish_attention(
    journal: &mut impl FileDeleteJournal,
    error: &CloudError,
) -> Result<FileDeleteOutcome, StoreError> {
    let (event, outcome) = if error.kind == ErrorKind::Conflict {
        (NamespaceEventKind::Conflict, FileDeleteOutcome::Conflict)
    } else {
        (NamespaceEventKind::Deferred, FileDeleteOutcome::Deferred)
    };
    journal.append_event(event)?;
    Ok(outcome)
}
fn uncertain(journal: &mut impl FileDeleteJournal) -> Result<FileDeleteOutcome, StoreError> {
    journal.append_event(NamespaceEventKind::Uncertain)?;
    Ok(FileDeleteOutcome::Uncertain)
}

/// Exactly one explicit user-delete attempt. Every nonpristine/recovered record
/// is retained without dispatch, even after successful remote verification.
/// No deletion is inferred from directory notifications or a missing local file.
pub fn reconcile_file_delete(
    journal: &mut impl FileDeleteJournal,
    remote: &(impl FileDeleteRemote + ?Sized),
    local: &mut (impl FileDeleteLocal + ?Sized),
) -> Result<FileDeleteOutcome, StoreError> {
    let intent = journal.intent().clone();
    if !journal.owns_fresh_user_delete()
        || NamespaceIntentProgress::new(intent.clone()).is_err()
        || !supported(&intent)
    {
        return Ok(FileDeleteOutcome::Retained);
    }
    let progress = journal.progress();
    if progress.sequence != 0
        || progress.remote != NamespacePhase::Pending
        || progress.source_removal.is_some()
        || progress.attention.is_some()
        || progress.local_completed
        || progress.recorded_complete
    {
        return Ok(FileDeleteOutcome::Retained);
    }
    let original = source(&intent).expect("validated delete-only intent");
    if let Err(error) = remote
        .ensure_authorized(&intent)
        .and_then(|()| admit_clean(local, &intent))
        .and_then(|()| remote.preflight(&intent))
        .and_then(|observed| {
            if observed != *original {
                return Err(CloudError::new(
                    ErrorKind::Conflict,
                    "ordinary file delete baseline changed",
                ));
            }
            remote.ensure_authorized(&intent)
        })
    {
        return finish_attention(journal, &error);
    }
    journal.append_event(NamespaceEventKind::RemoteSubmitted)?;
    // Do not mint dispatch from merely deserialized/recovered Submitted history.
    if journal.progress().remote != NamespacePhase::Submitted
        || journal.progress().sequence != 1
        || !journal.owns_fresh_user_delete()
    {
        return Err(StoreError::CorruptEvidence);
    }
    let dispatch = FileDeleteDispatch { intent: &intent };
    let mut guards = 0;
    let mut guarded = false;
    let mut before_send = || {
        guards += 1;
        if guards != 1 || !journal.owns_fresh_user_delete() {
            return Err(unavailable());
        }
        remote.ensure_authorized(&intent)?;
        admit_clean(local, &intent)?;
        remote.ensure_authorized(&intent)?;
        guarded = true;
        Ok(())
    };
    let sent = remote.delete_with_send_guard(&dispatch, &mut before_send);
    // A second invocation may follow an earlier successful guard/send. Its
    // later refusal cannot turn a possibly sent request into a no-send error.
    if guards > 1 {
        return uncertain(journal);
    }
    match sent {
        Ok(FileDeleteSend::Deleted) if guarded && guards == 1 => (),
        Ok(FileDeleteSend::Deleted | FileDeleteSend::Uncertain) => return uncertain(journal),
        Ok(FileDeleteSend::Rejected(error)) | Err(error) => {
            return finish_attention(journal, &error);
        }
    }
    let absence = match remote
        .ensure_authorized(&intent)
        .and_then(|()| remote.observe_absence(&intent))
        .and_then(|absence| {
            remote.ensure_authorized(&intent)?;
            Ok(absence)
        }) {
        Ok(absence) if absence.source == *original && absence.original_path_absent => absence,
        _ => return uncertain(journal),
    };
    journal.append_event(NamespaceEventKind::RemoteDeleted {
        source: original.clone(),
    })?;
    let readback = FileDeleteReadback { absence };
    if remote.ensure_authorized(&intent).is_err() {
        return Ok(FileDeleteOutcome::RemoteVerifiedLocalPending);
    }
    match local.record_completion(&intent, &readback, || {
        journal.append_event(NamespaceEventKind::LocalDeleted {
            source: original.clone(),
        })
    }) {
        Ok(()) if journal.progress().recorded_complete => Ok(FileDeleteOutcome::Completed),
        Ok(()) | Err(FileDeleteCompletionError::Unavailable) => {
            Ok(FileDeleteOutcome::RemoteVerifiedLocalPending)
        }
        Err(FileDeleteCompletionError::Store(error)) => Err(error),
        Err(FileDeleteCompletionError::Uncertain) => Ok(FileDeleteOutcome::Uncertain),
    }
}

#[cfg(test)]
#[path = "namespace_file_delete_tests.rs"]
mod tests;
