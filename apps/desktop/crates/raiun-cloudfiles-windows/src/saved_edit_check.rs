//! Informational cloud comparison only. No dispatch, history, or native proof.
use super::*;
use crate::ReconciliationIssue;
#[cfg(windows)]
use crate::RecoveryRemoteVersion;
#[cfg(windows)]
use raiun_core::backend::ErrorKind;

/// Current cloud observation of an authenticated immutable retained body.
/// None of these outcomes retires custody or authorizes native completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SavedEditCloudCheck {
    /// Current bytes match. Without a protected created-file ID this makes no
    /// historical ownership claim about the observed cloud file.
    Matched {
        bytes: u64,
    },
    /// A direct created-file lookup returned NotFound while exact original
    /// root and parent checks succeeded before and after that request.
    Missing,
    Different,
    Unavailable,
}

#[cfg(windows)]
pub(super) fn check_created(
    store: &Arc<crate::streamed_store::SnapshotStore>,
    key: &crate::streamed_store::StreamedRecordKey,
    remote: &dyn RecoveryRemote,
    job: &crate::StreamedRecoveryJob,
) -> Result<SavedEditCloudCheck, crate::JournalError> {
    use crate::namespace_intent::{NamespaceObjectKind, NamespaceOperation, StorageClassification};
    use crate::streamed_store::namespace_file_store::{CapturedCreatePath, FileCreateStore};
    let creates =
        FileCreateStore::new(Arc::clone(store)).map_err(crate::edit_journal::admission_error)?;
    let mut selected = creates
        .discover()
        .map_err(crate::edit_journal::admission_error)?
        .into_iter()
        .filter(|row| row.snapshot_id() == key.record_id());
    let Some(join) = selected.next() else {
        // Authenticate the retained body even if its required join is absent.
        // No path-only fallback or network request may follow that absence.
        store
            .open_verified_key(key, &mut || job.is_stopped())
            .map_err(crate::edit_journal::admission_error)?;
        return Ok(SavedEditCloudCheck::Unavailable);
    };
    if selected.next().is_some()
        || join.key().generation() != key.generation()
        || join.key().scope() != key.scope()
    {
        return Err(crate::JournalError::ScopeMismatch);
    }
    let verified = creates
        .open_joined(join.key(), &mut || job.is_stopped())
        .map_err(crate::edit_journal::admission_error)?;
    let binding = verified.manifest().binding();
    let NamespaceOperation::CreateFile {
        destination,
        content,
    } = &verified.record().intent().operation
    else {
        return Err(crate::JournalError::ScopeMismatch);
    };
    let parent = &destination.parent;
    let sha_hex = verified
        .manifest()
        .content_sha256()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if !verified
        .matches_snapshot_key(key)
        .map_err(crate::edit_journal::admission_error)?
        || verified.record().key() != join.key()
        || verified.record().intent() != join.intent()
        || verified.record().manifest_commitment_sha256() != join.manifest_commitment_sha256()
        || binding.record_id != key.record_id()
        || binding.generation != key.generation()
        || binding.scope != *key.scope()
        || parent.scope != *key.scope()
        || binding.remote.is_some()
        || binding.local_file != destination.local_file
        || binding.content_len != content.byte_len
        || sha_hex != content.sha256
        || destination.object_kind != NamespaceObjectKind::File
        || parent.classification != StorageClassification::Ordinary
    {
        return Err(crate::JournalError::ScopeMismatch);
    }
    let mut components = parent.local_components.clone();
    components.push(destination.name.clone());
    CapturedCreatePath::new(components, binding.relative_path.clone())
        .map_err(crate::edit_journal::admission_error)?;
    let report = verified.remote_report();
    if report.is_some_and(|report| {
        report.destination != *destination
            || report.content.as_ref() != Some(content)
            || report.remote.byte_len != content.byte_len
    }) {
        return Err(crate::JournalError::ScopeMismatch);
    }
    let authorized = || {
        !job.is_stopped()
            && remote.server_origin() == Some(key.scope().server_origin.as_str())
            && remote.ensure_authorized(key.scope()).is_ok()
    };
    if !authorized() {
        return Ok(SavedEditCloudCheck::Unavailable);
    }
    let result = remote.check_created_copy(
        key.scope(),
        &binding.relative_path,
        &parent.remote,
        report.map(|report| report.remote.resource_id.as_str()),
        binding.content_len,
        *verified.manifest().content_sha256(),
        job,
    );
    if !authorized() {
        return Ok(SavedEditCloudCheck::Unavailable);
    }
    verified
        .verify_pin()
        .map_err(crate::edit_journal::admission_error)?;
    Ok(match result {
        Ok(SavedEditCloudCheck::Matched { bytes }) if bytes != binding.content_len => {
            SavedEditCloudCheck::Different
        }
        Ok(result) => result,
        Err(error) => cloud_error(error.kind),
    })
}

pub(super) fn check(
    prepared: &DurablePreparedEditRecovery,
    record_id: &str,
    generation: u64,
    remote: &dyn RecoveryRemote,
) -> Result<SavedEditCloudCheck, crate::JournalError> {
    if !valid_scope_binding(&prepared.scope, prepared.root_identity)
        || record_id.is_empty()
        || record_id.len() > 128
        || !record_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        || generation == 0
    {
        return Err(crate::JournalError::ScopeMismatch);
    }
    #[cfg(windows)]
    if let Some(result) = prepared.try_check_recovered_streamed(record_id, generation, remote)? {
        return Ok(result);
    }
    let journal = prepared.catalog.journal_for_record(
        &prepared.scope,
        prepared.root_identity,
        record_id,
        generation,
    )?;
    let scope = journal.scope();
    // The catalog selects the exact immutable account/root/record generation;
    // recover_all authenticates the protected full body before any HTTP.
    let mut selected = journal.recover_all()?.records.into_iter().filter(|record| {
        record.metadata.record_id == record_id
            && record.metadata.generation == generation
            && &record.metadata.scope == scope
    });
    let record = selected.next().ok_or(crate::JournalError::ScopeMismatch)?;
    if selected.next().is_some() {
        return Err(crate::JournalError::ScopeMismatch);
    }
    if record.metadata.remote.is_none() {
        // A new-file create needs its protected namespace parent/report join.
        // A same-path object cannot become its historical resource identity.
        return Ok(SavedEditCloudCheck::Unavailable);
    }
    let checked = crate::verify_edit_readback(&record, scope, remote);
    if remote.server_origin() != Some(scope.server_origin.as_str())
        || remote.ensure_authorized(scope).is_err()
    {
        return Ok(SavedEditCloudCheck::Unavailable);
    }
    match checked {
        Ok(proof) => Ok(SavedEditCloudCheck::Matched {
            bytes: proof.metadata().content_len,
        }),
        Err(ReconciliationOutcome::Conflict(ReconciliationIssue::RemoteObjectMissing)) => {
            // Generic legacy metadata lookup can hide an ancestor/root 404.
            Ok(SavedEditCloudCheck::Unavailable)
        }
        Err(ReconciliationOutcome::Conflict(
            ReconciliationIssue::RemoteObjectChanged
            | ReconciliationIssue::ContentMismatch
            | ReconciliationIssue::ResponseInconsistent,
        )) => Ok(SavedEditCloudCheck::Different),
        Err(_) => Ok(SavedEditCloudCheck::Unavailable),
    }
}

#[cfg(windows)]
fn strong_etag(etag: &str) -> bool {
    etag.len() >= 3
        && etag.len() <= 4096
        && etag.starts_with('"')
        && etag.ends_with('"')
        && !etag[1..etag.len() - 1]
            .bytes()
            .any(|byte| byte == b'"' || byte < 0x21 || byte == 0x7f)
}

#[cfg(windows)]
pub(super) fn check_streamed(
    store: &crate::streamed_store::SnapshotStore,
    key: &crate::streamed_store::StreamedRecordKey,
    current_generation: u64,
    remote: &dyn RecoveryRemote,
    job: &crate::StreamedRecoveryJob,
) -> Result<SavedEditCloudCheck, crate::JournalError> {
    let snapshot = store
        .open_verified_key(key, &mut || job.is_stopped())
        .map_err(crate::edit_journal::admission_error)?;
    let manifest = snapshot.manifest();
    let binding = manifest.binding();
    if binding.scope != *key.scope()
        || binding.record_id != key.record_id()
        || binding.generation != key.generation()
        || current_generation == 0
    {
        return Err(crate::JournalError::ScopeMismatch);
    }
    let Some(baseline) = binding
        .remote
        .as_ref()
        .filter(|base| !base.resource_id.is_empty() && strong_etag(&base.etag))
    else {
        return Ok(SavedEditCloudCheck::Unavailable);
    };
    let Some(adapter) = remote.streamed_remote_for_job(job) else {
        return Ok(SavedEditCloudCheck::Unavailable);
    };
    // Historical snapshot generation is authenticated above. The independent
    // live transport is bound to the current authorized token generation.
    let authorized = || {
        !job.is_stopped()
            && remote.server_origin() == Some(key.scope().server_origin.as_str())
            && remote.ensure_authorized(key.scope()).is_ok()
            && adapter.server_origin() == key.scope().server_origin
            && adapter
                .ensure_authorized(key.scope(), current_generation)
                .is_ok()
            && !job.is_stopped()
    };
    if !authorized() {
        return Ok(SavedEditCloudCheck::Unavailable);
    }
    let before = adapter.stat(key.scope(), &binding.relative_path);
    if !authorized() {
        return Ok(SavedEditCloudCheck::Unavailable);
    }
    let before = match before {
        Ok(version) => version,
        Err(error) => return Ok(cloud_error(error.kind)),
    };
    if !same_target(&before, &baseline.resource_id, binding.content_len) {
        return Ok(SavedEditCloudCheck::Different);
    }
    let result = adapter.read_digest(
        key.scope(),
        &binding.relative_path,
        &baseline.resource_id,
        &before.etag,
        binding.content_len,
        *manifest.content_sha256(),
    );
    if !authorized() {
        return Ok(SavedEditCloudCheck::Unavailable);
    }
    // Retain and recheck the original immutable body pin through the full GET.
    snapshot
        .verify_pin()
        .map_err(crate::edit_journal::admission_error)?;
    Ok(match result {
        Ok(digest)
            if digest.version == before
                && digest.bytes == binding.content_len
                && digest.sha256 == *manifest.content_sha256() =>
        {
            SavedEditCloudCheck::Matched {
                bytes: binding.content_len,
            }
        }
        Ok(_) => SavedEditCloudCheck::Different,
        Err(error) => cloud_error(error.kind),
    })
}

#[cfg(windows)]
fn same_target(version: &RecoveryRemoteVersion, resource: &str, bytes: u64) -> bool {
    version.resource_id == resource
        && version.size == bytes
        && !version.is_directory
        && !version.encrypted
        && strong_etag(&version.etag)
}

#[cfg(windows)]
fn cloud_error(kind: ErrorKind) -> SavedEditCloudCheck {
    match kind {
        // Opaque metadata/full-read helpers may report an ancestor/root 404.
        ErrorKind::NotFound => SavedEditCloudCheck::Unavailable,
        ErrorKind::Conflict => SavedEditCloudCheck::Different,
        _ => SavedEditCloudCheck::Unavailable,
    }
}
