//! Full-body source and destination proof for one live rename session.
//!
//! These capabilities are private to the process and bound to the exact
//! session. A local digest becomes trusted only after an If-Match full GET
//! verifies that the captured remote source has those exact bytes.

use super::*;
use crate::namespace_file_rename::{FileRenameCompletionError, FileRenameReadback};
use raiun_opencloud::RecoveryStreamReadback;
use std::sync::Arc;

pub(crate) struct VerifiedRenameSourceContent<'session, 'backend> {
    session: &'session FileRenameSession<'backend>,
    sha256: [u8; 32],
    byte_len: u64,
}

impl VerifiedRenameSourceContent<'_, '_> {
    #[cfg(test)]
    pub(crate) fn digest(&self) -> &[u8; 32] {
        &self.sha256
    }

    #[cfg(windows)]
    pub(crate) fn byte_len(&self) -> u64 {
        self.byte_len
    }
}

pub(crate) struct VerifiedRenameContentPublication<'session, 'backend> {
    publication: VerifiedFileRenamePublication<'session, 'backend>,
    sha256: [u8; 32],
    byte_len: u64,
}

impl VerifiedRenameContentPublication<'_, '_> {
    #[cfg(windows)]
    pub(crate) fn identity(&self) -> OpaqueIdentity {
        self.publication.identity()
    }

    #[cfg(windows)]
    pub(crate) fn source_identity(&self) -> OpaqueIdentity {
        self.publication.source_identity()
    }

    pub(crate) fn digest(&self) -> &[u8; 32] {
        &self.sha256
    }

    pub(crate) fn byte_len(&self) -> u64 {
        self.byte_len
    }

    pub(crate) fn publish_file_rename_completion(
        self,
        complete: impl FnOnce() -> Result<(), FileRenameCompletionError>,
    ) -> Result<(), FileRenameCompletionError> {
        self.publication.publish_file_rename_completion(complete)
    }
}

pub(super) fn verify_source_content<'session, 'backend>(
    session: &'session FileRenameSession<'backend>,
    expected_sha256: [u8; 32],
) -> Result<VerifiedRenameSourceContent<'session, 'backend>, CloudError> {
    let remote = &session.remote;
    if remote.attempted.get() || remote.renamed.get() {
        return Err(refusal(ErrorKind::Conflict));
    }

    let intent = &remote.intent;
    remote.ensure_authorized(intent)?;
    remote.check_parent(true)?;
    require_source(remote)?;

    let source = remote.source();
    let proof = full_revision_read(
        remote,
        &remote.source_relative,
        &source.remote.resource_id,
        &source.remote.etag,
        source.remote.byte_len,
        expected_sha256,
    )?;
    remote.ensure_authorized(intent)?;
    if !matches_revision_read(
        &proof,
        &remote.source_path,
        &source.remote.resource_id,
        &source.remote.etag,
        source.remote.byte_len,
        &expected_sha256,
    ) {
        return Err(remote.authoritative(refusal(ErrorKind::Conflict)));
    }

    require_source(remote)?;
    remote.check_parent(true)?;
    remote.ensure_authorized(intent)?;
    if remote.attempted.get() || remote.renamed.get() {
        return Err(refusal(ErrorKind::Conflict));
    }

    Ok(VerifiedRenameSourceContent {
        session,
        sha256: expected_sha256,
        byte_len: source.remote.byte_len,
    })
}

pub(super) fn prepare_content_verified_file_rename<'session, 'proof, 'backend>(
    session: &'session FileRenameSession<'backend>,
    readback: &'session FileRenameReadback,
    source_content: &VerifiedRenameSourceContent<'proof, 'backend>,
) -> Result<VerifiedRenameContentPublication<'session, 'backend>, BackendError> {
    let remote = &session.remote;
    let unavailable = || BackendError::Unavailable;
    if !std::ptr::eq(source_content.session, session)
        || source_content.byte_len != remote.source().remote.byte_len
        || !remote.renamed.get()
        || !readback.source_absent()
    {
        return Err(unavailable());
    }
    remote
        .ensure_authorized(&remote.intent)
        .map_err(|_| unavailable())?;
    let recorded = remote.observed.borrow().clone().ok_or_else(unavailable)?;
    if !recorded.1 || recorded.0 != *readback.destination() {
        return Err(unavailable());
    }

    // Recheck the factual rename both sides of the full GET, before any
    // publication lock is acquired.
    let before = remote.observe(&remote.intent).map_err(|_| unavailable())?;
    if !same_readback(&before, readback) {
        return Err(unavailable());
    }

    let source = remote.source();
    let report = readback.destination();
    if report.content.is_some()
        || report.remote.resource_id != source.remote.resource_id
        || report.remote.byte_len != source_content.byte_len
        || !strong(&report.remote.etag)
    {
        return Err(unavailable());
    }
    let proof = full_revision_read(
        remote,
        &remote.destination_relative,
        &report.remote.resource_id,
        &report.remote.etag,
        report.remote.byte_len,
        source_content.sha256,
    )
    .map_err(|_| unavailable())?;
    remote
        .ensure_authorized(&remote.intent)
        .map_err(|_| unavailable())?;
    if !matches_revision_read(
        &proof,
        &remote.destination_path,
        &report.remote.resource_id,
        &report.remote.etag,
        report.remote.byte_len,
        &source_content.sha256,
    ) {
        remote.authoritative(refusal(ErrorKind::Conflict));
        return Err(unavailable());
    }

    let after = remote.observe(&remote.intent).map_err(|_| unavailable())?;
    if !same_readback(&after, readback) {
        remote.authoritative(refusal(ErrorKind::Conflict));
        return Err(unavailable());
    }
    remote
        .ensure_authorized(&remote.intent)
        .map_err(|_| unavailable())?;

    let publication = session
        .prepare_verified_file_rename(readback)
        .map_err(|_| unavailable())?;
    Ok(VerifiedRenameContentPublication {
        publication,
        sha256: source_content.sha256,
        byte_len: source_content.byte_len,
    })
}

fn require_source(remote: &LiveFileRename<'_>) -> Result<(), CloudError> {
    match remote.leaf(&remote.source_relative)? {
        OrdinaryTargetPresence::Present(entry) if remote.checked_source(&entry) => Ok(()),
        OrdinaryTargetPresence::Present(_) => {
            Err(remote.authoritative(refusal(ErrorKind::Conflict)))
        }
        OrdinaryTargetPresence::Absent => Err(remote.authoritative(refusal(ErrorKind::NotFound))),
    }
}

fn full_revision_read(
    remote: &LiveFileRename<'_>,
    relative_path: &str,
    resource_id: &str,
    etag: &str,
    byte_len: u64,
    expected_sha256: [u8; 32],
) -> Result<RecoveryStreamReadback, CloudError> {
    let scope = &remote.source().local.parent.scope;
    remote
        .backend
        .client
        .recovery_read_digest_cancellable_with_context(
            &scope.space_id,
            &remote.root_path,
            &scope.root_resource_id,
            relative_path,
            resource_id,
            etag,
            byte_len,
            expected_sha256,
            remote.context,
            Arc::clone(&remote.cancelled),
        )
        .map_err(|error| remote.authoritative(error))
}

fn matches_revision_read(
    proof: &RecoveryStreamReadback,
    expected_path: &str,
    resource_id: &str,
    etag: &str,
    byte_len: u64,
    sha256: &[u8; 32],
) -> bool {
    proof.entry.path.trim_end_matches('/') == expected_path.trim_end_matches('/')
        && proof.entry.id == resource_id
        && proof.entry.etag == etag
        && proof.entry.size == byte_len
        && proof.bytes == byte_len
        && proof.sha256 == *sha256
        && !proof.entry.directory
        && !proof.entry.encrypted
        && proof.entry.writable
}

fn same_readback(
    observation: &crate::namespace_file_rename::FileRenameObservation,
    readback: &FileRenameReadback,
) -> bool {
    observation.source_absent && observation.destination == *readback.destination()
}
