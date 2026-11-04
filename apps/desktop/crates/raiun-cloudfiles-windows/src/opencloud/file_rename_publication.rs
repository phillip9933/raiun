//! Consumed destination catalog publication after a verified same-file rename.
//!
//! This capability does not prove a native rename or atomic parent/source CAS.
//! Callers must perform their own fresh native admission inside the callback.
use super::*;
use crate::namespace_file_rename::{FileRenameCompletionError, FileRenameReadback};
use crate::namespace_intent::NamespaceIntent;
use std::{sync::TryLockError, time::Instant};

/// Non-cloneable permission to publish the new path-derived identity for one
/// session's freshly observed rename. The old source binding is retained.
pub struct VerifiedFileRenamePublication<'session, 'backend> {
    session: &'session FileRenameSession<'backend>,
    readback: &'session FileRenameReadback,
    source_identity: OpaqueIdentity,
    destination_identity: OpaqueIdentity,
    source_binding: FileBinding,
    destination_prior: Option<FileBinding>,
    destination_binding: FileBinding,
    catalog: ProviderIdentityCatalogScope,
}

pub(super) fn prepare<'session, 'backend>(
    session: &'session FileRenameSession<'backend>,
    readback: &'session FileRenameReadback,
) -> Result<VerifiedFileRenamePublication<'session, 'backend>, BackendError> {
    let remote = &session.remote;
    if remote.publication_claimed.get() || !remote.renamed.get() || !readback.source_absent() {
        return Err(BackendError::Unavailable);
    }
    let intent = &remote.intent;
    remote
        .ensure_authorized(intent)
        .map_err(|_| BackendError::Unavailable)?;
    let observed = remote
        .observed
        .borrow()
        .clone()
        .ok_or(BackendError::Unavailable)?;
    if observed.0 != *readback.destination() || !observed.1 {
        return Err(BackendError::Unavailable);
    }
    let fresh = remote
        .observe(intent)
        .map_err(|_| BackendError::Unavailable)?;
    if !fresh.source_absent || fresh.destination != *readback.destination() {
        return Err(BackendError::Unavailable);
    }
    remote
        .ensure_authorized(intent)
        .map_err(|_| BackendError::Unavailable)?;

    let (source, destination) = move_entries(intent).ok_or(BackendError::Unavailable)?;
    let report = readback.destination();
    if report.destination != *destination
        || report.content.is_some()
        || report.remote.resource_id != source.remote.resource_id
        || report.remote.byte_len != source.remote.byte_len
        || !strong(&report.remote.etag)
    {
        return Err(BackendError::Unavailable);
    }

    let backend = remote.backend;
    let scope = backend
        .catalog_scope_snapshot()?
        .ok_or(BackendError::Unavailable)?;
    let expected_scope = &source.local.parent.scope;
    if scope.profile_id != expected_scope.profile_id
        || scope.account_id != expected_scope.account_subject
        || scope.server_origin != expected_scope.server_origin
        || scope.root_volume_serial != expected_scope.root_volume_serial
        || scope.root_file_index != expected_scope.root_file_index
    {
        return Err(BackendError::Unavailable);
    }
    let expected_source_identity = binding_identity(
        &scope,
        "file",
        &[
            &expected_scope.space_id,
            &expected_scope.root_resource_id,
            &remote.source_path,
            &source.remote.resource_id,
        ],
    );
    if expected_source_identity != remote.source_identity {
        return Err(BackendError::Unavailable);
    }
    let destination_identity = binding_identity(
        &scope,
        "file",
        &[
            &expected_scope.space_id,
            &expected_scope.root_resource_id,
            &remote.destination_path,
            &source.remote.resource_id,
        ],
    );
    let source_binding = remote.source_binding.clone();
    let destination_binding = FileBinding {
        space_id: expected_scope.space_id.clone(),
        root_resource_id: expected_scope.root_resource_id.clone(),
        path: remote.destination_path.clone(),
        remote_id: report.remote.resource_id.clone(),
        etag: report.remote.etag.clone(),
        size: report.remote.byte_len,
    };
    let destination_prior = {
        let state = backend
            .state
            .lock()
            .map_err(|_| BackendError::Unavailable)?;
        if state.files.get(&remote.source_identity) != Some(&source_binding) {
            return Err(BackendError::Unavailable);
        }
        let destination_prior = state.files.get(&destination_identity).cloned();
        if let Some(existing) = destination_prior.as_ref() {
            if existing.space_id != destination_binding.space_id
                || existing.root_resource_id != destination_binding.root_resource_id
                || existing.path != destination_binding.path
                || existing.remote_id != destination_binding.remote_id
            {
                return Err(BackendError::Unavailable);
            }
        }
        if state.directories.contains_key(&destination_identity)
            || state
                .namespace_directories
                .contains_key(&destination_identity)
        {
            return Err(BackendError::Unavailable);
        }
        destination_prior
    };
    remote.publication_claimed.set(true);
    Ok(VerifiedFileRenamePublication {
        session,
        readback,
        source_identity: remote.source_identity,
        destination_identity,
        source_binding,
        destination_prior,
        destination_binding,
        catalog: scope,
    })
}

impl VerifiedFileRenamePublication<'_, '_> {
    pub fn intent(&self) -> &NamespaceIntent {
        self.session.intent()
    }
    pub fn source_identity(&self) -> OpaqueIdentity {
        self.source_identity
    }
    pub fn identity(&self) -> OpaqueIdentity {
        self.destination_identity
    }

    /// Preserve the exact typed result from a native/journal completion
    /// callback while still classifying publication rejection before callback
    /// entry and post-callback authorization loss conservatively.
    pub fn publish_file_rename_completion(
        self,
        complete: impl FnOnce() -> Result<(), FileRenameCompletionError>,
    ) -> Result<(), FileRenameCompletionError> {
        let mut callback_result = None;
        let published = self.publish_and_complete(|| {
            let result = complete();
            let publication_result = match result {
                Ok(()) => Ok(()),
                Err(_) => Err(crate::Error::EditRecoveryUnavailable),
            };
            callback_result = Some(result);
            publication_result
        });
        match callback_result {
            Some(Err(error)) => Err(error),
            Some(Ok(())) if published.is_ok() => Ok(()),
            Some(Ok(())) => Err(FileRenameCompletionError::Uncertain),
            None if published.is_err() => Err(FileRenameCompletionError::Unavailable),
            None => Err(FileRenameCompletionError::Uncertain),
        }
    }

    /// Persist the new path-derived catalog binding before invoking the
    /// caller's native-fenced callback. The callback must not re-enter this
    /// backend, acquire its token, or perform HTTP while the state guard is
    /// held. The source binding remains untouched. This orders evidence only;
    /// it is not a native or server-side CAS proof.
    pub fn publish_and_complete<T>(
        self,
        complete: impl FnOnce() -> Result<T, crate::Error>,
    ) -> Result<T, crate::Error> {
        let unavailable = || crate::Error::EditRecoveryUnavailable;
        let remote = &self.session.remote;
        let current = || {
            remote.context.deadline > Instant::now()
                && (remote.owner_current)(remote.source().local.parent.authorization)
                && !(remote.cancelled)()
                && remote.backend.ensure_active().is_ok()
        };
        if !current()
            || !remote.renamed.get()
            || !self.readback.source_absent()
            || !remote
                .observed
                .borrow()
                .as_ref()
                .is_some_and(|(report, absent)| *absent && report == self.readback.destination())
        {
            return Err(unavailable());
        }
        let fresh = remote.observe(&remote.intent).map_err(|_| unavailable())?;
        if !fresh.source_absent || &fresh.destination != self.readback.destination() {
            return Err(unavailable());
        }
        if !current() {
            return Err(unavailable());
        }
        let remaining = remote
            .context
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(unavailable)?;
        let cancellation = CancellationToken::with_timeout(remaining);
        let _permit = remote
            .backend
            .begin_scoped_publish(&cancellation)
            .map_err(|_| unavailable())?;
        if !current() {
            return Err(unavailable());
        }
        let mut state = match remote.backend.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock | TryLockError::Poisoned(_)) => {
                return Err(unavailable());
            }
        };
        if state.files.get(&self.source_identity) != Some(&self.source_binding)
            || state.files.get(&self.destination_identity) != self.destination_prior.as_ref()
            || state.directories.get(&remote.parent_identity) != Some(&remote.parent)
        {
            return Err(unavailable());
        }
        let existing_destination = state.files.get(&self.destination_identity);
        if existing_destination.is_some_and(|existing| {
            existing.space_id != self.destination_binding.space_id
                || existing.root_resource_id != self.destination_binding.root_resource_id
                || existing.path != self.destination_binding.path
                || existing.remote_id != self.destination_binding.remote_id
        }) || state.directories.contains_key(&self.destination_identity)
            || state
                .namespace_directories
                .contains_key(&self.destination_identity)
        {
            return Err(unavailable());
        }
        if existing_destination.is_none() && binding_count(&state) >= MAX_IDENTITY_CATALOG_ENTRIES {
            return Err(unavailable());
        }
        if !current() {
            return Err(unavailable());
        }
        let binding = ProviderIdentityBinding::File {
            identity: *self.destination_identity.as_bytes(),
            space_id: self.destination_binding.space_id.clone(),
            root_resource_id: self.destination_binding.root_resource_id.clone(),
            path: self.destination_binding.path.clone(),
            remote_id: self.destination_binding.remote_id.clone(),
            etag: self.destination_binding.etag.clone(),
            size: self.destination_binding.size,
        };
        remote
            .backend
            .upsert_identity_binding(&self.catalog, &binding)
            .map_err(|_| unavailable())?;
        state
            .files
            .insert(self.destination_identity, self.destination_binding.clone());
        if !current() {
            drop(state);
            return Err(unavailable());
        }
        let result = complete()?;
        if !current() {
            drop(state);
            return Err(unavailable());
        }
        drop(state);
        Ok(result)
    }
}
