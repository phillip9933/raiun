//! Bounded online copy between two independently unlocked vault roots.
//!
//! This is intentionally copy-only. The source is never modified or deleted.

use super::*;
use crate::async_body;
use std::{fs::File, io::Cursor, sync::Arc};
use tempfile::NamedTempFile;

const MAX_CROSS_VAULT_COPY_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultCopyRequest {
    pub source_scope: VaultSessionScope,
    pub destination_scope: VaultSessionScope,
    pub source_path: String,
    pub source_resource_id: String,
    pub source_etag: String,
    pub destination_path: String,
    pub destination_parent_resource_id: String,
    pub destination_parent_etag: String,
    pub source_auth_generation: u64,
    pub destination_auth_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultCopyReconciliationReason {
    DestinationCreateUncertain,
    DestinationConflict,
    DestinationReadbackUnavailable,
    DestinationReadbackMismatch,
    SourceChangedAfterCopy,
    AuthenticationGenerationChanged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultCopyResolutionReason {
    LegacySourceBindingUnavailable,
    CopyWasNeverAttempted,
    SourceScopeMismatch,
    SourceChanged,
    DestinationChanged,
    ContentMismatch,
    AuthenticationGenerationChanged,
    VerificationUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultCopyResolutionOutcome {
    Verified {
        destination: RemoteEntry,
        plaintext_len: u64,
        plaintext_sha256: String,
    },
    NeedsReview {
        write_id: String,
        revision: u64,
        reason: VaultCopyResolutionReason,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultCopyOutcome {
    Copied {
        destination: RemoteEntry,
        plaintext_len: u64,
        plaintext_sha256: String,
    },
    NeedsReconciliation {
        destination_scope: VaultSessionScope,
        destination_path: String,
        destination_resource_id: Option<String>,
        destination_etag: Option<String>,
        write_id: String,
        revision: u64,
        reason: VaultCopyReconciliationReason,
    },
}

impl VaultBackend {
    /// Resolve an interrupted CopyFile using two independently unlocked,
    /// exact-scope backends. This is read-only remotely: it never retries a
    /// PUT or removes a source. A row is retired only after source and
    /// destination identities and decrypted content are verified again.
    ///
    /// When the original conditional PUT response was lost, the journal has
    /// no destination resource ID or ETag to prove which actor created the
    /// current entry. This check proves that the original source identity is
    /// unchanged and that the exact destination path under the recorded stable
    /// parent currently decrypts to the source's sealed length and digest. It
    /// does not claim exclusive authorship if another actor independently
    /// created identical plaintext at that path.
    pub fn resolve_pending_copy_to(
        &self,
        destination: &VaultBackend,
        write_id: &str,
        revision: u64,
    ) -> Result<VaultCopyResolutionOutcome, CloudError> {
        self.resolve_pending_copy_to_cancellable(destination, write_id, revision, || false)
    }

    /// Variant for agent jobs that can be cancelled during verification. The
    /// predicate is checked under both token-generation and unlocked-session
    /// guards immediately before local journal retirement.
    pub fn resolve_pending_copy_to_cancellable(
        &self,
        destination: &VaultBackend,
        write_id: &str,
        revision: u64,
        cancelled: impl Fn() -> bool,
    ) -> Result<VaultCopyResolutionOutcome, CloudError> {
        self.resolve_pending_copy_to_cancellable_with_hook(
            destination,
            write_id,
            revision,
            cancelled,
            || {},
        )
    }

    /// Same as [`Self::resolve_pending_copy_to_cancellable`], with a narrow
    /// completion-admission hook used to test cancellation at the local CAS
    /// boundary. Production callers should use the simpler method above.
    #[doc(hidden)]
    pub fn resolve_pending_copy_to_cancellable_with_hook(
        &self,
        destination: &VaultBackend,
        write_id: &str,
        revision: u64,
        cancelled: impl Fn() -> bool,
        before_completion_admission: impl FnOnce(),
    ) -> Result<VaultCopyResolutionOutcome, CloudError> {
        let check_cancelled = || {
            if cancelled() {
                Err(CloudError::new(
                    ErrorKind::Forbidden,
                    "copy verification was cancelled",
                ))
            } else {
                Ok(())
            }
        };
        check_cancelled()?;
        if self.offline_only || destination.offline_only {
            return Err(CloudError::new(
                ErrorKind::Offline,
                "copy resolution requires online vault roots",
            ));
        }
        let cache = destination.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Unsupported,
                "copy resolution requires its durable destination journal",
            )
        })?;
        let operation = cache.pending_operation(&destination.sessions, write_id, revision)?;
        if operation.operation != VaultPendingOperationKind::CopyFile {
            return Err(conflict("encrypted journal row is not a copy"));
        }
        let needs_review = |reason| VaultCopyResolutionOutcome::NeedsReview {
            write_id: operation.id.clone(),
            revision: operation.revision,
            reason,
        };
        let review = |reason| Ok(needs_review(reason));
        let Some(source_binding) = operation.copy_source.as_ref() else {
            return review(VaultCopyResolutionReason::LegacySourceBindingUnavailable);
        };
        check_cancelled()?;
        if !matches!(
            operation.state,
            CiphertextWriteState::Attempting | CiphertextWriteState::Uncertain
        ) {
            return review(VaultCopyResolutionReason::CopyWasNeverAttempted);
        }
        if self.scope == destination.scope
            || source_binding.account_id != self.scope.account_id()
            || source_binding.server_origin != self.scope.server_origin()
            || source_binding.space_id != self.scope.space_id()
            || source_binding.root_resource_id != self.scope.resource_id()
            || source_binding.root_path != self.root_path
            || destination.scope == self.scope
        {
            return review(VaultCopyResolutionReason::SourceScopeMismatch);
        }
        let (Some(parent_ref), false) = (
            operation.parent_ref.as_ref(),
            operation.path == "/" || operation.parent_resource_id.is_empty(),
        ) else {
            return review(VaultCopyResolutionReason::DestinationChanged);
        };
        let expected_parent = match parent_ref {
            VaultPendingParentRef::Stable { resource_id } => resource_id,
            VaultPendingParentRef::PendingCreate { .. } => {
                return review(VaultCopyResolutionReason::DestinationChanged);
            }
        };
        if expected_parent != &operation.parent_resource_id
            || !destination
                .sessions
                .is_unlocked(&destination.scope)
                .map_err(vault_error)?
            || !self
                .sessions
                .is_unlocked(&self.scope)
                .map_err(vault_error)?
        {
            return review(VaultCopyResolutionReason::SourceScopeMismatch);
        }

        let source_generation = self.client.token_generation();
        let destination_generation = destination.client.token_generation();
        let verified =
            (|| -> Result<(RemoteEntry, u64, String), (VaultCopyResolutionReason, CloudError)> {
                let (source_entry, source_plaintext) = self
                    .read_bounded_plaintext_cancellable(
                        &source_binding.path,
                        &source_binding.resource_id,
                        &source_binding.etag,
                        source_generation,
                        &cancelled,
                    )
                    .map_err(|error| {
                        let reason = if self.client.token_generation() != source_generation {
                            VaultCopyResolutionReason::AuthenticationGenerationChanged
                        } else if error.kind == ErrorKind::Conflict {
                            VaultCopyResolutionReason::SourceChanged
                        } else {
                            VaultCopyResolutionReason::VerificationUnavailable
                        };
                        (reason, error)
                    })?;
                let source_hash = hex_digest(&Sha256::digest(&*source_plaintext));
                if source_entry.size != source_binding.plaintext_len
                    || source_plaintext.len() as u64 != source_binding.plaintext_len
                    || source_hash != source_binding.plaintext_sha256
                {
                    return Err((
                        VaultCopyResolutionReason::ContentMismatch,
                        conflict("copy source content no longer matches its sealed binding"),
                    ));
                }
                drop(source_plaintext);

                check_cancelled()
                    .map_err(|error| (VaultCopyResolutionReason::VerificationUnavailable, error))?;
                let destination_state = destination
                    .revalidate_root()
                    .map_err(|error| (VaultCopyResolutionReason::VerificationUnavailable, error))?;
                let parent = destination
                    .current_parent_binding(&operation.path)
                    .map_err(|error| (VaultCopyResolutionReason::VerificationUnavailable, error))?;
                if parent.0 != operation.parent_resource_id {
                    return Err((
                        VaultCopyResolutionReason::DestinationChanged,
                        conflict("copy destination parent identity changed"),
                    ));
                }
                let destination_entry = destination
                    .stat_raw(&destination_state, &operation.path)
                    .map_err(|error| {
                    let reason =
                        if error.kind == ErrorKind::NotFound || error.kind == ErrorKind::Conflict {
                            VaultCopyResolutionReason::DestinationChanged
                        } else {
                            VaultCopyResolutionReason::VerificationUnavailable
                        };
                    (reason, error)
                })?;
                check_cancelled()
                    .map_err(|error| (VaultCopyResolutionReason::VerificationUnavailable, error))?;
                if destination_entry.directory
                    || destination_entry.path != operation.path
                    || destination_entry.size != source_binding.plaintext_len
                    || validate_strong_etag(&destination_entry.etag).is_err()
                {
                    return Err((
                        VaultCopyResolutionReason::DestinationChanged,
                        conflict("copy destination identity or size changed"),
                    ));
                }
                let (readback_entry, destination_plaintext) = destination
                    .read_bounded_plaintext_cancellable(
                        &operation.path,
                        &destination_entry.id,
                        &destination_entry.etag,
                        destination_generation,
                        &cancelled,
                    )
                    .map_err(|error| {
                        let reason =
                            if destination.client.token_generation() != destination_generation {
                                VaultCopyResolutionReason::AuthenticationGenerationChanged
                            } else if error.kind == ErrorKind::Conflict {
                                VaultCopyResolutionReason::DestinationChanged
                            } else {
                                VaultCopyResolutionReason::VerificationUnavailable
                            };
                        (reason, error)
                    })?;
                let destination_hash = hex_digest(&Sha256::digest(&*destination_plaintext));
                if readback_entry.id != destination_entry.id
                    || readback_entry.etag != destination_entry.etag
                    || readback_entry.size != source_binding.plaintext_len
                    || destination_plaintext.len() as u64 != source_binding.plaintext_len
                    || destination_hash != source_binding.plaintext_sha256
                {
                    return Err((
                        VaultCopyResolutionReason::ContentMismatch,
                        conflict("copy destination content does not match its sealed source"),
                    ));
                }
                drop(destination_plaintext);
                check_cancelled()
                    .map_err(|error| (VaultCopyResolutionReason::VerificationUnavailable, error))?;
                if self.client.token_generation() != source_generation
                    || destination.client.token_generation() != destination_generation
                {
                    return Err((
                        VaultCopyResolutionReason::AuthenticationGenerationChanged,
                        conflict("copy authentication generation changed during resolution"),
                    ));
                }
                let source_state = self
                    .revalidate_root()
                    .map_err(|error| (VaultCopyResolutionReason::VerificationUnavailable, error))?;
                let source_after = self
                    .stat_raw(&source_state, &source_binding.path)
                    .map_err(|error| (VaultCopyResolutionReason::VerificationUnavailable, error))?;
                check_cancelled()
                    .map_err(|error| (VaultCopyResolutionReason::VerificationUnavailable, error))?;
                if source_after.directory
                    || source_after.id != source_binding.resource_id
                    || source_after.etag != source_binding.etag
                    || source_after.size != source_binding.plaintext_len
                {
                    return Err((
                        VaultCopyResolutionReason::SourceChanged,
                        conflict("copy source identity changed during resolution"),
                    ));
                }
                let destination_final_state = destination
                    .revalidate_root()
                    .map_err(|error| (VaultCopyResolutionReason::VerificationUnavailable, error))?;
                let destination_parent = destination
                    .current_parent_binding(&operation.path)
                    .map_err(|error| (VaultCopyResolutionReason::VerificationUnavailable, error))?;
                if destination_parent.0 != operation.parent_resource_id {
                    return Err((
                        VaultCopyResolutionReason::DestinationChanged,
                        conflict("copy destination parent changed during resolution"),
                    ));
                }
                let destination_after = destination
                    .stat_raw(&destination_final_state, &operation.path)
                    .map_err(|error| {
                        let reason = if error.kind == ErrorKind::NotFound
                            || error.kind == ErrorKind::Conflict
                        {
                            VaultCopyResolutionReason::DestinationChanged
                        } else {
                            VaultCopyResolutionReason::VerificationUnavailable
                        };
                        (reason, error)
                    })?;
                check_cancelled()
                    .map_err(|error| (VaultCopyResolutionReason::VerificationUnavailable, error))?;
                if destination_after.directory
                    || destination_after.id != destination_entry.id
                    || destination_after.etag != destination_entry.etag
                    || destination_after.size != source_binding.plaintext_len
                {
                    return Err((
                        VaultCopyResolutionReason::DestinationChanged,
                        conflict("copy destination identity changed during resolution"),
                    ));
                }
                if self.client.token_generation() != source_generation
                    || destination.client.token_generation() != destination_generation
                {
                    return Err((
                        VaultCopyResolutionReason::AuthenticationGenerationChanged,
                        conflict("copy authentication generation changed during resolution"),
                    ));
                }
                Ok((
                    destination_after,
                    source_binding.plaintext_len,
                    source_binding.plaintext_sha256.clone(),
                ))
            })();

        let (entry, plaintext_len, plaintext_sha256) = match verified {
            Ok(verified) => verified,
            Err((reason, _error)) => return review(reason),
        };
        before_completion_admission();
        retire_verified_copy(
            CopyOperationGuard {
                source_client: &self.client,
                destination_client: &destination.client,
                source_sessions: &self.sessions,
                source_scope: &self.scope,
                destination_sessions: &destination.sessions,
                destination_scope: &destination.scope,
                cache,
                operation: &operation,
                source_generation,
                destination_generation,
            },
            || {},
            &cancelled,
        )?;
        Ok(VaultCopyResolutionOutcome::Verified {
            destination: entry,
            plaintext_len,
            plaintext_sha256,
        })
    }

    /// Copy one regular file between two distinct, online vault roots.
    ///
    /// Every input scope and version is checked against the bound backends.
    /// Plaintext is capped at 16 MiB and held only in a zeroizing buffer; the
    /// encrypted destination create is durably journaled before PUT. An
    /// uncertain result never deletes the source and never retries/clobbers.
    pub fn copy_file_to(
        &self,
        destination: &VaultBackend,
        request: &VaultCopyRequest,
    ) -> Result<VaultCopyOutcome, CloudError> {
        self.copy_file_to_cancellable(destination, request, &|| false)
    }

    /// Cancellation before the durable claim leaves the copy unattempted.
    /// After claim, retain the journal whenever completion cannot be admitted;
    /// cancellation never authorizes retrying or deleting either remote copy.
    pub fn copy_file_to_cancellable(
        &self,
        destination: &VaultBackend,
        request: &VaultCopyRequest,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<VaultCopyOutcome, CloudError> {
        self.copy_file_to_cancellable_with_binding(destination, request, cancelled, |_, _| {})
    }

    /// Copy one file and publish the exact durable journal binding as soon as
    /// the destination journal row is queued, before any later cancellation,
    /// generation, admission, or network result can be returned.
    ///
    /// The callback receives only the opaque write ID and revision. If the
    /// operation is cancelled before queueing, it is not called. Once called,
    /// the row is durable and remains available for inspection after later
    /// errors or cancellation. A successful copy may retire the row, so the
    /// published binding is historical metadata, not a guarantee that the row
    /// still exists.
    pub fn copy_file_to_cancellable_with_binding(
        &self,
        destination: &VaultBackend,
        request: &VaultCopyRequest,
        cancelled: &dyn Fn() -> bool,
        publish_binding: impl FnOnce(&str, u64),
    ) -> Result<VaultCopyOutcome, CloudError> {
        if cancelled() {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "cross-vault copy was cancelled",
            ));
        }
        if self.offline_only || destination.offline_only {
            return Err(CloudError::new(
                ErrorKind::Offline,
                "cross-vault copy requires online vault roots",
            ));
        }
        if request.source_scope != self.scope
            || request.destination_scope != destination.scope
            || self.scope == destination.scope
        {
            return Err(invalid("cross-vault copy scope does not match its roots"));
        }
        if self.client.token_generation() != request.source_auth_generation
            || destination.client.token_generation() != request.destination_auth_generation
        {
            return Err(conflict(
                "cross-vault copy authentication generation changed",
            ));
        }
        validate_strong_etag(&request.source_etag)?;
        validate_strong_etag(&request.destination_parent_etag)?;
        if request.source_resource_id.is_empty()
            || request.source_resource_id.len() > 512
            || request.destination_parent_resource_id.is_empty()
            || request.destination_parent_resource_id.len() > 512
        {
            return Err(invalid("cross-vault copy resource identity is invalid"));
        }
        let source_path = normalize_virtual_path(&request.source_path)?;
        let destination_path = normalize_virtual_path(&request.destination_path)?;
        validate_virtual_path(&source_path)?;
        validate_virtual_path(&destination_path)?;
        if source_path == "/" || destination_path == "/" {
            return Err(invalid("cross-vault copy requires regular file paths"));
        }

        let (source_entry, plaintext) = self.read_bounded_plaintext_cancellable(
            &source_path,
            &request.source_resource_id,
            &request.source_etag,
            request.source_auth_generation,
            cancelled,
        )?;
        let plaintext_len = u64::try_from(plaintext.len())
            .map_err(|_| invalid("cross-vault copy length is invalid"))?;
        let digest = hex_digest(&Sha256::digest(&*plaintext));
        let source_binding = VaultCopySourceBinding {
            account_id: self.scope.account_id().to_owned(),
            server_origin: self.scope.server_origin().to_owned(),
            space_id: self.scope.space_id().to_owned(),
            root_resource_id: self.scope.resource_id().to_owned(),
            root_path: self.root_path.clone(),
            path: source_path.clone(),
            resource_id: source_entry.id.clone(),
            etag: source_entry.etag.clone(),
            plaintext_len,
            plaintext_sha256: digest.clone(),
        };

        let parent_ref = VaultPendingParentRef::Stable {
            resource_id: request.destination_parent_resource_id.clone(),
        };
        let (parent_id, parent_etag) = destination.current_parent_binding(&destination_path)?;
        if parent_id != request.destination_parent_resource_id
            || parent_etag != request.destination_parent_etag
        {
            return Err(conflict("cross-vault destination parent changed"));
        }
        let encoded_target = destination.prepare_file_create_target_for_parent(
            &destination_path,
            &parent_ref,
            None,
        )?;
        if destination.client.token_generation() != request.destination_auth_generation {
            return Err(conflict(
                "cross-vault copy authentication generation changed",
            ));
        }
        let state = destination.revalidate_root()?;
        if !state.space.writable {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "cross-vault destination is read only",
            ));
        }
        let cache = destination.offline_cache.as_ref().ok_or_else(|| {
            CloudError::new(
                ErrorKind::Unsupported,
                "cross-vault copy requires a durable destination journal",
            )
        })?;
        let mut journal_body = Cursor::new(&*plaintext);
        let mut metadata = cache.queue_copy_file(
            &destination.sessions,
            &mut journal_body,
            VaultPendingCreateRequest {
                integrity_token: &state.integrity_token,
                encoded_target: &encoded_target,
                existing_id: None,
                parent_resource_id: Some(&parent_id),
                parent_etag: Some(&parent_etag),
                parent_ref: &parent_ref,
                body_len: plaintext_len,
                // This durable operation class is excluded from generic
                // CreateFile retry/reconciliation even before dispatch.
                state: CiphertextWriteState::NeverAttempted,
            },
            &source_binding,
        )?;
        publish_binding(&metadata.id, metadata.revision);

        if self.client.token_generation() != request.source_auth_generation
            || destination.client.token_generation() != request.destination_auth_generation
        {
            return Ok(needs_reconciliation(
                destination,
                &destination_path,
                None,
                None,
                metadata.id,
                metadata.revision,
                VaultCopyReconciliationReason::AuthenticationGenerationChanged,
            ));
        }

        // Revalidate permissions and both auth generations immediately before
        // the durable attempt claim. Generic restart recovery recognizes the
        // CopyFile discriminator and cannot dispatch this row.
        let fresh_state = destination.revalidate_root()?;
        if !fresh_state.space.writable {
            return Ok(needs_reconciliation(
                destination,
                &destination_path,
                None,
                None,
                metadata.id,
                metadata.revision,
                VaultCopyReconciliationReason::DestinationConflict,
            ));
        }
        if self.client.token_generation() != request.source_auth_generation
            || destination.client.token_generation() != request.destination_auth_generation
        {
            return Ok(needs_reconciliation(
                destination,
                &destination_path,
                None,
                None,
                metadata.id,
                metadata.revision,
                VaultCopyReconciliationReason::AuthenticationGenerationChanged,
            ));
        }
        claim_copy_attempt(
            CopyOperationGuard {
                source_client: &self.client,
                destination_client: &destination.client,
                source_sessions: &self.sessions,
                source_scope: &self.scope,
                destination_sessions: &destination.sessions,
                destination_scope: &destination.scope,
                cache,
                operation: &metadata,
                source_generation: request.source_auth_generation,
                destination_generation: request.destination_auth_generation,
            },
            || {},
            cancelled,
        )?;
        metadata.state = CiphertextWriteState::Attempting;

        if cancelled() {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "cross-vault copy was cancelled after attempt admission",
            ));
        }
        let mut upload_body = Cursor::new(&*plaintext);
        let uploaded = destination.put_vault_reader(
            &state,
            &destination_path,
            &mut upload_body,
            plaintext_len,
            WriteCondition::Absent,
            VaultPutExpectation {
                encoded_target: Some(&encoded_target),
                parent_binding: Some((&parent_id, &parent_etag)),
                expected_token_generation: Some(request.destination_auth_generation),
                caller_cancelled: Some(cancelled),
                external_token_generation: Some((
                    Arc::clone(&self.client.token_generation),
                    request.source_auth_generation,
                )),
            },
        );
        let uploaded = match uploaded {
            Ok(entry) => entry,
            Err(error) => {
                let reason = if self.client.token_generation() != request.source_auth_generation
                    || destination.client.token_generation() != request.destination_auth_generation
                {
                    VaultCopyReconciliationReason::AuthenticationGenerationChanged
                } else if error.kind == ErrorKind::Conflict {
                    VaultCopyReconciliationReason::DestinationConflict
                } else {
                    VaultCopyReconciliationReason::DestinationCreateUncertain
                };
                cache.set_pending_edit_state(
                    &metadata.id,
                    metadata.revision,
                    if error.kind == ErrorKind::Conflict {
                        CiphertextWriteState::Conflict
                    } else {
                        CiphertextWriteState::Uncertain
                    },
                )?;
                return Ok(needs_reconciliation(
                    destination,
                    &destination_path,
                    None,
                    None,
                    metadata.id,
                    metadata.revision,
                    reason,
                ));
            }
        };

        if uploaded.directory
            || uploaded.path != destination_path
            || uploaded.id.is_empty()
            || uploaded.size != plaintext_len
            || validate_strong_etag(&uploaded.etag).is_err()
        {
            cache.set_pending_edit_state(
                &metadata.id,
                metadata.revision,
                CiphertextWriteState::Uncertain,
            )?;
            return Ok(needs_reconciliation(
                destination,
                &destination_path,
                Some(uploaded.id),
                Some(uploaded.etag),
                metadata.id,
                metadata.revision,
                VaultCopyReconciliationReason::DestinationReadbackMismatch,
            ));
        }
        if self.client.token_generation() != request.source_auth_generation
            || destination.client.token_generation() != request.destination_auth_generation
        {
            cache.set_pending_edit_state(
                &metadata.id,
                metadata.revision,
                CiphertextWriteState::Uncertain,
            )?;
            return Ok(needs_reconciliation(
                destination,
                &destination_path,
                Some(uploaded.id),
                Some(uploaded.etag),
                metadata.id,
                metadata.revision,
                VaultCopyReconciliationReason::AuthenticationGenerationChanged,
            ));
        }

        let readback = destination.read_bounded_plaintext_cancellable(
            &destination_path,
            &uploaded.id,
            &uploaded.etag,
            request.destination_auth_generation,
            cancelled,
        );
        let (readback, readback_reason) = match readback {
            Ok((entry, bytes)) => {
                let matches = !entry.directory
                    && entry.id == uploaded.id
                    && entry.etag == uploaded.etag
                    && entry.size == plaintext_len
                    && bytes.len() as u64 == plaintext_len
                    && Sha256::digest(&*bytes).as_slice() == Sha256::digest(&*plaintext).as_slice();
                if matches {
                    (
                        Some(entry),
                        VaultCopyReconciliationReason::DestinationReadbackUnavailable,
                    )
                } else {
                    (
                        None,
                        VaultCopyReconciliationReason::DestinationReadbackMismatch,
                    )
                }
            }
            Err(_) => (
                None,
                VaultCopyReconciliationReason::DestinationReadbackUnavailable,
            ),
        };
        let Some(verified_destination) = readback else {
            let reason =
                if destination.client.token_generation() != request.destination_auth_generation {
                    VaultCopyReconciliationReason::AuthenticationGenerationChanged
                } else {
                    readback_reason
                };
            cache.set_pending_edit_state(
                &metadata.id,
                metadata.revision,
                CiphertextWriteState::Uncertain,
            )?;
            return Ok(needs_reconciliation(
                destination,
                &destination_path,
                Some(uploaded.id),
                Some(uploaded.etag),
                metadata.id,
                metadata.revision,
                reason,
            ));
        };

        let source_still_matches = self
            .revalidate_root()
            .and_then(|state| self.stat_raw(&state, &source_path))
            .is_ok_and(|entry| {
                !entry.directory
                    && entry.id == source_entry.id
                    && entry.etag == source_entry.etag
                    && entry.size == source_entry.size
            });
        if !source_still_matches {
            cache.set_pending_edit_state(
                &metadata.id,
                metadata.revision,
                CiphertextWriteState::Conflict,
            )?;
            return Ok(needs_reconciliation(
                destination,
                &destination_path,
                Some(verified_destination.id),
                Some(verified_destination.etag),
                metadata.id,
                metadata.revision,
                VaultCopyReconciliationReason::SourceChangedAfterCopy,
            ));
        }
        if self.client.token_generation() != request.source_auth_generation
            || destination.client.token_generation() != request.destination_auth_generation
        {
            cache.set_pending_edit_state(
                &metadata.id,
                metadata.revision,
                CiphertextWriteState::Conflict,
            )?;
            return Ok(needs_reconciliation(
                destination,
                &destination_path,
                Some(verified_destination.id),
                Some(verified_destination.etag),
                metadata.id,
                metadata.revision,
                VaultCopyReconciliationReason::AuthenticationGenerationChanged,
            ));
        }
        retire_verified_copy(
            CopyOperationGuard {
                source_client: &self.client,
                destination_client: &destination.client,
                source_sessions: &self.sessions,
                source_scope: &self.scope,
                destination_sessions: &destination.sessions,
                destination_scope: &destination.scope,
                cache,
                operation: &metadata,
                source_generation: request.source_auth_generation,
                destination_generation: request.destination_auth_generation,
            },
            || {},
            cancelled,
        )?;
        Ok(VaultCopyOutcome::Copied {
            destination: verified_destination,
            plaintext_len,
            plaintext_sha256: digest,
        })
    }

    fn read_bounded_plaintext_cancellable(
        &self,
        path: &str,
        expected_id: &str,
        expected_etag: &str,
        expected_generation: u64,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(RemoteEntry, zeroize::Zeroizing<Vec<u8>>), CloudError> {
        if cancelled() || self.client.token_generation() != expected_generation {
            return Err(conflict(
                "cross-vault copy authentication generation changed",
            ));
        }
        let state = self.revalidate_root()?;
        let before = self.stat_raw(&state, path)?;
        if before.directory || before.id != expected_id || before.etag != expected_etag {
            return Err(conflict("cross-vault copy source identity changed"));
        }
        validate_strong_etag(&before.etag)?;
        if before.size > MAX_CROSS_VAULT_COPY_BYTES {
            return Err(CloudError::new(
                ErrorKind::Unsupported,
                "cross-vault copy exceeds the 16 MiB limit",
            ));
        }
        let ciphertext_len = ciphertext_len_from_plaintext(before.size)?;
        let url = self.target_url(&state, path)?;
        let mut ciphertext = NamedTempFile::new().map_err(io_error)?;
        let output = ciphertext.as_file().try_clone().map_err(io_error)?;
        let (request, token) = self.client.request_async(Method::GET, &url)?;
        let budget = self.client.transfer_budget();
        let cancellation = budget.cancellation();
        let watchdog_cancellation = cancellation.clone();
        let timeout = crate::transfer_timeout_with_budget(
            &budget,
            TransferDirection::Download,
            ciphertext_len,
        );
        let expected_etag = before.etag.clone();
        let client = self.client.clone();
        let body_client = self.client.clone();
        let copied = async_body::run_body_operation_cancellable(
            self.client.body_idle_timeout(),
            timeout,
            move || {
                watchdog_cancellation.is_cancelled()
                    || cancelled()
                    || client.token_generation() != expected_generation
            },
            move |progress| async move {
                let response = request
                    .header(IF_MATCH, expected_etag.as_str())
                    .timeout(timeout)
                    .send()
                    .await
                    .map_err(network)?;
                let mut response = crate::checked_async(response, &[StatusCode::OK], &token)?;
                if response.content_length() != Some(ciphertext_len) {
                    return Err(conflict("cross-vault ciphertext length changed"));
                }
                let mut output = tokio::fs::File::from_std(output);
                let copied = async_body::copy_response_body(
                    &mut response,
                    &mut output,
                    ciphertext_len,
                    &budget,
                    move || {
                        cancellation.is_cancelled()
                            || cancelled()
                            || body_client.token_generation() != expected_generation
                    },
                    &progress,
                )
                .await?;
                use tokio::io::AsyncWriteExt;
                output.flush().await.map_err(io_error)?;
                output.sync_all().await.map_err(io_error)?;
                Ok(copied)
            },
        )?;
        if copied != ciphertext_len {
            return Err(invalid("cross-vault ciphertext length is invalid"));
        }
        if cancelled() {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "copy verification was cancelled",
            ));
        }
        ciphertext.as_file_mut().flush().map_err(io_error)?;
        ciphertext.as_file().sync_all().map_err(io_error)?;
        if self.client.token_generation() != expected_generation {
            return Err(conflict(
                "cross-vault copy authentication generation changed",
            ));
        }
        let after_state = self.revalidate_root()?;
        if cancelled() {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "copy verification was cancelled",
            ));
        }
        let after = self.stat_raw(&after_state, path)?;
        if after.id != before.id || after.etag != before.etag || after.size != before.size {
            return Err(conflict("cross-vault file changed while reading"));
        }
        let mut encrypted = File::open(ciphertext.path()).map_err(io_error)?;
        if cancelled() {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "copy verification was cancelled",
            ));
        }
        let plaintext = self
            .sessions
            .decrypt_file_to_bytes(
                &self.scope,
                &mut encrypted,
                MAX_CROSS_VAULT_COPY_BYTES,
                before.size,
            )
            .map_err(vault_error)?;
        if !self
            .sessions
            .is_unlocked(&self.scope)
            .map_err(vault_error)?
        {
            return Err(CloudError::new(
                ErrorKind::Forbidden,
                "cross-vault copy session was locked",
            ));
        }
        Ok((after, plaintext))
    }
}

/// Bind a copy journal transition while auth and key revocation are excluded. `before_admission` is a private deterministic
/// seam for lifecycle race tests; production passes an empty closure.
struct CopyOperationGuard<'a> {
    source_client: &'a OpenCloudClient,
    destination_client: &'a OpenCloudClient,
    source_sessions: &'a Arc<VaultSessionCoordinator>,
    source_scope: &'a VaultSessionScope,
    destination_sessions: &'a Arc<VaultSessionCoordinator>,
    destination_scope: &'a VaultSessionScope,
    cache: &'a VaultOfflineCache,
    operation: &'a VaultPendingEditMetadata,
    source_generation: u64,
    destination_generation: u64,
}

fn retire_verified_copy(
    guard: CopyOperationGuard<'_>,
    before_admission: impl FnOnce(),
    cancelled: &dyn Fn() -> bool,
) -> Result<(), CloudError> {
    before_admission();
    guard.source_client.with_token_generations(
        guard.destination_client,
        guard.source_generation,
        guard.destination_generation,
        || {
            VaultSessionCoordinator::with_unlocked_scopes_and_sessions(
                guard.source_sessions,
                guard.source_scope,
                guard.destination_sessions,
                guard.destination_scope,
                |_, destination_session| {
                    if cancelled() {
                        return Err(CloudError::new(
                            ErrorKind::Forbidden,
                            "copy verification was cancelled before completion admission",
                        ));
                    }
                    guard
                        .cache
                        .reopen_copy_for_resolution(destination_session, guard.operation)?;
                    guard.cache.retire_resolved_copy(
                        &guard.operation.id,
                        guard.operation.revision,
                        guard.operation.state,
                    )
                },
            )
            .map_err(|_| {
                CloudError::new(
                    ErrorKind::Forbidden,
                    "vault session changed before copy completion",
                )
            })?
        },
    )??;
    Ok(())
}

fn claim_copy_attempt(
    guard: CopyOperationGuard<'_>,
    before_admission: impl FnOnce(),
    cancelled: &dyn Fn() -> bool,
) -> Result<(), CloudError> {
    before_admission();
    guard.source_client.with_token_generations(
        guard.destination_client,
        guard.source_generation,
        guard.destination_generation,
        || {
            VaultSessionCoordinator::with_unlocked_scopes_and_sessions(
                guard.source_sessions,
                guard.source_scope,
                guard.destination_sessions,
                guard.destination_scope,
                |_, destination_session| {
                    if cancelled() {
                        return Err(CloudError::new(
                            ErrorKind::Forbidden,
                            "copy was cancelled before attempt admission",
                        ));
                    }
                    guard
                        .cache
                        .claim_copy_file_attempt_with_session(destination_session, guard.operation)
                },
            )
            .map_err(|_| {
                CloudError::new(
                    ErrorKind::Forbidden,
                    "vault session changed before copy attempt",
                )
            })?
        },
    )??;
    Ok(())
}

fn needs_reconciliation(
    destination: &VaultBackend,
    path: &str,
    resource_id: Option<String>,
    etag: Option<String>,
    write_id: String,
    revision: u64,
    reason: VaultCopyReconciliationReason,
) -> VaultCopyOutcome {
    VaultCopyOutcome::NeedsReconciliation {
        destination_scope: destination.scope.clone(),
        destination_path: path.to_owned(),
        destination_resource_id: resource_id,
        destination_etag: etag,
        write_id,
        revision,
        reason,
    }
}

fn validate_strong_etag(etag: &str) -> Result<(), CloudError> {
    if etag.len() < 2
        || etag.len() > 4_096
        || !etag.starts_with('"')
        || !etag.ends_with('"')
        || etag.starts_with("W/")
        || etag.chars().any(char::is_control)
    {
        return Err(invalid("cross-vault copy requires a strong ETag"));
    }
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

// These integration tests exercise the durable encrypted-cache journal. The
// cache intentionally fails closed on Windows until native ACL validation is
// implemented, so retain the tests on supported private-directory platforms
// and keep Windows' explicit unsupported-platform behavior tested in
// `raiun-cache` itself.
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use raiun_cache::{Cache, CiphertextWriteState};
    use raiun_vault::session::VaultSessionCoordinator;
    use std::{
        fs,
        sync::{Arc, mpsc},
        thread,
        time::Duration,
    };

    const TOKEN: &str = include_str!("../../../raiun-vault/tests/fixtures/web-integrity-token.b64");

    fn scope(account: &str, origin: &str, space: &str, root: &str) -> VaultSessionScope {
        VaultSessionScope::new(account, origin, space, root).unwrap()
    }

    fn unlock(sessions: &VaultSessionCoordinator, scope: &VaultSessionScope) {
        let mut password = b"potato".to_vec();
        sessions.unlock(scope, &mut password, TOKEN.trim()).unwrap();
    }

    type PreparedCopy = (
        tempfile::TempDir,
        OpenCloudClient,
        OpenCloudClient,
        Arc<VaultSessionCoordinator>,
        VaultSessionScope,
        Arc<VaultSessionCoordinator>,
        VaultSessionScope,
        Arc<VaultOfflineCache>,
        VaultPendingEditMetadata,
    );

    fn prepared_copy(claim: bool) -> PreparedCopy {
        let source_scope = scope(
            "source-account",
            "https://source.example",
            "source-space",
            "source-root",
        );
        let destination_scope = scope(
            "destination-account",
            "https://destination.example",
            "destination-space",
            "destination-root",
        );
        let source_sessions = Arc::new(VaultSessionCoordinator::new());
        let destination_sessions = Arc::new(VaultSessionCoordinator::new());
        unlock(&source_sessions, &source_scope);
        unlock(&destination_sessions, &destination_scope);
        let source_client =
            OpenCloudClient::new(source_scope.server_origin(), "synthetic-token".into()).unwrap();
        let destination_client =
            OpenCloudClient::new(destination_scope.server_origin(), "synthetic-token".into())
                .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let cache_root = temp.path().join("cache");
        fs::create_dir(&cache_root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&cache_root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let cache = Cache::open(&cache_root, 8 * 1024 * 1024).unwrap();
        let adapter = Arc::new(
            VaultOfflineCache::new(cache, destination_scope.clone(), "/Destination.vault").unwrap(),
        );
        let target = destination_sessions
            .encrypt_path(&destination_scope, "copied.txt")
            .unwrap();
        let parent = VaultPendingParentRef::Stable {
            resource_id: "destination-parent".into(),
        };
        let plaintext = b"abc";
        let source_binding = VaultCopySourceBinding {
            account_id: source_scope.account_id().to_owned(),
            server_origin: source_scope.server_origin().to_owned(),
            space_id: source_scope.space_id().to_owned(),
            root_resource_id: source_scope.resource_id().to_owned(),
            root_path: "/Source.vault".into(),
            path: "/source.txt".into(),
            resource_id: "source-file".into(),
            etag: "\"source-e1\"".into(),
            plaintext_len: plaintext.len() as u64,
            plaintext_sha256: hex_digest(&Sha256::digest(plaintext)),
        };
        let mut body = Cursor::new(plaintext);
        let queued = adapter
            .queue_copy_file(
                &destination_sessions,
                &mut body,
                VaultPendingCreateRequest {
                    integrity_token: TOKEN.trim(),
                    encoded_target: &target,
                    existing_id: None,
                    parent_resource_id: Some("destination-parent"),
                    parent_etag: Some("\"parent-e1\""),
                    parent_ref: &parent,
                    body_len: plaintext.len() as u64,
                    state: CiphertextWriteState::NeverAttempted,
                },
                &source_binding,
            )
            .unwrap();
        if claim {
            adapter
                .claim_copy_file_attempt(&destination_sessions, &queued.id, queued.revision)
                .unwrap();
        }
        let operation = adapter
            .pending_operation(&destination_sessions, &queued.id, queued.revision)
            .unwrap();
        (
            temp,
            source_client,
            destination_client,
            source_sessions,
            source_scope,
            destination_sessions,
            destination_scope,
            adapter,
            operation,
        )
    }

    #[test]
    fn locked_source_or_cancelled_admission_keeps_copy_never_attempted() {
        for cancel in [false, true] {
            let (
                _temp,
                source_client,
                destination_client,
                source_sessions,
                source_scope,
                destination_sessions,
                destination_scope,
                cache,
                operation,
            ) = prepared_copy(false);
            let result = claim_copy_attempt(
                CopyOperationGuard {
                    source_client: &source_client,
                    destination_client: &destination_client,
                    source_sessions: &source_sessions,
                    source_scope: &source_scope,
                    destination_sessions: &destination_sessions,
                    destination_scope: &destination_scope,
                    cache: &cache,
                    operation: &operation,
                    source_generation: source_client.token_generation(),
                    destination_generation: destination_client.token_generation(),
                },
                || {
                    if !cancel {
                        source_sessions.lock(&source_scope).unwrap();
                    }
                },
                &|| cancel,
            );
            assert!(result.is_err());
            let retained = cache
                .pending_operation(&destination_sessions, &operation.id, operation.revision)
                .unwrap();
            assert_eq!(retained.state, CiphertextWriteState::NeverAttempted);
            assert_eq!(retained, operation);
        }
    }

    #[test]
    fn revocation_before_completion_admission_keeps_copy_journal() {
        for (destination_revocation, revoke_token) in
            [(false, true), (false, false), (true, true), (true, false)]
        {
            let (
                _temp,
                source_client,
                destination_client,
                source_sessions,
                source_scope,
                destination_sessions,
                destination_scope,
                cache,
                operation,
            ) = prepared_copy(true);
            let source_generation = source_client.token_generation();
            let destination_generation = destination_client.token_generation();
            let worker_source_client = source_client.clone();
            let worker_destination_client = destination_client.clone();
            let worker_source_sessions = Arc::clone(&source_sessions);
            let worker_destination_sessions = Arc::clone(&destination_sessions);
            let worker_source_scope = source_scope.clone();
            let worker_destination_scope = destination_scope.clone();
            let worker_cache = Arc::clone(&cache);
            let worker_operation = operation.clone();
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let worker = thread::spawn(move || {
                retire_verified_copy(
                    CopyOperationGuard {
                        source_client: &worker_source_client,
                        destination_client: &worker_destination_client,
                        source_sessions: &worker_source_sessions,
                        source_scope: &worker_source_scope,
                        destination_sessions: &worker_destination_sessions,
                        destination_scope: &worker_destination_scope,
                        cache: &worker_cache,
                        operation: &worker_operation,
                        source_generation,
                        destination_generation,
                    },
                    || {
                        entered_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                    },
                    &|| false,
                )
            });
            entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            if revoke_token {
                if destination_revocation {
                    destination_client
                        .set_bearer_token("rotated-before-completion".into())
                        .unwrap();
                } else {
                    source_client
                        .set_bearer_token("rotated-before-completion".into())
                        .unwrap();
                }
            } else if destination_revocation {
                destination_sessions.lock(&destination_scope).unwrap();
            } else {
                source_sessions.lock(&source_scope).unwrap();
            }
            release_tx.send(()).unwrap();
            assert!(worker.join().unwrap().is_err());
            if !destination_sessions
                .is_unlocked(&destination_scope)
                .unwrap()
            {
                unlock(&destination_sessions, &destination_scope);
            }
            let retained = cache
                .pending_operation(&destination_sessions, &operation.id, operation.revision)
                .unwrap();
            assert_eq!(retained.operation, VaultPendingOperationKind::CopyFile);
            assert_eq!(retained.state, CiphertextWriteState::Attempting);
        }
    }

    #[test]
    fn sealed_copy_target_is_exact_revision_and_never_caller_supplied() {
        let (
            _temp,
            _source_client,
            _destination_client,
            _source_sessions,
            source_scope,
            destination_sessions,
            _destination_scope,
            cache,
            operation,
        ) = prepared_copy(true);
        let target = cache
            .pending_copy_source_target(&destination_sessions, &operation.id, operation.revision)
            .unwrap()
            .expect("v12 copy has sealed source scope");
        assert_eq!(target.scope, source_scope);
        assert_eq!(target.root_path, "/Source.vault");
        assert!(
            cache
                .pending_copy_source_target(
                    &destination_sessions,
                    &operation.id,
                    operation.revision + 1,
                )
                .is_err()
        );
    }
}
