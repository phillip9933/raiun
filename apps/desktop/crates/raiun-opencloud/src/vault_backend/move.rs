//! Bounded online cross-vault move of one regular encrypted file.
//!
//! A move is a verified copy followed by the existing journaled conditional
//! source deletion. The destination is never rolled back when source removal
//! cannot be confirmed.

use super::copy::validate_strong_etag;
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultMoveReviewReason {
    CopyNeedsReconciliation,
    CancelledBeforeSourceRemoval,
    AuthenticationGenerationChanged,
    VaultLockedBeforeSourceRemoval,
    SourceChangedAfterCopy,
    DestinationChangedAfterCopy,
    SourceRemovalNotConfirmed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultMoveOutcome {
    /// Source removal received a confirmed successful result.
    Moved { copy: VaultCopyOutcome },
    /// The source delete is durably journaled but not confirmed complete.
    /// The verified destination remains in place.
    SourceRemovalPending {
        copy: VaultCopyOutcome,
        write_id: String,
        revision: u64,
        uncertain: bool,
    },
    /// Source removal was not confirmed. Its exact recovery row is persisted
    /// in Conflict so ordinary delete reconciliation cannot replay it without
    /// a fresh cross-vault destination proof.
    SourceRemovalNeedsReview {
        copy: VaultCopyOutcome,
        write_id: String,
        revision: u64,
    },
    /// The copy outcome is preserved for inspection. No move success is
    /// claimed, and a verified destination is never removed as compensation.
    NeedsReview {
        copy: VaultCopyOutcome,
        reason: VaultMoveReviewReason,
    },
}

impl VaultBackend {
    /// Copy one file between independently unlocked vaults, then conditionally
    /// remove its exact source revision. Both roots and authentication
    /// generations are bound by `request`. The callback publishes the durable
    /// destination-copy journal ID before any destination PUT.
    pub fn move_file_to_cancellable_with_binding(
        &self,
        destination: &VaultBackend,
        request: &VaultCopyRequest,
        cancelled: &dyn Fn() -> bool,
        publish_binding: impl FnOnce(&str, u64),
    ) -> Result<VaultMoveOutcome, CloudError> {
        let copy = self.copy_file_to_cancellable_with_binding_for_move(
            destination,
            request,
            cancelled,
            publish_binding,
        )?;

        let (verified_destination, plaintext_len) = match &copy {
            VaultCopyOutcome::Copied {
                destination,
                plaintext_len,
                ..
            } => (destination.clone(), *plaintext_len),
            VaultCopyOutcome::NeedsReconciliation { .. } => {
                return Ok(VaultMoveOutcome::NeedsReview {
                    copy,
                    reason: VaultMoveReviewReason::CopyNeedsReconciliation,
                });
            }
        };

        let needs_review = |reason| VaultMoveOutcome::NeedsReview {
            copy: copy.clone(),
            reason,
        };
        if cancelled() {
            return Ok(needs_review(
                VaultMoveReviewReason::CancelledBeforeSourceRemoval,
            ));
        }
        if !self
            .client
            .provider_generation_is_current(request.source_auth_generation)
            || !destination
                .client
                .provider_generation_is_current(request.destination_auth_generation)
        {
            return Ok(needs_review(
                VaultMoveReviewReason::AuthenticationGenerationChanged,
            ));
        }
        if !matches!(self.sessions.is_unlocked(&self.scope), Ok(true))
            || !matches!(
                destination.sessions.is_unlocked(&destination.scope),
                Ok(true)
            )
        {
            return Ok(needs_review(
                VaultMoveReviewReason::VaultLockedBeforeSourceRemoval,
            ));
        }

        let source_path = match normalize_virtual_path(&request.source_path) {
            Ok(path) => path,
            Err(_) => return Ok(needs_review(VaultMoveReviewReason::SourceChangedAfterCopy)),
        };
        let destination_path = match normalize_virtual_path(&request.destination_path) {
            Ok(path) => path,
            Err(_) => {
                return Ok(needs_review(
                    VaultMoveReviewReason::DestinationChangedAfterCopy,
                ));
            }
        };

        // Recheck the source first. delete_file_with_queue repeats the exact
        // source ID/ETag and parent checks immediately before its conditional
        // DELETE, closing the remaining source-side race.
        let source_state = match self.revalidate_root() {
            Ok(state) => state,
            Err(_) => return Ok(needs_review(VaultMoveReviewReason::SourceChangedAfterCopy)),
        };
        let source_now = match self.stat_raw(&source_state, &source_path) {
            Ok(entry) => entry,
            Err(_) => return Ok(needs_review(VaultMoveReviewReason::SourceChangedAfterCopy)),
        };
        if source_now.directory
            || source_now.path != source_path
            || source_now.id != request.source_resource_id
            || source_now.etag != request.source_etag
            || source_now.size != plaintext_len
        {
            return Ok(needs_review(VaultMoveReviewReason::SourceChangedAfterCopy));
        }

        // Revalidate the destination directly before source removal. The copy
        // primitive already decrypted and hashed its readback; this exact
        // strong-ETag identity check keeps that proof bound to the current
        // destination revision without downloading the body a second time.
        // The successful Copy may itself advance the parent directory ETag.
        // Bind to its fresh post-copy revision, while requiring that the
        // stable parent resource ID is still the one selected by the caller.
        let post_copy_parent = match destination.current_parent_binding(&destination_path) {
            Ok(parent) => parent,
            Err(_) => {
                return Ok(needs_review(
                    VaultMoveReviewReason::DestinationChangedAfterCopy,
                ));
            }
        };
        if post_copy_parent.0 != request.destination_parent_resource_id
            || validate_strong_etag(&post_copy_parent.1).is_err()
        {
            return Ok(needs_review(
                VaultMoveReviewReason::DestinationChangedAfterCopy,
            ));
        }
        let destination_state = match destination.revalidate_root() {
            Ok(state) => state,
            Err(_) => {
                return Ok(needs_review(
                    VaultMoveReviewReason::DestinationChangedAfterCopy,
                ));
            }
        };
        let destination_now = match destination.stat_raw(&destination_state, &destination_path) {
            Ok(entry) => entry,
            Err(_) => {
                return Ok(needs_review(
                    VaultMoveReviewReason::DestinationChangedAfterCopy,
                ));
            }
        };
        if destination_now.directory
            || destination_now.path != destination_path
            || destination_now.id != verified_destination.id
            || destination_now.etag != verified_destination.etag
            || destination_now.size != plaintext_len
            || validate_strong_etag(&destination_now.etag).is_err()
        {
            return Ok(needs_review(
                VaultMoveReviewReason::DestinationChangedAfterCopy,
            ));
        }
        // No source deletion if another actor changes the selected parent
        // after our copy, even if the destination leaf still appears present.
        let final_parent = match destination.current_parent_binding(&destination_path) {
            Ok(parent) => parent,
            Err(_) => {
                return Ok(needs_review(
                    VaultMoveReviewReason::DestinationChangedAfterCopy,
                ));
            }
        };
        if final_parent != post_copy_parent {
            return Ok(needs_review(
                VaultMoveReviewReason::DestinationChangedAfterCopy,
            ));
        }
        // This is the cancellation admission boundary. The existing guarded
        // delete primitive durably journals removal and may continue after
        // this call even if the caller later cancels; its result is therefore
        // reported as committed, pending, or review, never inferred from the
        // cancellation flag afterward.
        if cancelled() {
            return Ok(needs_review(
                VaultMoveReviewReason::CancelledBeforeSourceRemoval,
            ));
        }
        if !self
            .client
            .provider_generation_is_current(request.source_auth_generation)
            || !destination
                .client
                .provider_generation_is_current(request.destination_auth_generation)
        {
            return Ok(needs_review(
                VaultMoveReviewReason::AuthenticationGenerationChanged,
            ));
        }
        if !matches!(self.sessions.is_unlocked(&self.scope), Ok(true))
            || !matches!(
                destination.sessions.is_unlocked(&destination.scope),
                Ok(true)
            )
        {
            return Ok(needs_review(
                VaultMoveReviewReason::VaultLockedBeforeSourceRemoval,
            ));
        }

        match self.delete_file_for_move_with_queue(
            &source_path,
            &request.source_resource_id,
            &request.source_etag,
        ) {
            Ok(VaultDeleteOutcome::Committed) => Ok(VaultMoveOutcome::Moved { copy }),
            Ok(VaultDeleteOutcome::Queued {
                write_id,
                revision,
                uncertain: _,
            }) => Ok(VaultMoveOutcome::SourceRemovalNeedsReview {
                copy,
                write_id,
                revision,
            }),
            Err(_) => Ok(needs_review(
                VaultMoveReviewReason::SourceRemovalNotConfirmed,
            )),
        }
    }

    pub fn move_file_to_cancellable(
        &self,
        destination: &VaultBackend,
        request: &VaultCopyRequest,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<VaultMoveOutcome, CloudError> {
        self.move_file_to_cancellable_with_binding(destination, request, cancelled, |_, _| {})
    }

    pub fn move_file_to(
        &self,
        destination: &VaultBackend,
        request: &VaultCopyRequest,
    ) -> Result<VaultMoveOutcome, CloudError> {
        self.move_file_to_cancellable(destination, request, &|| false)
    }
}
