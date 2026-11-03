//! Shared operation labels for both desktop interfaces. No mutation authority.
use raiun_opencloud::vault_cache::VaultPendingOperationKind;

pub(crate) fn vault_pending_operation_name(operation: VaultPendingOperationKind) -> &'static str {
    match operation {
        VaultPendingOperationKind::Overwrite => "overwrite",
        VaultPendingOperationKind::CreateFile => "create_file",
        VaultPendingOperationKind::RenameFile => "rename_file",
        VaultPendingOperationKind::DeleteFile => "delete_file",
        VaultPendingOperationKind::CreateDirectory => "create_directory",
        VaultPendingOperationKind::CopyFile => "copy_file",
    }
}

pub(crate) fn vault_pending_operation_state_name(
    state: raiun_cache::CiphertextWriteState,
) -> &'static str {
    match state {
        raiun_cache::CiphertextWriteState::Building => "building",
        raiun_cache::CiphertextWriteState::Pending => "pending",
        raiun_cache::CiphertextWriteState::NeverAttempted => "queued",
        raiun_cache::CiphertextWriteState::Attempting => "uncertain",
        raiun_cache::CiphertextWriteState::RecoveryAttempting
        | raiun_cache::CiphertextWriteState::RecoveryRetrying => "uncertain",
        raiun_cache::CiphertextWriteState::Uncertain => "uncertain",
        raiun_cache::CiphertextWriteState::Conflict => "conflict",
        raiun_cache::CiphertextWriteState::CommittedReceipt
        | raiun_cache::CiphertextWriteState::CancelledReceipt
        | raiun_cache::CiphertextWriteState::AcknowledgedReceipt => "internal",
    }
}

pub(crate) fn vault_pending_operation_attention_reason(
    operation: VaultPendingOperationKind,
    state: raiun_cache::CiphertextWriteState,
) -> Option<&'static str> {
    match (operation, state) {
        (
            VaultPendingOperationKind::CopyFile,
            raiun_cache::CiphertextWriteState::Building
            | raiun_cache::CiphertextWriteState::Pending
            | raiun_cache::CiphertextWriteState::NeverAttempted
            | raiun_cache::CiphertextWriteState::Attempting
            | raiun_cache::CiphertextWriteState::RecoveryAttempting
            | raiun_cache::CiphertextWriteState::RecoveryRetrying
            | raiun_cache::CiphertextWriteState::Uncertain
            | raiun_cache::CiphertextWriteState::Conflict,
        ) => Some("copy_file_requires_review"),
        (
            VaultPendingOperationKind::CreateDirectory,
            raiun_cache::CiphertextWriteState::Attempting,
        ) => Some("directory_create_attempt_interrupted"),
        (VaultPendingOperationKind::CreateFile, raiun_cache::CiphertextWriteState::Attempting) => {
            Some("file_create_attempt_interrupted")
        }
        (
            VaultPendingOperationKind::CreateFile,
            raiun_cache::CiphertextWriteState::RecoveryAttempting
            | raiun_cache::CiphertextWriteState::RecoveryRetrying,
        ) => Some("file_create_recovery_interrupted"),
        _ => None,
    }
}
