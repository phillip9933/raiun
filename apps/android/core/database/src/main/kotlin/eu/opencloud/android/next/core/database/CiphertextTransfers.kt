package eu.opencloud.android.next.core.database

import androidx.room.withTransaction

internal suspend fun FileBrowserDatabase.enqueuePreparedCiphertextUpload(transfer: TransferEntity): TransferEntity =
    withTransaction {
        require(transfer.locationKind == "VAULT" && transfer.direction == "UPLOAD")
        require(transfer.sourceUri == null && !transfer.overwrite && !transfer.deleteSourceAfterSuccess)
        require(transfer.bytesTotal >= 32 && transfer.resourceId == null)
        requireNotNull(accountDao().findById(transfer.accountId))
        transferDao().insert(transfer)
        transfer
    }

internal suspend fun FileBrowserDatabase.retryPreparedCiphertextTransfer(
    expected: TransferEntity,
    replacement: TransferEntity,
    scope: TransferBulkScope? = null,
): TransferEntity? =
    withTransaction {
        require(expected.locationKind == "VAULT" && expected.direction in setOf("UPLOAD", "DOWNLOAD"))
        require(
            replacement.copy(
                state = expected.state,
                error = expected.error,
                errorCode = expected.errorCode,
                notBeforeEpochMillis = expected.notBeforeEpochMillis,
                attemptCount = expected.attemptCount,
                verificationPending = expected.verificationPending,
                workId = expected.workId,
                updatedAtEpochMillis = expected.updatedAtEpochMillis,
            ) == expected,
        )
        if (accountDao().findById(expected.accountId) == null) return@withTransaction null
        if (scope == null) {
            transferDao().retry(expected, replacement)
        } else {
            TransferInventory(this@retryPreparedCiphertextTransfer).retryScoped(scope, expected, replacement)
        }
    }

internal suspend fun FileBrowserDatabase.enqueuePreparedCiphertextDownload(transfer: TransferEntity): TransferEntity =
    withTransaction {
        require(transfer.locationKind == "VAULT" && transfer.direction == "DOWNLOAD" && transfer.offlinePin)
        require(
            transfer.sourceUri?.startsWith("vault-offline:") == true &&
                !transfer.overwrite &&
                !transfer.deleteSourceAfterSuccess,
        )
        require(transfer.bytesTotal >= 32 && transfer.resourceId != null)
        requireNotNull(accountDao().findById(transfer.accountId))
        transferDao().insert(transfer)
        transfer
    }

internal suspend fun FileBrowserDatabase.completePendingCiphertextDownload(
    expected: TransferEntity,
    replacement: TransferEntity,
): Boolean =
    withTransaction {
        require(
            expected.locationKind == "VAULT" &&
                expected.direction == "DOWNLOAD" &&
                expected.state == "AWAITING_UNLOCK",
        )
        require(replacement.state in setOf("SUCCEEDED", "FAILED"))
        require(
            replacement.copy(
                state = expected.state,
                error = expected.error,
                errorCode = expected.errorCode,
                verificationPending = expected.verificationPending,
                updatedAtEpochMillis = expected.updatedAtEpochMillis,
            ) ==
                expected,
        )
        if (transferDao().findById(expected.id) != expected ||
            accountDao().findById(expected.accountId) == null
        ) {
            return@withTransaction false
        }
        transferDao().update(replacement)
        true
    }
