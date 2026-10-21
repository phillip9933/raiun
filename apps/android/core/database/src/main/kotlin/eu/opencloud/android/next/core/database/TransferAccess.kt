package eu.opencloud.android.next.core.database

import androidx.room.withTransaction

internal suspend fun FileBrowserDatabase.retryAllowedTransfer(
    expected: TransferEntity,
    replacement: TransferEntity,
): TransferEntity? =
    withTransaction {
        require(
            replacement.accountId == expected.accountId &&
                replacement.spaceId == expected.spaceId &&
                replacement.direction == expected.direction &&
                replacement.locationKind == expected.locationKind,
        )
        if (expected.locationKind != "SPACE") return@withTransaction null
        val space = spaceDao().findById(expected.accountId, expected.spaceId)
        if (space == null || space.isDisabled || space.isDeleted) {
            return@withTransaction null
        }
        if (vaultExclusionDao().denies(expected.accountId, expected.spaceId, expected.destinationPath) ||
            vaultExclusionDao().denies(replacement.accountId, replacement.spaceId, replacement.destinationPath)
        ) {
            return@withTransaction null
        }
        if (accountDao().findById(expected.accountId) == null) return@withTransaction null
        transferDao().retry(expected, replacement)
    }

internal suspend fun FileBrowserDatabase.claimAllowedTransfer(
    id: String,
    workerId: String,
    now: Long,
): TransferEntity? =
    withTransaction {
        val current = transferDao().findById(id) ?: return@withTransaction null
        if (current.locationKind == "SPACE" &&
            vaultExclusionDao().denies(current.accountId, current.spaceId, current.destinationPath)
        ) {
            if (current.state in setOf("QUEUED", "RUNNING", "RETRY")) transferDao().cancel(id)
            return@withTransaction null
        }
        transferDao().claim(id, workerId, now)
    }
