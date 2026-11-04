package eu.opencloud.android.next.core.database

import androidx.room.withTransaction
import androidx.sqlite.db.SimpleSQLiteQuery

internal suspend fun FileBrowserDatabase.retryOfflineGroup(
    expected: VaultGroupLease,
    workerId: String,
    now: Long,
    scope: TransferBulkScope?,
): VaultGroupLease? =
    withTransaction {
        requireUuid(workerId)
        val groups = VaultOfflineGroups(this@retryOfflineGroup)
        val parent = expected.parent ?: return@withTransaction null
        if (!retryableGroup(expected.group) || !groups.current(expected)) return@withTransaction null
        if (!bulkAdmitsGroup(scope, parent)) return@withTransaction null
        val active = vaultOfflineGroupDao().active(parent.accountId, parent.spaceId, expected.group.remoteVaultId)
        if (active != null && active.id != expected.group.id) return@withTransaction null
        val unresolved =
            vaultOfflineGroupDao().unresolved(
                parent.accountId,
                expected.group.accountIncarnation,
                expected.group.identityDigest,
            )
        if (unresolved) {
            return@withTransaction null
        }
        val replacement =
            parent.copy(
                state = "QUEUED",
                workId = workerId,
                error = null,
                errorCode = null,
                notBeforeEpochMillis = 0,
                verificationPending = false,
                attemptCount = 0,
                updatedAtEpochMillis = now,
            )
        if (transferDao().retry(parent, replacement) == null) return@withTransaction null
        val group =
            expected.group.copy(
                state = "QUEUED",
                attemptId = null,
                activeSlot = 1,
                errorCode = null,
                revision = Math.addExact(expected.group.revision, 1),
                updatedAtEpochMillis = now,
            )
        vaultOfflineGroupDao().updateGroup(group)
        VaultGroupLease(group, replacement)
    }

private fun retryableGroup(group: VaultOfflineGroupEntity): Boolean =
    group.state in setOf("FAILED", "CANCELLED", "RETRY") &&
        group.pendingPublicationId == null &&
        group.sealedPlanDigest != null &&
        group.errorCode !in setOf("BASE_OFFLINE_ROOT_CHANGED", "OFFLINE_SNAPSHOT_CHANGED")

private suspend fun FileBrowserDatabase.bulkAdmitsGroup(
    scope: TransferBulkScope?,
    parent: TransferEntity,
): Boolean {
    if (scope == null) return true
    val current =
        scope.account.id == parent.accountId &&
            transferInventoryVersions.isCurrent(scope.token) &&
            accountDao().findById(parent.accountId) == scope.account
    return current &&
        transferInventoryDao().count(
            SimpleSQLiteQuery(
                "SELECT COUNT(*) FROM transfer_queue WHERE transferId = ? AND sequence <= ?",
                arrayOf<Any?>(parent.id, scope.watermark),
            ),
        ) == 1
}

/** Scoped clear cancellation updates durable group ownership before any worker is cancelled externally. */
internal suspend fun FileBrowserDatabase.cancelOfflineGroupParent(parent: TransferEntity): Boolean {
    val groups = VaultOfflineGroups(this)
    val group = vaultOfflineGroupDao().group(parent.id) ?: return false
    return groups.cancel(VaultGroupLease(group, parent), System.currentTimeMillis()) != null
}

internal suspend fun FileBrowserDatabase.cancelOwnedTransfer(id: String) =
    withTransaction {
        val parent = transferDao().findById(id) ?: return@withTransaction
        if (parent.locationKind == VAULT_GROUP_LOCATION_KIND) {
            cancelOfflineGroupParent(parent)
        } else {
            transferDao().cancel(id)
        }
        Unit
    }
