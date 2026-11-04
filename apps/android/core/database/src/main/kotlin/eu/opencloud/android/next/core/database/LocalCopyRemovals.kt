package eu.opencloud.android.next.core.database

import androidx.room.withTransaction
import androidx.sqlite.db.SimpleSQLiteQuery
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.Closeable
import java.io.File
import java.io.IOException
import java.security.MessageDigest

fun FileBrowserStore.localCopyRemovals(): LocalCopyRemovals = LocalCopyRemovals(database)

internal suspend fun FileBrowserDatabase.clearRemovalAwareTransferHistory(accountId: String): Unit =
    withTransaction {
        temporaryCopyVersions.begin(accountId)
        transferDao().deleteHistory(accountId)
        compactTerminalOfflineGroupHistory(accountId)
        Unit
    }

data class LocalCopyRemovalRow(
    val resource: ResourceEntity,
    val removeCopy: Boolean,
)

enum class LocalCopyRemovalDecision { Applied, Changed, ActiveDownload }

class LocalCopyRemovalChangedException : IllegalStateException("The local-copy selection changed.")

/** One owned disk snapshot; account removal/replacement cannot transfer this authority to another incarnation. */
@Suppress("LongParameterList") // Independent account, admission, selection and owned-stage proofs form one scope.
class LocalCopyRemovalScope internal constructor(
    val account: AccountEntity,
    internal val owner: FileBrowserDatabase,
    internal val token: SnapshotToken,
    internal val incarnation: String,
    internal val snapshot: TemporaryCopySnapshot,
    internal val transfers: TransferBulkScope,
    internal val single: ResourceEntity?,
    internal val selectionDigest: ByteArray,
) : Closeable {
    internal val gate = Mutex()
    internal var closed = false

    override fun close() =
        runBlocking(Dispatchers.IO) {
            gate.withLock {
                if (!closed) {
                    closed = true
                    try {
                        snapshot.close()
                    } finally {
                        selectionDigest.fill(0)
                    }
                }
            }
        }
}

/** Explicit user removal. Temporary-copy expiration keeps its separate pin/ancestor protections. */
class LocalCopyRemovals(
    private val database: FileBrowserDatabase,
) {
    private val inventory = TransferInventory(database)
    private val pins = LocalCopyPinGuard(database)

    suspend fun captureOne(
        requested: ResourceEntity,
        requireSameCopy: Boolean,
        directory: File,
    ): LocalCopyRemovalScope? = capture(requested.accountId, directory, requested, requireSameCopy)

    suspend fun captureAll(
        accountId: String,
        directory: File,
    ): LocalCopyRemovalScope? = capture(accountId, directory, null, false)

    @Suppress("TooGenericExceptionCaught") // Failed capture and interrupted delivery close only the owned stage.
    private suspend fun capture(
        accountId: String,
        directory: File,
        requested: ResourceEntity?,
        sameCopy: Boolean,
    ): LocalCopyRemovalScope? {
        var staged: TemporaryCopySnapshot? = null
        try {
            val result =
                withContext(Dispatchers.IO) {
                    if (database.accountDao().findById(accountId) == null) return@withContext null
                    val snapshot = TemporaryCopySnapshot.create(directory)
                    staged = snapshot
                    database.withTransaction {
                        val account = database.accountDao().findById(accountId) ?: return@withTransaction null
                        val incarnation = database.ensureAccountIncarnation(accountId).incarnation
                        val transfers = inventory.captureScope(accountId) ?: return@withTransaction null
                        val checkActive = currentCoroutineContext().let { coroutine -> { coroutine.ensureActive() } }
                        val current = requested?.let { requireSingle(it, sameCopy) }
                        if (requested != null && current == null) return@withTransaction null
                        val selection =
                            if (current == null) {
                                captureBulk(accountId, snapshot, checkActive)
                                LocalCopyPinGuard.emptyDigest()
                            } else {
                                snapshot.insertRemovalBatch(listOf(current to hasCopy(current)))
                                pins.digest(current, checkActive)
                            }
                        LocalCopyRemovalScope(
                            account,
                            database,
                            database.temporaryCopyVersions.capture(accountId),
                            incarnation,
                            snapshot,
                            transfers,
                            current,
                            selection,
                        )
                    }
                }
            if (result == null) staged?.close()
            return result
        } catch (failure: Throwable) {
            withContext(NonCancellable + Dispatchers.IO) { staged?.close() }
            throw failure
        }
    }

    private suspend fun requireSingle(
        requested: ResourceEntity,
        requireSameCopy: Boolean,
    ): ResourceEntity? {
        val current = database.resourceDao().findById(requested.accountId, requested.spaceId, requested.remoteId)
        if (requireSameCopy && !sameCopy(current, requested)) throw LocalCopyRemovalChangedException()
        return current
    }

    private suspend fun captureBulk(
        accountId: String,
        snapshot: TemporaryCopySnapshot,
        checkActive: () -> Unit,
    ) {
        var after: TemporaryCopyKey? = null
        val store = FileBrowserStore(database)
        while (true) {
            checkActive()
            val rows =
                database.resourceDao().collectionRows(
                    SimpleSQLiteQuery(
                        "SELECT r.*, CASE WHEN r.hasLocalCopy=1 AND r.localPath IS NOT NULL AND " +
                            "s.isDisabled=0 AND s.isDeleted=0 THEN 1 ELSE 0 END AS keptOffline FROM resources r " +
                            "LEFT JOIN spaces s ON s.accountId=r.accountId AND s.driveId=r.spaceId " +
                            "WHERE r.accountId=? AND (r.offlinePinned=1 OR " +
                            "(r.hasLocalCopy=1 AND r.localPath IS NOT NULL AND s.isDisabled=0 AND s.isDeleted=0)) " +
                            "AND (? IS NULL OR r.spaceId COLLATE BINARY > ? OR " +
                            "(r.spaceId=? AND r.remoteId COLLATE BINARY > ?)) " +
                            "ORDER BY r.spaceId COLLATE BINARY,r.remoteId COLLATE BINARY LIMIT 128",
                        arrayOf(accountId, after?.spaceId, after?.spaceId, after?.spaceId, after?.remoteId),
                    ),
                )
            if (rows.isEmpty()) break
            val frozen =
                rows.map { row ->
                    checkActive()
                    if (row.resource.offlinePinned) store.setOfflinePinned(row.resource, false)
                    row.resource.copy(offlinePinned = false) to row.keptOffline
                }
            snapshot.insertRemovalBatch(frozen)
            after = rows.last().resource.key()
        }
        database.pendingPinDao().deleteAccount(accountId)
        database.pendingPinDao().deleteOperationPins(accountId)
    }

    suspend fun page(
        scope: LocalCopyRemovalScope,
        after: TemporaryCopyKey? = null,
    ): List<LocalCopyRemovalRow> =
        scope.gate.withLock {
            database.withTransaction {
                requireCurrent(scope)
                scope.snapshot.page(after).map { LocalCopyRemovalRow(it, scope.snapshot.removalEligible(it.key())) }
            }
        }

    suspend fun downloadPage(
        scope: LocalCopyRemovalScope,
        afterId: String? = null,
    ): List<TransferEntity> =
        scope.gate.withLock {
            database.withTransaction {
                requireCurrent(scope)
                val single = scope.single
                val states = if (single == null) REMOVABLE_DOWNLOAD_STATES else ACTIVE_DOWNLOAD_STATES
                val selection = if (single == null) "" else " AND t.spaceId=? AND t.resourceId=?"
                val args = mutableListOf<Any?>(scope.account.id, scope.transfers.watermark, afterId, afterId)
                if (single != null) {
                    args.add(single.spaceId)
                    args.add(single.remoteId)
                }
                database.transferInventoryDao().rows(
                    SimpleSQLiteQuery(
                        "SELECT t.* FROM transfers t JOIN transfer_queue q ON q.transferId=t.id " +
                            "WHERE t.accountId=? AND q.sequence<=? AND (? IS NULL OR t.id COLLATE BINARY > ?) " +
                            "AND t.direction='DOWNLOAD' AND t.state IN ($states)$selection " +
                            "ORDER BY t.id COLLATE BINARY LIMIT 128",
                        args.toTypedArray(),
                    ),
                )
            }
        }

    /** Returns only the admitted old worker; callers must cancel its UUID, never a reusable unique-work name. */
    suspend fun cancelDownload(
        scope: LocalCopyRemovalScope,
        id: String,
    ): TransferEntity? =
        scope.gate.withLock {
            database.withTransaction {
                if (!isCurrent(scope) || !singleUnchanged(scope)) return@withTransaction null
                val row = database.transferDao().findById(id) ?: return@withTransaction null
                if (!matchesDownload(scope, row)) return@withTransaction null
                inventory.cancelForClear(scope.transfers, id)
            }
        }

    /** Canonical cache-use exclusion is acquired by the caller BEFORE this Room transaction. */
    suspend fun remove(
        scope: LocalCopyRemovalScope,
        expected: LocalCopyRemovalRow,
        deleteValidatedCopy: () -> Boolean,
    ): LocalCopyRemovalDecision =
        scope.gate.withLock {
            database.withTransaction {
                val original = expected.resource
                if (!isCurrent(scope) ||
                    !matchesSnapshot(scope, expected)
                ) {
                    return@withTransaction LocalCopyRemovalDecision.Changed
                }
                val current = database.resourceDao().findById(original.accountId, original.spaceId, original.remoteId)
                if (current != original) return@withTransaction LocalCopyRemovalDecision.Changed
                val checkActive = currentCoroutineContext().let { coroutine -> { coroutine.ensureActive() } }
                if (!MessageDigest.isEqual(pins.digest(original, checkActive), scope.selectionDigest)) {
                    return@withTransaction LocalCopyRemovalDecision.Changed
                }
                if (database.transferDao().findActiveDownload(
                        original.accountId,
                        original.spaceId,
                        original.remoteId,
                    ) !=
                    null
                ) {
                    return@withTransaction LocalCopyRemovalDecision.ActiveDownload
                }
                if (hasLaterDownload(scope, original)) return@withTransaction LocalCopyRemovalDecision.Changed
                checkActive()
                if (expected.removeCopy &&
                    !deleteValidatedCopy()
                ) {
                    throw IOException("The local copy could not be removed.")
                }
                if (scope.single != null) revokeSingleSelection(original)
                if (expected.removeCopy) {
                    database.resourceDao().updateLocalCopy(
                        original.accountId,
                        original.spaceId,
                        original.remoteId,
                        false,
                        null,
                    )
                }
                LocalCopyRemovalDecision.Applied
            }
        }

    private suspend fun hasLaterDownload(
        scope: LocalCopyRemovalScope,
        resource: ResourceEntity,
    ): Boolean =
        database.transferInventoryDao().count(
            SimpleSQLiteQuery(
                "SELECT EXISTS(SELECT 1 FROM transfers t JOIN transfer_queue q ON q.transferId=t.id " +
                    "WHERE t.accountId=? AND t.spaceId=? AND t.resourceId=? AND t.direction='DOWNLOAD' " +
                    "AND q.sequence>?)",
                arrayOf(resource.accountId, resource.spaceId, resource.remoteId, scope.transfers.watermark),
            ),
        ) != 0

    private suspend fun revokeSingleSelection(resource: ResourceEntity) {
        FileBrowserStore(database).setOfflinePinned(resource, false)
        database.pendingPinDao().acknowledge(resource.accountId, resource.spaceId, resource.path)
        database.pendingPinDao().deleteSourceSelection(resource.accountId, resource.spaceId, resource.path)
    }

    private fun matchesSnapshot(
        scope: LocalCopyRemovalScope,
        row: LocalCopyRemovalRow,
    ): Boolean =
        row.resource.accountId == scope.account.id &&
            scope.snapshot.find(row.resource.key()) == row.resource &&
            scope.snapshot.removalEligible(row.resource.key()) == row.removeCopy

    private fun matchesDownload(
        scope: LocalCopyRemovalScope,
        row: TransferEntity,
    ): Boolean {
        val belongs = row.accountId == scope.account.id && row.direction == "DOWNLOAD" && row.state in DOWNLOAD_STATES
        val single = scope.single
        val selected = single == null || matchesSingleDownload(single, row)
        return belongs && selected
    }

    private fun matchesSingleDownload(
        single: ResourceEntity,
        row: TransferEntity,
    ): Boolean = row.spaceId == single.spaceId && row.resourceId == single.remoteId && row.state in ACTIVE_STATES

    private suspend fun singleUnchanged(scope: LocalCopyRemovalScope): Boolean {
        val single = scope.single
        return single == null || matchesSingleSelection(scope, single)
    }

    private suspend fun matchesSingleSelection(
        scope: LocalCopyRemovalScope,
        single: ResourceEntity,
    ): Boolean {
        val unchanged = database.resourceDao().findById(single.accountId, single.spaceId, single.remoteId) == single
        val coroutine = currentCoroutineContext()
        return unchanged &&
            MessageDigest.isEqual(pins.digest(single) { coroutine.ensureActive() }, scope.selectionDigest)
    }

    private suspend fun isCurrent(scope: LocalCopyRemovalScope): Boolean {
        val owned = scope.owner === database && !scope.closed && scope.account.isActive
        val current =
            database.temporaryCopyVersions.isCurrent(scope.token) &&
                database.transferInventoryVersions.isCurrent(scope.transfers.token)
        val account =
            database.accountDao().findById(scope.account.id) == scope.account &&
                database.vaultOfflineGroupDao().owner(scope.account.id)?.incarnation == scope.incarnation
        return owned && current && account
    }

    private suspend fun requireCurrent(scope: LocalCopyRemovalScope) {
        if (!isCurrent(scope)) throw LocalCopyRemovalChangedException()
        currentCoroutineContext().ensureActive()
    }

    private companion object {
        val DOWNLOAD_STATES = setOf("QUEUED", "RUNNING", "RETRY", "AWAITING_UNLOCK", "FAILED", "CONFLICT")
        val ACTIVE_STATES = setOf("QUEUED", "RUNNING", "RETRY")
        const val ACTIVE_DOWNLOAD_STATES = "'QUEUED','RUNNING','RETRY'"
        const val REMOVABLE_DOWNLOAD_STATES = "'QUEUED','RUNNING','RETRY','AWAITING_UNLOCK','FAILED','CONFLICT'"

        fun hasCopy(resource: ResourceEntity): Boolean = resource.hasLocalCopy && resource.localPath != null

        fun sameCopy(
            current: ResourceEntity?,
            requested: ResourceEntity,
        ): Boolean {
            if (current == null) return false
            return current.localPath == requested.localPath &&
                current.eTag == requested.eTag &&
                current.sizeBytes == requested.sizeBytes
        }
    }
}

private fun ResourceEntity.key() = TemporaryCopyKey(spaceId, remoteId)
