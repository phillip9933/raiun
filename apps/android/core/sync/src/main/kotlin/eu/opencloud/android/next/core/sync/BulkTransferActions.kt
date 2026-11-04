package eu.opencloud.android.next.core.sync

import android.content.Context
import androidx.work.WorkManager
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.TransferBulkKind
import eu.opencloud.android.next.core.database.TransferBulkScope
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.database.TransferState
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import java.util.UUID

/** Whole-account actions retain bounded windows and the queue admission watermark captured at invocation. */
internal class BulkTransferActions(
    private val context: Context,
    private val store: FileBrowserStore,
    private val workManager: WorkManager,
    private val retryTransfer: suspend (TransferBulkScope, TransferEntity) -> Boolean,
) {
    private val inventory = store.transferInventory()

    suspend fun retryUploads(accountId: String): BulkUploadRetryResult {
        val scope = captureScope(accountId)
        val attentionCount = inventory.countBulk(scope, TransferBulkKind.RetryUploads)
        var accepted = 0
        var after: String? = null
        while (true) {
            val page = inventory.bulkPage(scope, after, TransferBulkKind.RetryUploads)
            if (page.isEmpty()) break
            for (transfer in page) {
                currentCoroutineContext().ensureActive()
                if (retryCandidate(scope, transfer)) accepted++
            }
            after = page.last().id
        }
        return BulkUploadRetryResult(retried = accepted, needsAttention = (attentionCount - accepted).coerceAtLeast(0))
    }

    @Suppress("TooGenericExceptionCaught") // One failed candidate preserves its row and does not stop other uploads.
    private suspend fun retryCandidate(scope: TransferBulkScope, transfer: TransferEntity): Boolean {
        if (transfer.state == TransferState.CONFLICT.name || !transfer.errorCode.isSafeForBulkRetry()) return false
        return try {
            retryTransfer(scope, transfer)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            false
        }
    }

    suspend fun clearHistory(accountId: String) {
        val scope = captureScope(accountId)
        VaultOfflineStore(context).mutateTransferHistory(accountId) {
            inventory.deleteScopedHistory(scope)
            reconcileVaultPayloads(context, store)
        }
    }

    suspend fun clearAll(accountId: String) {
        val scope = captureScope(accountId)
        VaultOfflineStore(context).mutateTransferHistory(accountId) {
            cancelScope(scope)
            inventory.deleteScopedHistory(scope)
            reconcileVaultPayloads(context, store)
        }
    }

    private suspend fun cancelScope(scope: TransferBulkScope) {
        var after: String? = null
        while (true) {
            val page = inventory.bulkPage(scope, after)
            if (page.isEmpty()) break
            for (transfer in page) {
                currentCoroutineContext().ensureActive()
                val workId = inventory.cancelForClear(scope, transfer.id)?.workId
                val worker = workId?.let { runCatching { UUID.fromString(it) }.getOrNull() }
                worker?.let(workManager::cancelWorkById)
            }
            after = page.last().id
        }
    }

    private suspend fun captureScope(accountId: String): TransferBulkScope =
        requireNotNull(inventory.captureScope(accountId)) { "The transfer account is unavailable." }
}

private fun String?.isSafeForBulkRetry(): Boolean =
    this in setOf("CONNECTIVITY", "TIMEOUT", "RATE_LIMITED", "REMOTE_NOT_READY") ||
        this?.matches(Regex("SERVER_(500|502|503|504)")) == true
