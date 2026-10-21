package eu.opencloud.android.next.core.sync

import android.content.Context
import android.util.Log
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.TransferEntity
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking

/** Schedule durable intents in bounded pages before attempting optional orphan cleanup. */
@Suppress("TooGenericExceptionCaught")
internal suspend fun recoverPendingTransfers(
    context: Context,
    store: FileBrowserStore,
    enqueue: suspend (TransferEntity) -> Unit,
) {
    var afterId = ""
    while (true) {
        val page = store.pendingTransferPage(afterId)
        if (page.isEmpty()) break
        page.forEach { enqueue(it) }
        afterId = page.last().id
    }
    try {
        VaultOfflineStore(context).recoverPendingPublications()
        reconcileVaultPayloads(context, store)
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (_: Exception) {
        Log.e("OpenCloudSync", "VAULT_PAYLOAD_CLEANUP_FAILED")
    }
}

internal fun reconcileVaultPayloads(
    context: Context,
    store: FileBrowserStore,
) {
    fun retained(id: String): Boolean =
        runBlocking {
            store.transfer(id)?.state !in setOf(null, "SUCCEEDED")
        }
    VaultUploadStore(context).reconcile(::retained)
    VaultDownloadStore(context).reconcile(::retained)
}
