package eu.opencloud.android.next.core.sync

import android.content.Context
import androidx.work.WorkManager
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.TransferDirection
import kotlinx.coroutines.flow.first

internal class LocalCopyOperations(
    private val context: Context,
    private val store: FileBrowserStore,
    private val workManager: WorkManager,
) {
    suspend fun removeAll(accountId: String) {
        store.offlinePinnedResources().filter { it.accountId == accountId }.forEach {
            store.setOfflinePinned(it, false)
            workManager.cancelUniqueWork("offline-${it.accountId}-${it.spaceId}-${it.remoteId}")
        }
        store
            .activeTransfers(accountId)
            .filter { it.direction == TransferDirection.DOWNLOAD.name }
            .forEach { cancel(it) }
        store.observeOffline(accountId).first().forEach { remove(it) }
    }

    suspend fun remove(
        resource: ResourceEntity,
        requireSameCopy: Boolean = false,
    ) {
        store
            .activeTransfers(resource.accountId)
            .filter {
                it.direction == TransferDirection.DOWNLOAD.name &&
                    it.spaceId == resource.spaceId &&
                    it.resourceId == resource.remoteId &&
                    it.state in setOf("QUEUED", "RUNNING", "RETRY")
            }.forEach { cancel(it) }
        val current = store.resource(resource.accountId, resource.spaceId, resource.remoteId) ?: return
        if (requireSameCopy) {
            require(
                current.localPath == resource.localPath &&
                    current.eTag == resource.eTag &&
                    current.sizeBytes == resource.sizeBytes,
            ) { "The local copy changed during export; it was kept." }
        }
        val directory =
            eu.opencloud.android.next.core.model.resourceCacheDirectory(
                context.filesDir,
                current.accountId,
                current.spaceId,
            )
        val cached =
            eu.opencloud.android.next.core.model.validatedCachedFile(
                directory,
                current.localPath,
                current.sizeBytes,
            )
        require(cached == null || !cached.exists() || cached.delete()) { "The local copy could not be removed." }
        check(store.clearMatchingLocalCopy(current)) {
            "The cached file changed while its local copy was being removed."
        }
    }

    private suspend fun cancel(transfer: eu.opencloud.android.next.core.database.TransferEntity) {
        store.cancelTransfer(transfer.id)
        workManager.cancelUniqueWork("transfer-${transfer.id}")
    }
}
