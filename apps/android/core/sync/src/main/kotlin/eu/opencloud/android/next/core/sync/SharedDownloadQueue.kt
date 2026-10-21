package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.SharedDownloadRecord
import eu.opencloud.android.next.core.database.SharedDownloadStore
import eu.opencloud.android.next.core.database.SharedFolderEntry
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

/** Resolves and persists shared download intent; WorkManager scheduling is handled by TransferManager. */
class SharedDownloadQueue(
    private val store: SharedDownloadStore,
    private val resolver: SharedDownloadResolver,
) {
    suspend fun enqueue(
        request: SharedDownloadRequest,
        transferId: String,
        offlinePin: Boolean,
        now: Long,
    ): TransferEntity = enqueue(resolver.prepare(request), transferId, offlinePin, now)

    suspend fun enqueue(
        source: PreparedSharedDownload,
        transferId: String,
        offlinePin: Boolean,
        now: Long,
    ): TransferEntity {
        require(transferId.isNotBlank())
        currentCoroutineContext().ensureActive()
        val location = source.location
        val item = source.item
        val entry =
            SharedFolderEntry(
                location.accountId,
                location.scopeId,
                item.id,
                source.page.path,
                item.path,
                item.name,
                item.folder,
                item.mimeType,
                item.size,
                item.eTag,
                item.modifiedAtEpochMillis,
                item.createdAtEpochMillis,
            )
        val transfer =
            TransferEntity(
                id = transferId,
                accountId = location.accountId,
                spaceId = location.scopeId,
                resourceId = item.id,
                direction = "DOWNLOAD",
                sourceUri = null,
                destinationPath = item.path,
                displayName = item.name,
                mimeType = item.mimeType,
                bytesTotal = item.size,
                offlinePin = offlinePin,
                createdAtEpochMillis = now,
                updatedAtEpochMillis = now,
                expectedETag = item.eTag,
                locationKind = "SHARED_FOLDER",
            )
        return store.enqueue(source.page.checked.lease, location.binding(), entry, transfer) ?: staleQueue()
    }

    suspend fun restore(transferId: String): PreparedSharedDownload? {
        val record =
            store.read(transferId)?.takeIf {
                it.transfer.state in setOf("QUEUED", "RUNNING", "RETRY")
            } ?: return null
        val source = resolver.prepare(request(record))
        currentCoroutineContext().ensureActive()
        if (store.read(transferId) != record) staleQueue()
        return source
    }

    suspend fun retry(
        expected: TransferEntity,
        workerId: String,
        now: Long,
    ): TransferEntity? {
        val record = store.read(expected.id)?.takeIf { it.transfer == expected } ?: return null
        val source = resolver.prepare(request(record))
        currentCoroutineContext().ensureActive()
        if (source.location.binding() != record.scope) staleQueue()
        return store.retry(source.page.checked.lease, record, workerId, now)
    }

    private fun request(record: SharedDownloadRecord): SharedDownloadRequest {
        val intent = record.intent
        return SharedDownloadRequest(
            intent.accountId,
            record.scope.shareId,
            intent.scopeId,
            SharedDownloadFile(intent.remoteId, intent.path, intent.sizeBytes, intent.eTag),
        )
    }

    companion object {
        fun create(context: Context): SharedDownloadQueue =
            SharedDownloadQueue(
                SharedDownloadStore(FileBrowserDatabase.create(context)),
                SharedDownloadResolver.create(context),
            )
    }
}

private fun staleQueue(): Nothing = throw OpenCloudException(OpenCloudError.PreconditionFailed)
