package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.resourceCacheDirectory
import eu.opencloud.android.next.core.model.validatedCachedFile
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout

suspend fun prepareLocalResource(
    context: Context,
    resource: ResourceEntity,
): ResourceEntity =
    withContext(Dispatchers.IO) {
        val store = FileBrowserStore(FileBrowserDatabase.create(context))

        fun cached(value: ResourceEntity) =
            validatedCachedFile(
                resourceCacheDirectory(context.filesDir, value.accountId, value.spaceId),
                value.localPath?.takeIf { value.hasLocalCopy },
                value.sizeBytes,
            )?.also { it.setLastModified(System.currentTimeMillis()) } != null
        val permit =
            eu.opencloud.android.next.core.security
                .AppLock(context)
                .beginAppAction()
        val current = ExternalFileFreshness(context, store).current(resource, permit)
        if (cached(current)) return@withContext current
        if (!AndroidNetworkStatus(context).isConnected()) throw OpenCloudException(OpenCloudError.Connectivity)
        val id = TransferManager(context, store).enqueueDownload(current, offlinePin = false)
        withTimeout(30 * 60 * 1000L) {
            store.observeTransfers(current.accountId).first { values ->
                val transfer = values.find { it.id == id }
                transfer == null || transfer.state !in setOf("QUEUED", "RUNNING", "RETRY")
            }
        }
        val downloaded = requireNotNull(store.resource(resource.accountId, resource.spaceId, resource.remoteId))
        check(cached(downloaded)) { "The file could not be downloaded." }
        downloaded
    }
