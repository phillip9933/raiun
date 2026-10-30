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
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
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
        if (cached(current)) {
            check(permit()) { "File access is locked." }
            return@withContext current
        }
        if (!AndroidNetworkStatus(context).isConnected()) throw OpenCloudException(OpenCloudError.Connectivity)
        val id = TransferManager(context, store).enqueueDownload(current, offlinePin = false)
        awaitDownloadedResource(store, current, id, permit, ::cached)
    }

/** The download wait never admits bytes after the initiating app action or resource access was revoked. */
internal suspend fun awaitDownloadedResource(
    store: FileBrowserStore,
    resource: ResourceEntity,
    transferId: String,
    permit: () -> Boolean,
    cached: (ResourceEntity) -> Boolean,
): ResourceEntity {
    withTimeout(30 * 60 * 1000L) {
        store.observeTransfer(resource.accountId, transferId).first { transfer ->
            transfer == null || transfer.state !in setOf("QUEUED", "RUNNING", "RETRY")
        }
    }
    currentCoroutineContext().ensureActive()
    check(permit()) { "File access is locked." }
    val allowed = store.requireCurrentMutableResource(resource, false)
    check(cached(allowed)) { "The file could not be downloaded." }
    currentCoroutineContext().ensureActive()
    check(permit()) { "File access is locked." }
    return allowed
}
