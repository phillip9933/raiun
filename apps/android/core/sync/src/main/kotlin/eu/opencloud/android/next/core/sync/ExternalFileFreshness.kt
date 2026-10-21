package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import java.io.FileNotFoundException

/** Check server metadata before handing cached bytes to another app. Offline copies remain readable offline. */
class ExternalFileFreshness(
    context: Context,
    private val store: FileBrowserStore,
    private val network: NetworkStatus = AndroidNetworkStatus(context),
    private val refresh: suspend (ResourceEntity, () -> Boolean) -> Unit = { resource, allowed ->
        ProviderFolderOperations(
            context,
            store,
        ).refresh(resource.accountId, resource.spaceId, resource.parentId, allowed)
    },
) {
    suspend fun current(
        resource: ResourceEntity,
        allowed: () -> Boolean,
    ): ResourceEntity {
        check(allowed()) { "File access is locked." }
        val before = requireNotNull(store.resource(resource.accountId, resource.spaceId, resource.remoteId))
        store.requireCurrentMutableResource(before, false)
        val online = network.isConnected()
        if (online) {
            // Do not silently fall back to old bytes when an online check fails or access was revoked.
            refresh(before, allowed)
        }
        check(allowed()) { "File access is locked." }
        var current =
            store.resource(resource.accountId, resource.spaceId, resource.remoteId)
                ?: throw FileNotFoundException("The file is no longer available.")
        if (online &&
            current.hasLocalCopy &&
            eu.opencloud.android.next.core.network
                .DownloadExpectation(current.sizeBytes, current.eTag)
                .strongETag ==
            null
        ) {
            store.invalidateFileContent(current)
            current = requireNotNull(store.resource(current.accountId, current.spaceId, current.remoteId))
        }
        require(current.kind == ResourceKind.FILE)
        return store.requireCurrentMutableResource(current, false)
    }
}
