package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.SharedFolderCacheStore
import eu.opencloud.android.next.core.database.SharedFolderEntry
import eu.opencloud.android.next.core.database.SharedFolderListing
import eu.opencloud.android.next.core.database.SharedFolderScopeEntity
import eu.opencloud.android.next.core.database.SnapshotToken

/** Saves metadata into isolated tables, never into a whole-drive space or an automatically writable destination. */
class SharedFolderPageCache(
    private val store: SharedFolderCacheStore,
    private val afterCleanupNeeded: (() -> Unit)? = null,
) {
    suspend fun begin(
        checked: CheckedShareAccess,
        location: SharedFolderLocation,
        path: String,
    ): SnapshotToken? = store.begin(checked.lease, location.binding(), path)

    suspend fun save(
        page: SharedFolderPage,
        token: SnapshotToken,
    ): Boolean {
        val location = page.location
        val entries =
            page.items.map { item ->
                SharedFolderEntry(
                    location.accountId,
                    location.scopeId,
                    item.id,
                    page.path,
                    item.path,
                    item.name,
                    item.folder,
                    item.mimeType,
                    item.size,
                    item.eTag,
                    item.modifiedAtEpochMillis,
                    item.createdAtEpochMillis,
                )
            }
        val result =
            store.saveAndReport(
                page.checked.lease,
                token,
                location.binding(),
                page.path,
                SharedFolderListing(entries, page.excludedVaultPaths, page.plainCollectionConfirmed),
            )
        if (result.cleanupNeeded) afterCleanupNeeded?.invoke()
        return result.accepted
    }
}

internal fun SharedFolderLocation.binding() =
    SharedFolderScopeEntity(
        accountId,
        scopeId,
        shareId,
        serverDriveId,
        rootItemId,
        rootWebDavUrl,
    )
