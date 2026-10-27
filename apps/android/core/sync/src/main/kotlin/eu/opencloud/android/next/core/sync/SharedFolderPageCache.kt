package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.SharedFolderCacheStore
import eu.opencloud.android.next.core.database.SharedFolderDisplaySnapshot
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

    internal suspend fun find(
        checked: CheckedShareAccess,
        location: SharedFolderLocation,
        id: String,
    ) = store.readEntry(checked.lease, location.binding(), id)

    internal suspend fun findPath(
        checked: CheckedShareAccess,
        location: SharedFolderLocation,
        parent: String,
        path: String,
    ) = store.readEntryAtPath(checked.lease, location.binding(), parent, path)

    internal suspend fun displayPage(
        checked: CheckedShareAccess,
        location: SharedFolderLocation,
        path: String,
        offset: Int,
    ) = store.readDisplayPage(checked.lease, location.binding(), path, offset)

    internal suspend fun captureDisplaySnapshot(
        checked: CheckedShareAccess,
        location: SharedFolderLocation,
        path: String,
    ): SharedFolderDisplaySnapshot? = store.captureDisplaySnapshot(checked.lease, location.binding(), path)

    internal suspend fun displayPageAtRevision(
        checked: CheckedShareAccess,
        location: SharedFolderLocation,
        path: String,
        offset: Int,
        revision: Long,
    ) = store.readDisplayPageAtRevision(checked.lease, location.binding(), path, offset, revision)

    internal suspend fun isDisplayRevisionCurrent(
        checked: CheckedShareAccess,
        location: SharedFolderLocation,
        path: String,
        revision: Long,
    ) = store.isDisplayRevisionCurrent(checked.lease, location.binding(), path, revision)

    @Suppress("LongParameterList") // Staged payload and validated root metadata have the same snapshot identity.
    internal suspend fun saveStaged(
        checked: CheckedShareAccess,
        location: SharedFolderLocation,
        path: String,
        token: SnapshotToken,
        staged: StagedRemoteFolder,
        metadata: eu.opencloud.android.next.core.network.RemoteFolderSnapshot,
    ): Boolean {
        val requestedExcluded = path in metadata.excludedVaultPaths

        fun convert(item: eu.opencloud.android.next.core.network.RemoteResource) =
            SharedFolderEntry(
                location.accountId,
                location.scopeId,
                item.id,
                path,
                item.path,
                item.name,
                item.folder,
                item.mimeType,
                item.size,
                item.eTag,
                item.modifiedAtEpochMillis,
                item.createdAtEpochMillis,
            )
        val reader =
            object : eu.opencloud.android.next.core.database.SharedFolderSnapshotReader {
                override fun page(afterSequence: Long) =
                    if (requestedExcluded) {
                        emptyList()
                    } else {
                        staged.page(afterSequence).map { row ->
                            eu.opencloud.android.next.core.database.SharedFolderSnapshotRow(
                                row.sequence,
                                row.entry.resource?.let(::convert),
                                row.entry.path.takeIf { row.entry.resource == null },
                            )
                        }
                    }

                override fun find(remoteId: String) = staged.findEntry(remoteId)?.resource?.let(::convert)
            }
        val result =
            store.saveStaged(
                checked.lease,
                token,
                location.binding(),
                path,
                reader,
                requestedExcluded,
                metadata.plainCollectionConfirmed,
            )
        if (result.cleanupNeeded) afterCleanupNeeded?.invoke()
        return result.accepted
    }

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
