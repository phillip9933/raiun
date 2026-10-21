package eu.opencloud.android.next.core.database

import androidx.room.withTransaction
import eu.opencloud.android.next.core.model.ResourceKind

/** Applies fully validated listings atomically while preserving local copies and snapshot leases. */
internal class RemoteSnapshotStore(
    private val database: FileBrowserDatabase,
) {
    private val spaces = database.spaceDao()
    private val resources = database.resourceDao()

    suspend fun replaceRemoteSpaces(
        accountId: String,
        snapshot: List<SpaceEntity>,
        token: SnapshotToken? = null,
        excludedVaultIds: Set<String> = emptySet(),
    ): Boolean =
        database.withTransaction {
            require(snapshot.all { it.accountId == accountId })
            require(snapshot.map { it.driveId }.distinct().size == snapshot.size)
            require(excludedVaultIds.none { it.isBlank() })
            require(snapshot.none { it.driveId in excludedVaultIds })
            if (!database.snapshotVersions.accept(accountId, token)) return@withTransaction false
            val incomingIds = snapshot.mapTo(mutableSetOf()) { it.driveId }
            spaces.findSpaces(accountId).filterNot { it.driveId in incomingIds }.forEach { stale ->
                // Absence can mean revoked access, not deletion. Retain pins, cache and durable intent.
                spaces.upsertAll(listOf(stale.copy(isDisabled = true)))
            }
            spaces.upsertAll(snapshot)
            snapshot.forEach { database.vaultExclusionDao().confirmPlain(accountId, it.driveId, "") }
            if (excludedVaultIds.isNotEmpty()) database.snapshotVersions.begin(accountId)
            excludedVaultIds.forEach { spaceId ->
                database.excludeVaultDrive(accountId, spaceId)
            }
            true
        }

    private suspend fun rebaseMovedFolder(
        local: ResourceEntity?,
        remote: ResourceEntity,
    ) {
        if (local?.kind == ResourceKind.FOLDER && remote.kind == ResourceKind.FOLDER && local.path != remote.path) {
            database.snapshotVersions.begin(remote.accountId)
            resources.rebaseDescendants(remote.accountId, remote.spaceId, local.path, remote.path)
        }
    }

    suspend fun replaceFolderSnapshot(
        accountId: String,
        spaceId: String,
        parentId: String?,
        snapshot: List<ResourceEntity>,
        token: SnapshotToken? = null,
    ): Boolean = replaceDiscoveredFolderSnapshot(accountId, spaceId, parentId, FolderSnapshot(snapshot), token)

    suspend fun replaceDiscoveredFolderSnapshot(
        accountId: String,
        spaceId: String,
        parentId: String?,
        discovered: FolderSnapshot,
        token: SnapshotToken? = null,
    ): Boolean =
        database.withTransaction {
            val snapshot = discovered.resources
            require(snapshot.all { it.accountId == accountId && it.spaceId == spaceId && it.parentId == parentId })
            require(snapshot.map { it.remoteId }.distinct().size == snapshot.size)
            require(snapshot.map { it.path }.distinct().size == snapshot.size)
            require(snapshot.map { it.name }.distinct().size == snapshot.size)
            if (!database.snapshotVersions.accept(accountId, token, FolderSnapshotScope(spaceId, parentId))) {
                return@withTransaction false
            }
            database.reconcileVaultFolders(accountId, spaceId, parentId, discovered)
            snapshot.forEach { database.vaultExclusionDao().confirmPlain(accountId, spaceId, it.path.trimEnd('/')) }
            val existing = resources.findChildren(accountId, spaceId, parentId)
            val incomingIds = snapshot.mapTo(mutableSetOf()) { it.remoteId }
            existing.filterNot { it.remoteId in incomingIds }.forEach { stale ->
                if (stale.kind ==
                    ResourceKind.FOLDER
                ) {
                    database.snapshotVersions.begin(accountId)
                    resources.deleteDescendants(accountId, spaceId, "${stale.path.trimEnd('/')}/")
                }
                resources.delete(stale)
            }
            snapshot.forEach { remote ->
                val local = resources.findById(accountId, spaceId, remote.remoteId)
                rebaseMovedFolder(local, remote)
                val pendingPin = database.pendingPinDao().selected(accountId, spaceId, remote.path)
                val sameContent =
                    local?.eTag == remote.eTag &&
                        local?.sizeBytes == remote.sizeBytes &&
                        local?.kind == remote.kind
                resources.upsert(
                    remote.copy(
                        hasLocalCopy = sameContent && local?.hasLocalCopy == true,
                        localPath = local?.localPath?.takeIf { sameContent },
                        offlinePinned = pendingPin || local?.offlinePinned == true,
                        isFavorite = remote.isFavorite,
                    ),
                )
                if (pendingPin) database.pendingPinDao().acknowledge(accountId, spaceId, remote.path)
            }
            true
        }
}
