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
        publicationGuard: () -> Unit = {},
    ): Boolean =
        database.withTransaction {
            publicationGuard()
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
            publicationGuard()
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
            val rootId = if (parentId == null) spaces.findById(accountId, spaceId)?.rootId else null
            require(snapshot.none { it.remoteId == parentId || it.remoteId == rootId })
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
                upsertDiscovered(accountId, spaceId, remote)
            }
            true
        }

    /** Applies a complete staged listing with bounded heap while retaining the same transaction semantics. */
    suspend fun replaceStagedFolderSnapshot(
        accountId: String,
        scope: FolderSnapshotScope,
        source: FolderSnapshotReader,
        token: SnapshotToken? = null,
        publicationGuard: () -> Unit = {},
    ): Boolean =
        database.withTransaction {
            publicationGuard()
            if (!database.snapshotVersions.accept(accountId, token, scope)) {
                return@withTransaction false
            }
            validateStagedRows(accountId, scope, source)
            reconcileStagedVaultEvidence(accountId, scope, source)
            deleteMissingStagedChildren(accountId, scope, source)
            eachStagedRow(source) { row ->
                row.resource?.let { upsertDiscovered(accountId, scope.spaceId, it) }
            }
            publicationGuard()
            true
        }

    private suspend fun validateStagedRows(
        accountId: String,
        scope: FolderSnapshotScope,
        source: FolderSnapshotReader,
    ) {
        val parentPath =
            scope.parentId?.let { parentId ->
                requireNotNull(resources.findById(accountId, scope.spaceId, parentId)).path.trimEnd('/')
            } ?: ""
        val spaceRootId = spaces.findById(accountId, scope.spaceId)?.rootId
        eachStagedRow(source) { row ->
            val path = row.excludedVaultPath
            val resource = row.resource
            require((path == null) != (resource == null))
            if (path != null) {
                requireValidStagedExclusion(path, parentPath)
            } else {
                requireValidStagedResource(requireNotNull(resource), accountId, scope, spaceRootId)
            }
        }
    }

    private fun requireValidStagedExclusion(
        path: String,
        parentPath: String,
    ) {
        val name = path.substringAfterLast('/')
        require(name.isNotBlank() && name != "." && name != "..")
        require(!name.contains('\\') && name.none { it.isISOControl() })
        require(path.substringBeforeLast('/') == parentPath)
    }

    private fun requireValidStagedResource(
        resource: ResourceEntity,
        accountId: String,
        scope: FolderSnapshotScope,
        spaceRootId: String?,
    ) {
        require(resource.accountId == accountId && resource.spaceId == scope.spaceId)
        require(resource.parentId == scope.parentId)
        require(resource.remoteId != scope.parentId)
        require(scope.parentId != null || resource.remoteId != spaceRootId)
    }

    private suspend fun reconcileStagedVaultEvidence(
        accountId: String,
        scope: FolderSnapshotScope,
        source: FolderSnapshotReader,
    ) {
        var revokedVault = false
        eachStagedRow(source) { row ->
            row.excludedVaultPath?.let { path ->
                if (!revokedVault) {
                    database.snapshotVersions.begin(accountId)
                    revokedVault = true
                }
                database.revokeVaultFolder(accountId, scope.spaceId, path)
            }
            row.resource?.let {
                database.vaultExclusionDao().confirmPlain(accountId, scope.spaceId, it.path.trimEnd('/'))
            }
        }
    }

    private suspend fun deleteMissingStagedChildren(
        accountId: String,
        scope: FolderSnapshotScope,
        source: FolderSnapshotReader,
    ) {
        var lastId = ""
        while (true) {
            val page = resources.childrenAfterId(accountId, scope.spaceId, scope.parentId, lastId)
            if (page.isEmpty()) break
            page.forEach { stale ->
                deleteStagedChildIfMissing(accountId, scope.spaceId, stale, source)
            }
            lastId = page.last().remoteId
        }
    }

    private suspend fun deleteStagedChildIfMissing(
        accountId: String,
        spaceId: String,
        stale: ResourceEntity,
        source: FolderSnapshotReader,
    ) {
        if (source.containsRemoteId(stale.remoteId)) return
        if (stale.kind == ResourceKind.FOLDER) {
            database.snapshotVersions.begin(accountId)
            resources.deleteDescendants(accountId, spaceId, "${stale.path.trimEnd('/')}/")
        }
        resources.delete(stale)
    }

    private suspend fun eachStagedRow(
        source: FolderSnapshotReader,
        visit: suspend (FolderSnapshotRow) -> Unit,
    ) {
        var after = 0L
        while (true) {
            val page = source.page(after)
            if (page.isEmpty()) break
            page.forEach { row ->
                require(row.sequence > after)
                visit(row)
                after = row.sequence
            }
        }
    }

    private suspend fun upsertDiscovered(
        accountId: String,
        spaceId: String,
        remote: ResourceEntity,
    ) {
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
}
