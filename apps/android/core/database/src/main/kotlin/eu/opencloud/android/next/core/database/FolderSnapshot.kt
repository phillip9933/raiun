package eu.opencloud.android.next.core.database

data class FolderSnapshot(
    val resources: List<ResourceEntity>,
    val excludedVaultPaths: Set<String> = emptySet(),
)

/** A validated, replayable listing whose backing store can page without retaining all children. */
interface FolderSnapshotReader {
    fun page(afterSequence: Long): List<FolderSnapshotRow>

    fun containsRemoteId(remoteId: String): Boolean
}

data class FolderSnapshotRow(
    val sequence: Long,
    val resource: ResourceEntity? = null,
    val excludedVaultPath: String? = null,
)

internal suspend fun FileBrowserDatabase.reconcileVaultFolders(
    accountId: String,
    spaceId: String,
    parentId: String?,
    discovered: FolderSnapshot,
) {
    val excluded = discovered.excludedVaultPaths
    val snapshot = discovered.resources
    val resources = resourceDao()
    if (excluded.isEmpty()) return
    val parentPath =
        if (parentId ==
            null
        ) {
            ""
        } else {
            requireNotNull(resources.findById(accountId, spaceId, parentId)).path.trimEnd('/')
        }
    require(
        excluded.all { path ->
            val name = path.substringAfterLast('/')
            name.isNotBlank() &&
                name != "." &&
                name != ".." &&
                !name.contains('\\') &&
                name.none { it.isISOControl() } &&
                path.substringBeforeLast('/') == parentPath
        },
    )
    require(snapshot.none { it.path in excluded })
    snapshotVersions.begin(accountId)
    excluded.forEach { path -> revokeVaultFolder(accountId, spaceId, path) }
}

internal suspend fun FileBrowserDatabase.revokeVaultFolder(
    accountId: String,
    spaceId: String,
    path: String,
) {
    val resources = resourceDao()
    vaultExclusionDao().record(VaultExclusion(accountId, spaceId, path))
    folderBackupDao().disableVault(accountId, spaceId, path)
    excludedCacheDao().capture(accountId, spaceId, path)
    fileOperationDao().blockVault(accountId, spaceId, path)
    pendingPinDao().clearBlockedOperations(accountId)
    transferDao().cancelTree(accountId, spaceId, path)
    offlineTraversalDao().cancelTree(accountId, spaceId, path)
    pendingPinDao().deleteTree(accountId, spaceId, path)
    resources.deleteDescendants(accountId, spaceId, "$path/")
    resources.findByPath(accountId, spaceId, path)?.let { resources.delete(it) }
}
