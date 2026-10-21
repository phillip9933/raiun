package eu.opencloud.android.next.core.database

import androidx.room.withTransaction
import eu.opencloud.android.next.core.model.ResourceKind

class StaleResourceException : IllegalStateException("The resource changed. Refresh and try again.")

/** Transactional checks shared by destructive mutations and offline selection. */
internal class VaultMutationGuard(
    private val database: FileBrowserDatabase,
) {
    private val resources = database.resourceDao()
    private val spaces = database.spaceDao()

    suspend fun setOfflinePinned(
        resource: ResourceEntity,
        pinned: Boolean,
    ) = database.withTransaction {
        if (pinned) requireCurrentResourceInTransaction(resource)
        resources.setOfflinePinned(resource.accountId, resource.spaceId, resource.remoteId, pinned)
        if (!pinned) database.offlineTraversalDao().cancelRoot(resource.accountId, resource.spaceId, resource.remoteId)
    }

    suspend fun requireCurrentResource(
        resource: ResourceEntity,
        includeDescendants: Boolean,
    ): ResourceEntity = database.withTransaction { requireCurrentResourceInTransaction(resource, includeDescendants) }

    private suspend fun requireCurrentResourceInTransaction(
        resource: ResourceEntity,
        includeDescendants: Boolean = true,
    ): ResourceEntity {
        requireAvailable(resource.accountId, resource.spaceId, "The resource is unavailable.")
        val current = resources.findById(resource.accountId, resource.spaceId, resource.remoteId)
        val sameRemoteIdentity =
            current != null &&
                listOf(current.path, current.parentId, current.kind, current.eTag) ==
                listOf(resource.path, resource.parentId, resource.kind, resource.eTag)
        if (!sameRemoteIdentity) throw StaleResourceException()
        requireAllowed(
            resource.accountId,
            resource.spaceId,
            requireNotNull(current).path,
            includeDescendants && current.kind == ResourceKind.FOLDER,
        )
        return requireNotNull(current)
    }

    suspend fun requireFolderDestination(
        accountId: String,
        spaceId: String,
        parentId: String?,
        expectedParentPath: String?,
        destinationPath: String,
    ) = database.withTransaction {
        requireAvailable(accountId, spaceId, "The destination is unavailable.")
        if (parentId != null) {
            val parent = resources.findById(accountId, spaceId, parentId)
            if (parent == null || parent.kind != ResourceKind.FOLDER || parent.path != expectedParentPath) {
                throw StaleResourceException()
            }
        }
        requireAllowed(accountId, spaceId, destinationPath, includeChildren = true)
    }

    suspend fun requireAllowedPath(
        accountId: String,
        spaceId: String,
        path: String,
        includeChildren: Boolean,
    ) = database.withTransaction {
        requireAvailable(accountId, spaceId, "The destination is unavailable.")
        requireAllowed(accountId, spaceId, path, includeChildren)
    }

    private suspend fun requireAvailable(
        accountId: String,
        spaceId: String,
        message: String,
    ) {
        val account = database.accountDao().findById(accountId)
        val space = spaces.findById(accountId, spaceId)
        check(account?.isActive == true && space != null && !space.isDisabled && !space.isDeleted) { message }
    }

    private suspend fun requireAllowed(
        accountId: String,
        spaceId: String,
        path: String,
        includeChildren: Boolean = false,
    ) {
        check(!database.vaultExclusionDao().denies(accountId, spaceId, path, includeChildren)) {
            "Encrypted vault locations are unavailable."
        }
    }
}
