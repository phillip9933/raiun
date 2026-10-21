package eu.opencloud.android.next.core.database

import androidx.room.withTransaction

internal suspend fun invalidateFileContent(
    database: FileBrowserDatabase,
    resource: ResourceEntity,
) = database.withTransaction {
    database.snapshotVersions.begin(resource.accountId)
    database.resourceDao().invalidatePathCache(resource.accountId, resource.spaceId, resource.path)
    FileBrowserStore(database).queueFolderRefresh(resource.accountId, resource.spaceId, resource.parentId)
}
