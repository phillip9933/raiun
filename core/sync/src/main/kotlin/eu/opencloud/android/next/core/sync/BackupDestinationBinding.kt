package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.FolderBackupEntity

internal fun FolderBackupEntity.sharedRequest(): SharedFolderRequest {
    require(destinationKind == "SHARED_FOLDER")
    require(spaceId.startsWith("shared-folder:"))
    requireSharedPath(destinationPath)
    return SharedFolderRequest(
        accountId,
        requireNotNull(sharedShareId),
        spaceId,
        requireNotNull(sharedFolderId),
        destinationPath,
    )
}
