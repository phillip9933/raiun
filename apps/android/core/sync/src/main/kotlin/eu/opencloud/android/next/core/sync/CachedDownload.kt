package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.resourceCacheDirectory
import eu.opencloud.android.next.core.model.validatedCachedFile

internal fun cachedDownload(
    context: Context,
    resource: ResourceEntity,
) = validatedCachedFile(
    resourceCacheDirectory(context.filesDir, resource.accountId, resource.spaceId),
    resource.localPath?.takeIf { resource.hasLocalCopy },
    resource.sizeBytes,
)
