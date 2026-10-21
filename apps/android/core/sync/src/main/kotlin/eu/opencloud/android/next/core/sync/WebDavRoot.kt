package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException

internal fun webDavRoot(space: SpaceEntity): String {
    if (space.isDisabled || space.isDeleted) throw OpenCloudException(OpenCloudError.AccessDenied)
    return space.rootWebDavUrl
        ?.takeIf(String::isNotBlank)
        ?.let {
            eu.opencloud.android.next.core.network
                .EndpointPolicy()
                .endpoint(it, allowQuery = false)
                .toString()
        }
        ?: throw OpenCloudException(OpenCloudError.PreconditionFailed)
}
