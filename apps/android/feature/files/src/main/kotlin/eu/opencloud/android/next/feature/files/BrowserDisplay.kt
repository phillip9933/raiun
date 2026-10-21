package eu.opencloud.android.next.feature.files

import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.datastore.FileDisplayOptions
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.ui.browserDisplayName
import java.text.DateFormat
import java.util.Date

internal enum class ExternalAction { OPEN, OPEN_WITH, SEND }

internal enum class OfflineFilter(
    @androidx.annotation.StringRes val labelResource: Int,
) {
    ALL(R.string.offline_filter_all),
    TEMPORARY(R.string.offline_filter_temporary),
    PINNED(R.string.offline_filter_pinned),
    ;

    fun matches(
        resource: ResourceEntity,
        pins: List<ResourceEntity>,
    ): Boolean =
        when (this) {
            ALL -> true
            TEMPORARY -> !isKeptOffline(resource, pins)
            PINNED -> isKeptOffline(resource, pins)
        }
}

internal fun displayFileName(
    resource: ResourceEntity,
    options: FileDisplayOptions,
): String = browserDisplayName(resource.name, resource.kind == ResourceKind.FOLDER, options)

internal fun formattedModified(
    timestamp: Long,
    now: Long = System.currentTimeMillis(),
): String? {
    if (timestamp <= 0) return null
    val format =
        if (timestamp <= now && now - timestamp < 86_400_000L) {
            DateFormat.getTimeInstance(DateFormat.SHORT)
        } else {
            DateFormat.getDateInstance(DateFormat.SHORT)
        }
    return format.format(Date(timestamp))
}
