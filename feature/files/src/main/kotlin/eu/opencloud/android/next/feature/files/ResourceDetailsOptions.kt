package eu.opencloud.android.next.feature.files

import eu.opencloud.android.next.core.datastore.FileDisplayOptions

internal data class ResourceDetailsOptions(
    val keptOffline: Boolean,
    val retentionHours: Int,
    val display: FileDisplayOptions,
)
