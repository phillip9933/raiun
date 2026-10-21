package eu.opencloud.android.next.feature.files

import eu.opencloud.android.next.core.database.ResourceEntity

data class ScannerDestinationActions(
    val dismiss: () -> Unit,
    val choose: () -> Unit,
    val spaces: () -> Unit,
    val space: (String) -> Unit,
    val breadcrumb: (Int) -> Unit,
    val folder: (ResourceEntity) -> Unit,
    val up: () -> Unit,
    val retry: () -> Unit,
)
