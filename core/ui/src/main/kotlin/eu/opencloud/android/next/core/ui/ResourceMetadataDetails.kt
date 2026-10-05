package eu.opencloud.android.next.core.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions

/** Shared metadata rows for ordinary and encrypted resource details. Null fields stay absent. */
@Composable
fun ResourceMetadataDetails(
    location: String,
    type: String,
    size: String?,
    modified: String?,
    modifier: Modifier = Modifier,
) {
    Column(modifier, verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm)) {
        Text(location)
        Text(type)
        size?.let { Text(it) }
        modified?.let { Text(it) }
    }
}
