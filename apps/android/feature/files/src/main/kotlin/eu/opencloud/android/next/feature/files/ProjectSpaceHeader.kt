package eu.opencloud.android.next.feature.files

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions

@Composable
internal fun ProjectSpaceHeader(
    name: String,
    trail: List<FolderCrumb>,
    onShowSpaces: () -> Unit,
) {
    Surface(color = MaterialTheme.colorScheme.secondaryContainer) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = OpenCloudDimensions.SpacingMd),
            horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(Icons.Default.Apps, contentDescription = null)
            Column(Modifier.weight(1f).padding(vertical = OpenCloudDimensions.SpacingSm)) {
                Text(stringResource(R.string.browser_project_space, name), style = MaterialTheme.typography.titleSmall)
                if (trail.isNotEmpty()) {
                    Text(trail.joinToString(" / ") { it.name }, style = MaterialTheme.typography.bodySmall)
                }
            }
            TextButton(onClick = onShowSpaces) { Text(stringResource(R.string.browser_all_spaces)) }
        }
    }
}
