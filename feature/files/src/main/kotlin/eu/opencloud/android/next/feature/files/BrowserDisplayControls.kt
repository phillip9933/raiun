package eu.opencloud.android.next.feature.files

import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.model.ResourceKind

@Composable
internal fun OfflineHeader(
    bytes: Long,
    filter: OfflineFilter,
    onFilter: (OfflineFilter) -> Unit,
) {
    Column(Modifier.padding(horizontal = OpenCloudDimensions.SpacingMd)) {
        Text(
            stringResource(
                R.string.offline_local_space_used,
                android.text.format.Formatter
                    .formatShortFileSize(LocalContext.current, bytes),
            ),
            style = MaterialTheme.typography.titleSmall,
        )
        Row(
            Modifier.horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
        ) {
            OfflineFilter.entries.forEach { option ->
                FilterChip(selected = filter == option, onClick = {
                    onFilter(option)
                }, label = { Text(stringResource(option.labelResource)) })
            }
        }
    }
}

@Composable
internal fun SelectionAction(
    label: String,
    icon: ImageVector,
    description: String,
    onClick: () -> Unit,
) {
    Column(
        Modifier
            .clickable(
                role = Role.Button,
                onClickLabel = description,
                onClick = onClick,
            ).heightIn(min = OpenCloudDimensions.TouchTarget)
            .padding(OpenCloudDimensions.SpacingXs),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(icon, description)
        Text(label, style = MaterialTheme.typography.labelSmall)
    }
}

@Composable
internal fun ActionGroupDivider() {
    HorizontalDivider(Modifier.padding(vertical = OpenCloudDimensions.SpacingXxs))
}

@Composable
internal fun FolderSummary(
    resources: List<ResourceEntity>,
    encryptedFolderCount: Int = 0,
) {
    val ordinaryFolders = resources.count { it.kind == ResourceKind.FOLDER }
    val folders = ordinaryFolders + encryptedFolderCount
    val files = resources.size - ordinaryFolders
    Text(
        stringResource(
            R.string.browser_folder_summary,
            pluralStringResource(R.plurals.browser_folder_count, folders, folders),
            pluralStringResource(R.plurals.browser_file_count, files, files),
        ),
        Modifier.padding(OpenCloudDimensions.SpacingMd),
        style = MaterialTheme.typography.bodySmall,
    )
}
