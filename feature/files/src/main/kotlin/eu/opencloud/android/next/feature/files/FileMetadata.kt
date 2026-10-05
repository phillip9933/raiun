package eu.opencloud.android.next.feature.files

import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.OfflinePin
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.designsystem.localizedString
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.ui.BrowserItemMetadataText

internal fun isKeptOffline(
    resource: ResourceEntity,
    offlinePins: List<ResourceEntity>,
): Boolean =
    resource.offlinePinned ||
        offlinePins.any {
            it.accountId == resource.accountId &&
                it.spaceId == resource.spaceId &&
                (
                    it.remoteId == resource.remoteId ||
                        it.kind == ResourceKind.FOLDER &&
                        resource.path.startsWith(it.path.trimEnd('/') + "/")
                )
        }

@Composable
internal fun LocalAvailabilityIcon(
    resource: ResourceEntity,
    pinned: Boolean,
) {
    val icon =
        when {
            pinned -> Icons.Default.OfflinePin
            resource.hasLocalCopy -> Icons.Default.History
            else -> Icons.Default.Cloud
        }
    val label =
        when {
            pinned && resource.hasLocalCopy -> stringResource(R.string.file_details_kept_offline)
            pinned -> stringResource(R.string.file_details_selected_offline)
            resource.hasLocalCopy -> stringResource(R.string.file_details_temporary_copy)
            else -> stringResource(R.string.file_details_cloud_only)
        }
    Icon(
        icon,
        label,
        Modifier.size(OpenCloudDimensions.SpacingMd),
        tint = if (pinned) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
internal fun FileMetadataText(
    resource: ResourceEntity,
    modifier: Modifier = Modifier,
    display: eu.opencloud.android.next.core.datastore.FileDisplayOptions =
        eu.opencloud.android.next.core.datastore
            .FileDisplayOptions(),
) {
    val context = LocalContext.current
    val size =
        if (resource.kind ==
            ResourceKind.FOLDER
        ) {
            context.localizedString(R.string.file_details_folder)
        } else {
            android.text.format.Formatter
                .formatShortFileSize(context, resource.sizeBytes)
        }
    val modified = if (display.showModified) formattedModified(resource.modifiedAtEpochMillis) else null
    BrowserItemMetadataText(
        listOfNotNull(size.takeIf { display.showSize }, modified).joinToString(" \u00b7 "),
        modifier,
    )
}

@Composable
internal fun OfflineLegend() {
    androidx.compose.foundation.layout.Row(
        Modifier.padding(horizontal = OpenCloudDimensions.SpacingMd, vertical = OpenCloudDimensions.SpacingXs),
        horizontalArrangement =
            androidx.compose.foundation.layout.Arrangement
                .spacedBy(OpenCloudDimensions.SpacingXs),
        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
    ) {
        Icon(
            Icons.Default.OfflinePin,
            null,
            Modifier.size(OpenCloudDimensions.SpacingMd),
            tint = MaterialTheme.colorScheme.primary,
        )
        Text(stringResource(R.string.file_details_kept_offline), style = MaterialTheme.typography.labelSmall)
        Icon(Icons.Default.History, null, Modifier.size(OpenCloudDimensions.SpacingMd))
        Text(stringResource(R.string.file_details_temporary_copy_short), style = MaterialTheme.typography.labelSmall)
    }
}
