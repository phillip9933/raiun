package eu.opencloud.android.next.feature.shares

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.ShareEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

@Composable
internal fun ShareResourceDetails(
    share: ShareEntity,
    onBrowseResource: ((ResourceEntity) -> Unit)?,
) {
    val context = LocalContext.current
    var resource by remember(share.accountId, share.resourceId) { mutableStateOf<ResourceEntity?>(null) }
    var loading by remember(share.accountId, share.resourceId) { mutableStateOf(onBrowseResource != null) }
    LaunchedEffect(share.accountId, share.resourceId, onBrowseResource != null) {
        if (onBrowseResource != null) {
            resource =
                withContext(Dispatchers.IO) {
                    val store = FileBrowserStore(FileBrowserDatabase.create(context))
                    share.resourceId?.let { id ->
                        store
                            .spaces(share.accountId)
                            .mapNotNull { space ->
                                store.resource(share.accountId, space.driveId, id)
                            }.singleOrNull()
                    }
                }
        }
        loading = false
    }
    Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm)) {
        ShareScopeMetadata(share, resource)
        share.resourceId?.takeIf { it.isNotBlank() }?.let { itemId ->
            eu.opencloud.android.next.core.ui
                .ItemActivitiesAction(share.accountId, itemId, share.label ?: share.path)
        }
        if (onBrowseResource != null) ShareBrowseAction(share.isFolder, resource, loading, onBrowseResource)
    }
}

@Composable
private fun ShareScopeMetadata(
    share: ShareEntity,
    resource: ResourceEntity?,
) {
    Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm)) {
        Text(stringResource(R.string.share_metadata_name_label), style = MaterialTheme.typography.titleSmall)
        Text(
            share.label?.takeIf(String::isNotBlank)
                ?: share.path.trimEnd('/').substringAfterLast('/').ifBlank {
                    stringResource(R.string.share_metadata_fallback_name)
                },
        )
        if (share.sharedAtEpochSeconds > 0) {
            Text(
                stringResource(
                    R.string.share_metadata_created,
                    shareDate(share.sharedAtEpochSeconds * 1000),
                ),
            )
        }
        Text(
            stringResource(
                R.string.share_metadata_expires,
                share.expiresAtEpochMillis?.let(::shareDate)
                    ?: stringResource(R.string.share_metadata_no_expiration),
            ),
        )
        Text(stringResource(R.string.share_metadata_location_label), style = MaterialTheme.typography.titleSmall)
        Text(
            resource?.path ?: share.path.ifBlank { stringResource(R.string.share_metadata_location_unavailable) },
        )
        if (share.isFolder) {
            Text(stringResource(R.string.share_metadata_folder_scope))
        }
    }
}

@Composable
private fun ShareBrowseAction(
    folder: Boolean,
    target: ResourceEntity?,
    loading: Boolean,
    onBrowseResource: (ResourceEntity) -> Unit,
) {
    Column {
        TextButton(enabled = target != null, onClick = { target?.let(onBrowseResource) }) {
            Text(
                stringResource(if (folder) R.string.share_browse_folder else R.string.share_show_in_folder),
            )
        }
        if (target == null) {
            Text(
                if (loading) {
                    stringResource(R.string.share_locating_item)
                } else {
                    stringResource(R.string.share_item_unavailable)
                },
            )
        }
    }
}

private fun shareDate(epochMillis: Long): String =
    Instant.ofEpochMilli(epochMillis).atZone(ZoneId.systemDefault()).format(DateTimeFormatter.ISO_LOCAL_DATE)

@Composable
internal fun sharedItemSummary(share: ShareEntity): String =
    stringResource(
        R.string.share_item_summary,
        stringResource(if (share.isFolder) R.string.share_item_type_folder else R.string.share_item_type_file),
        share.path.ifBlank { stringResource(R.string.share_item_location_unavailable) },
    )
