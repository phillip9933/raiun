package eu.opencloud.android.next.feature.files

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudColor
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions

data class BackupDestination(
    val spaceId: String,
    val path: String,
    val destinationKind: String,
    val sharedShareId: String?,
    val sharedFolderId: String?,
    val name: String,
)

data class BackupSharedRoot(
    val name: String,
    val shareId: String,
    val scopeId: String,
    val rootItemId: String,
)

data class BackupSharedFolder(
    val id: String,
    val name: String,
    val path: String,
)

@Composable
// Branches follow the selected destination kind.
@Suppress("LongParameterList", "CyclomaticComplexMethod", "ComplexCondition")
fun BackupDestinationPickerDialog(
    state: FileBrowserUiState,
    onDismiss: () -> Unit,
    onOpenSpace: (SpaceEntity) -> Unit,
    onOpenShare: (BackupSharedRoot) -> Unit,
    onOpenFolder: (ResourceEntity) -> Unit,
    onOpenSharedFolder: (BackupSharedFolder) -> Unit,
    onNavigateUp: () -> Unit,
    onRetry: () -> Unit,
    onCreateFolder: () -> Unit,
    onSelect: (BackupDestination) -> Unit,
) {
    val destination = state.backupPickerDestination
    val spaces = state.spaces.filter { !it.isDisabled && !it.isDeleted }
    val personal = spaces.filter { it.type.equals("personal", true) }
    val others = spaces.filterNot { it.type.equals("personal", true) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.backup_destination_choose)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs)) {
                if (destination != null) {
                    Text("${destination.name} · ${destination.path}", style = MaterialTheme.typography.bodyMedium)
                    TextButton(onClick = onRetry) { Text(stringResource(R.string.backup_destination_change_location)) }
                    if (state.backupPickerTrail.isNotEmpty()) {
                        ListItem(
                            colors = ListItemDefaults.colors(containerColor = OpenCloudColor.Transparent),
                            headlineContent = { Text(stringResource(R.string.browser_up)) },
                            leadingContent = { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null) },
                            modifier = Modifier.fillMaxWidth().clickable(onClick = onNavigateUp),
                        )
                    }
                }
                LazyColumn(Modifier.heightIn(max = OpenCloudDimensions.DestinationPickerHeight)) {
                    if (destination == null) {
                        item {
                            Text(
                                stringResource(R.string.backup_destination_personal),
                                style = MaterialTheme.typography.titleSmall,
                            )
                        }
                        items(personal, key = { it.driveId }) { space -> SpaceChoice(space, onOpenSpace) }
                        item {
                            Text(
                                stringResource(R.string.backup_destination_spaces),
                                style = MaterialTheme.typography.titleSmall,
                            )
                        }
                        items(others, key = { it.driveId }) { space -> SpaceChoice(space, onOpenSpace) }
                        item {
                            Text(
                                stringResource(R.string.backup_destination_shared_with_me),
                                style = MaterialTheme.typography.titleSmall,
                            )
                        }
                        items(state.backupPickerSharedRoots, key = { it.shareId }) { root ->
                            FolderChoice(root.name) { onOpenShare(root) }
                        }
                    } else if (destination.destinationKind == "SPACE") {
                        items(state.backupPickerResources, key = { it.remoteId }) { folder ->
                            FolderChoice(folder.name) { onOpenFolder(folder) }
                        }
                    } else {
                        items(state.backupPickerSharedFolders, key = { it.id }) { folder ->
                            FolderChoice(folder.name) { onOpenSharedFolder(folder) }
                        }
                    }
                }
                if (state.backupPickerLoading) CircularProgressIndicator()
                if (destination?.destinationKind == "SPACE" &&
                    !state.backupPickerLoading &&
                    state.backupPickerError == null
                ) {
                    FilledTonalButton(onClick = onCreateFolder) {
                        Icon(Icons.Default.Add, contentDescription = null)
                        Text(stringResource(R.string.browser_new_folder))
                    }
                }
                state.backupPickerError?.let { error ->
                    Text(error, color = MaterialTheme.colorScheme.error)
                    TextButton(onClick = onRetry) { Text(stringResource(R.string.backup_destination_retry)) }
                }
                if (destination != null &&
                    !state.backupPickerLoading &&
                    state.backupPickerError == null &&
                    state.backupPickerResources.isEmpty() &&
                    state.backupPickerSharedFolders.isEmpty()
                ) {
                    Text(stringResource(R.string.browser_no_folders_here))
                }
                if (destination?.destinationKind == "SHARED_FOLDER" &&
                    !state.backupPickerLoading &&
                    !state.backupPickerCanSelect &&
                    state.backupPickerError == null
                ) {
                    Text(
                        stringResource(R.string.backup_destination_upload_unavailable),
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = { destination?.let(onSelect) },
                enabled =
                    destination != null &&
                        state.backupPickerCanSelect &&
                        !state.backupPickerLoading &&
                        state.backupPickerError == null,
            ) {
                Text(stringResource(R.string.browser_select_this_folder))
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.browser_cancel)) } },
    )
}

@Composable
private fun SpaceChoice(
    space: SpaceEntity,
    onOpen: (SpaceEntity) -> Unit,
) {
    val unavailable = space.type.contains("encrypted", ignoreCase = true)
    ListItem(
        colors = ListItemDefaults.colors(containerColor = OpenCloudColor.Transparent),
        headlineContent = { Text(space.name) },
        supportingContent =
            if (unavailable) {
                (
                    {
                        Text(stringResource(R.string.backup_destination_encrypted_unavailable))
                    }
                )
            } else {
                null
            },
        leadingContent = { Icon(Icons.Default.Folder, contentDescription = null) },
        modifier = Modifier.fillMaxWidth().then(if (unavailable) Modifier else Modifier.clickable { onOpen(space) }),
    )
}

@Composable
private fun FolderChoice(
    name: String,
    onOpen: () -> Unit,
) {
    ListItem(
        colors = ListItemDefaults.colors(containerColor = OpenCloudColor.Transparent),
        headlineContent = { Text(name) },
        leadingContent = { Icon(Icons.Default.Folder, contentDescription = null) },
        modifier = Modifier.fillMaxWidth().clickable(onClick = onOpen),
    )
}
