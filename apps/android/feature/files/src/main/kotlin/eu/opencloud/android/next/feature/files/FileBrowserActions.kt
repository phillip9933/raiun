package eu.opencloud.android.next.feature.files

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.DriveFileMove
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.OfflinePin
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.outlined.People
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.ui.BrowserAction
import eu.opencloud.android.next.core.ui.BrowserActionSheet

@OptIn(ExperimentalFoundationApi::class)
@Composable
internal fun SheetAction(
    label: String,
    icon: ImageVector,
    color: Color = MaterialTheme.colorScheme.onSurface,
    onClick: () -> Unit,
) = BrowserAction(label, icon, color = color, onClick = onClick)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Suppress("LongParameterList")
fun ResourceActionSheet(
    resource: ResourceEntity,
    onDismiss: () -> Unit,
    onRename: () -> Unit,
    onMove: () -> Unit,
    onCopy: () -> Unit,
    onDownloadForOffline: () -> Unit,
    onDelete: () -> Unit,
    onToggleFavorite: () -> Unit = {},
    onShare: (() -> Unit)? = null,
    sheetState: androidx.compose.material3.SheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
    onOpenWith: (() -> Unit)? = null,
    onOpenOnServer: (() -> Unit)? = null,
    onDetails: (() -> Unit)? = null,
    onSend: (() -> Unit)? = null,
    onExport: ((Boolean) -> Unit)? = null,
    onRemoveLocalCopy: () -> Unit = {},
    keptOffline: Boolean = resource.offlinePinned,
) {
    BrowserActionSheet(resource.name, onDismiss, sheetState = sheetState) {
        onOpenWith?.let {
            SheetAction(
                stringResource(R.string.browser_open_with),
                Icons.AutoMirrored.Filled.OpenInNew,
                onClick = it,
            )
        }
        onOpenOnServer?.let {
            SheetAction(
                stringResource(R.string.document_web_open),
                Icons.Default.Apps,
                onClick = it,
            )
        }
        onSend?.let {
            SheetAction(
                stringResource(R.string.browser_send),
                Icons.AutoMirrored.Filled.Send,
                onClick = it,
            )
        }
        onShare?.let { SheetAction(stringResource(R.string.browser_share), Icons.Outlined.People, onClick = it) }
        onDetails?.let { SheetAction(stringResource(R.string.browser_details), Icons.Default.Info, onClick = it) }
        FolderShortcutAction(resource)
        ActionGroupDivider()
        SheetAction(stringResource(R.string.browser_rename), Icons.Default.Edit, onClick = onRename)
        SheetAction(
            stringResource(R.string.browser_move_to),
            Icons.AutoMirrored.Filled.DriveFileMove,
            onClick = onMove,
        )
        SheetAction(stringResource(R.string.browser_copy_to), Icons.Default.ContentCopy, onClick = onCopy)
        SheetAction(
            if (resource.isFavorite) {
                stringResource(
                    R.string.browser_remove_from_favorites,
                )
            } else {
                stringResource(R.string.browser_add_to_favorites)
            },
            Icons.Default.Star,
            onClick = onToggleFavorite,
        )
        ActionGroupDivider()
        if (!keptOffline) {
            SheetAction(
                stringResource(R.string.browser_make_available_offline),
                Icons.Default.OfflinePin,
                onClick = onDownloadForOffline,
            )
        }
        if (resource.hasLocalCopy || keptOffline) {
            SheetAction(
                if (resource.kind ==
                    ResourceKind.FOLDER
                ) {
                    stringResource(R.string.browser_stop_keeping_offline)
                } else {
                    stringResource(R.string.browser_delete_local_copy)
                },
                cleanupIcon(),
                onClick = onRemoveLocalCopy,
            )
        }
        onExport?.let { export ->
            SheetAction(
                stringResource(R.string.browser_copy_to_device),
                Icons.Default.ContentCopy,
                onClick = { export(false) },
            )
        }
        ActionGroupDivider()
        SheetAction(
            stringResource(R.string.browser_delete),
            Icons.Default.Delete,
            MaterialTheme.colorScheme.error,
            onDelete,
        )
    }
}

@Composable
internal fun BrowserNotice(
    title: String,
    message: String,
    onDismiss: () -> Unit,
) = AlertDialog(
    onDismissRequest = onDismiss,
    title = { Text(title) },
    text = { Text(message) },
    confirmButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.browser_ok)) } },
)

@Composable
internal fun ConflictResolutionDialog(
    conflict: TransferEntity,
    count: Int,
    busy: Boolean,
    onDecision: (ConflictDecision) -> Unit,
    onCancelAll: () -> Unit,
) {
    var confirmCancelAll by remember(conflict.accountId) { mutableStateOf(false) }
    if (confirmCancelAll) {
        AlertDialog(
            onDismissRequest = { if (!busy) confirmCancelAll = false },
            title = { Text(stringResource(R.string.browser_cancel_conflicts_title)) },
            text = { Text(stringResource(R.string.browser_cancel_conflicts_confirmation, count)) },
            confirmButton = {
                TextButton(
                    enabled = !busy,
                    onClick = {
                        confirmCancelAll = false
                        onCancelAll()
                    },
                ) { Text(stringResource(R.string.browser_cancel_conflicts_action)) }
            },
            dismissButton = {
                TextButton(enabled = !busy, onClick = { confirmCancelAll = false }) {
                    Text(stringResource(R.string.browser_keep_conflicts))
                }
            },
        )
    } else {
        AlertDialog(
            onDismissRequest = {},
            title = { Text(stringResource(R.string.browser_upload_conflict)) },
            text = {
                Column {
                    Text(stringResource(R.string.browser_conflict_message, conflict.displayName))
                    if (busy) Text(stringResource(R.string.browser_cancelling_conflicts))
                }
            },
            confirmButton = {
                Column(Modifier.fillMaxWidth()) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
                    ) {
                        FilledTonalButton(
                            onClick = { onDecision(ConflictDecision.KEEP_BOTH) },
                            enabled = !busy,
                            modifier = Modifier.weight(1f),
                        ) { Text(stringResource(R.string.browser_keep_both), textAlign = TextAlign.Center) }
                        FilledTonalButton(
                            onClick = { onDecision(ConflictDecision.REPLACE) },
                            enabled = !busy,
                            modifier = Modifier.weight(1f),
                        ) { Text(stringResource(R.string.browser_replace_remote), textAlign = TextAlign.Center) }
                    }
                    TextButton(onClick = { onDecision(ConflictDecision.CANCEL) }, enabled = !busy) {
                        Text(stringResource(R.string.browser_cancel_upload))
                    }
                    TextButton(onClick = { confirmCancelAll = true }, enabled = !busy) {
                        Text(stringResource(R.string.browser_cancel_conflicts_action))
                    }
                }
            },
        )
    }
}

@Composable
internal fun NameDialog(
    title: String,
    confirm: String,
    onDismiss: () -> Unit,
    initial: String = "",
    onConfirm: (String) -> Unit,
) {
    var name by remember { mutableStateOf(initial) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text(stringResource(R.string.browser_sort_name)) },
                singleLine = true,
            )
        },
        confirmButton = {
            Button(onClick = { onConfirm(name) }, enabled = name.isNotBlank()) { Text(confirm) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.browser_cancel)) } },
    )
}
