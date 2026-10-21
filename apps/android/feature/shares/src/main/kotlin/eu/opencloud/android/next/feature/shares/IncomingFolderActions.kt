package eu.opencloud.android.next.feature.shares

import android.content.ClipData
import android.content.ClipboardManager
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.sync.IncomingFolderDetails
import eu.opencloud.android.next.core.sync.IncomingFolderDetailsLoader
import eu.opencloud.android.next.core.ui.BrowserAction
import eu.opencloud.android.next.core.ui.BrowserActionSheet
import eu.opencloud.android.next.core.ui.displayServerDate
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
// Mutually exclusive action dialogs; network failures are sanitized and cancellation is preserved.
@Suppress("TooGenericExceptionCaught", "CyclomaticComplexMethod")
internal fun IncomingFolderActions(
    folder: IncomingBrowserItem.Folder,
    onOpen: () -> Unit,
    onChange: () -> Unit,
    onClose: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val loader = remember(context) { IncomingFolderDetailsLoader(context) }
    var details by remember(folder.request) { mutableStateOf<IncomingFolderDetails?>(null) }
    var error by remember(folder.request) { mutableStateOf<String?>(null) }
    var download by remember { mutableStateOf(false) }
    var showDetails by remember { mutableStateOf(false) }
    var confirmVisibility by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var retry by remember { mutableIntStateOf(0) }
    val copied = stringResource(R.string.incoming_link_copied)
    LaunchedEffect(folder.request, retry) {
        error = null
        try {
            details = withContext(Dispatchers.IO) { loader.load(folder.request) }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            error = failure.toOpenCloudError().safeMessage(context)
        }
    }
    if (download) {
        eu.opencloud.android.next.core.ui.FolderDownloadDialog(folder.name, { download = false }) { progress ->
            eu.opencloud.android.next.core.sync
                .FolderDownloads(context)
                .shared(folder.request, progress)
        }
    } else if (showDetails && details != null) {
        IncomingFolderDetailsDialog(requireNotNull(details), onClose) {
            eu.opencloud.android.next.core.ui.ItemActivitiesAction(
                folder.request.account,
                folder.request.remoteId,
                folder.name,
            )
        }
    } else if (confirmVisibility && details != null) {
        val hidden = requireNotNull(details).hidden
        AlertDialog(
            onDismissRequest = { if (!busy) confirmVisibility = false },
            title = {
                Text(
                    stringResource(if (hidden) R.string.incoming_unhide_share else R.string.incoming_hide_share),
                )
            },
            text = {
                Column {
                    Text(stringResource(R.string.incoming_hide_explanation))
                    if (busy) CircularProgressIndicator()
                    error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                }
            },
            confirmButton = {
                TextButton(enabled = !busy, onClick = {
                    scope.launch {
                        busy = true
                        error = null
                        try {
                            withContext(Dispatchers.IO) { loader.setHidden(folder.request, !hidden) }
                            onChange()
                            onClose()
                        } catch (cancelled: CancellationException) {
                            throw cancelled
                        } catch (failure: Exception) {
                            error = failure.toOpenCloudError().safeMessage(context)
                        } finally {
                            busy = false
                        }
                    }
                }) {
                    Text(
                        stringResource(if (hidden) R.string.incoming_unhide_share else R.string.incoming_hide_share),
                    )
                }
            },
            dismissButton = {
                TextButton(enabled = !busy, onClick = { confirmVisibility = false }) {
                    Text(stringResource(R.string.incoming_cancel))
                }
            },
        )
    } else {
        IncomingFolderActionSheet(
            folder.name,
            details,
            error,
            onOpen,
            onClose,
            onDetails = { showDetails = true },
            onCopyLink = {
                context
                    .getSystemService(ClipboardManager::class.java)
                    .setPrimaryClip(ClipData.newPlainText(folder.name, requireNotNull(details).permanentLink))
                android.widget.Toast
                    .makeText(context, copied, android.widget.Toast.LENGTH_SHORT)
                    .show()
                onClose()
            },
            onVisibility = { confirmVisibility = true },
            onRetry = { retry++ },
            folderActions = {
                eu.opencloud.android.next.core.ui.FolderShortcutAction { icon ->
                    eu.opencloud.android.next.core.sync
                        .SharedFolderShortcuts(context)
                        .pin(folder.request, icon)
                }
                BrowserAction(
                    stringResource(eu.opencloud.android.next.core.ui.R.string.folder_download),
                    Icons.Default.Download,
                    onClick = { download = true },
                )
            },
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Suppress("LongParameterList") // Explicit sheet actions and independently loaded metadata.
fun IncomingFolderActionSheet(
    name: String,
    details: IncomingFolderDetails?,
    error: String?,
    onOpen: () -> Unit,
    onClose: () -> Unit,
    onDetails: () -> Unit,
    onCopyLink: () -> Unit,
    onVisibility: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
    folderActions: @Composable () -> Unit = {},
) {
    BrowserActionSheet(name, onClose, modifier) {
        BrowserAction(stringResource(R.string.incoming_open_folder), Icons.Default.FolderOpen, onClick = onOpen)
        if (details != null) {
            folderActions()
            BrowserAction(stringResource(R.string.incoming_details), Icons.Default.Info, onClick = onDetails)
            BrowserAction(stringResource(R.string.incoming_copy_link), Icons.Default.Link, onClick = onCopyLink)
            if (details.canChangeVisibility) {
                BrowserAction(
                    stringResource(
                        if (details.hidden) R.string.incoming_unhide_share else R.string.incoming_hide_share,
                    ),
                    if (details.hidden) Icons.Default.Visibility else Icons.Default.VisibilityOff,
                    onClick = onVisibility,
                )
            }
        } else if (error == null) {
            CircularProgressIndicator()
        }
        if (error != null) {
            Text(error, color = MaterialTheme.colorScheme.error)
            TextButton(onClick = onRetry) { Text(stringResource(R.string.incoming_try_again)) }
        }
    }
}

@Composable
fun IncomingFolderDetailsDialog(
    details: IncomingFolderDetails,
    onClose: () -> Unit,
    activities: @Composable () -> Unit = {},
) {
    val context = LocalContext.current
    AlertDialog(onDismissRequest = onClose, title = { Text(details.name) }, text = {
        Column(
            Modifier.verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
        ) {
            activities()
            DetailValue(
                R.string.incoming_folder_location,
                details.shareName + if (details.path == "/") "" else details.path,
            )
            details.owner?.let { DetailValue(R.string.incoming_folder_owner, it) }
            if (details.sharedBy.isNotEmpty()) {
                DetailValue(
                    R.string.incoming_folder_shared_by,
                    details.sharedBy.joinToString(),
                )
            }
            if (details.sharedAt.isNotEmpty()) {
                DetailValue(
                    R.string.incoming_folder_shared_at,
                    details.sharedAt.joinToString { displayServerDate(it) },
                )
            }
            if (details.expiresAt.isNotEmpty()) {
                DetailValue(
                    R.string.incoming_folder_expires,
                    details.expiresAt.joinToString { displayServerDate(it) },
                )
            }
            details.modifiedAt?.let { DetailValue(R.string.incoming_folder_modified, displayServerDate(it)) }
            details.size?.let {
                DetailValue(
                    R.string.incoming_folder_size,
                    android.text.format.Formatter
                        .formatShortFileSize(context, it),
                )
            }
            DetailValue(R.string.incoming_folder_visible_items, details.visibleItems.toString())
            Text(stringResource(R.string.incoming_folder_access), style = MaterialTheme.typography.titleSmall)
            val access = details.access
            if (access.canBrowse) Text(stringResource(R.string.incoming_access_browse))
            if (access.canReadContent) Text(stringResource(R.string.incoming_access_download))
            if (access.canUpload) Text(stringResource(R.string.incoming_access_upload))
            if (access.canCreateFolder) Text(stringResource(R.string.incoming_access_create))
            Text(stringResource(R.string.incoming_access_scope), style = MaterialTheme.typography.bodySmall)
        }
    }, confirmButton = { TextButton(onClick = onClose) { Text(stringResource(R.string.incoming_close)) } })
}

@Composable
private fun DetailValue(
    label: Int,
    value: String,
) {
    Column {
        Text(stringResource(label), style = MaterialTheme.typography.titleSmall)
        Text(value)
    }
}
