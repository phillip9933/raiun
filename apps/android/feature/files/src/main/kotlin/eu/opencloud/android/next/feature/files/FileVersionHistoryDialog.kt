package eu.opencloud.android.next.feature.files

import android.text.format.Formatter
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
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
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.network.RemoteFileVersion
import eu.opencloud.android.next.core.network.TransferHttpException
import eu.opencloud.android.next.core.sync.FileVersionManager
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.util.Date

@Suppress("TooGenericExceptionCaught") // UI failure boundary: preserve cancellation and show a safe message.
@Composable
fun FileVersionHistoryDialog(
    resource: ResourceEntity,
    onDismiss: () -> Unit,
    loadVersions: (suspend (ResourceEntity) -> List<RemoteFileVersion>)? = null,
    restoreVersion: (suspend (ResourceEntity, RemoteFileVersion) -> Unit)? = null,
) {
    val context = LocalContext.current
    val manager = remember { FileVersionManager(context.applicationContext) }
    val scope = rememberCoroutineScope()
    var versions by remember(resource) { mutableStateOf<List<RemoteFileVersion>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var restoring by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<Int?>(null) }
    var attempt by remember { mutableIntStateOf(0) }
    var selection by remember { mutableStateOf<RemoteFileVersion?>(null) }
    var restored by remember { mutableStateOf(false) }
    LaunchedEffect(resource, attempt) {
        loading = true
        message = null
        versions = emptyList()
        try {
            versions = withContext(Dispatchers.IO) { (loadVersions ?: manager::list)(resource) }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: TransferHttpException) {
            message =
                if (error.statusCode in setOf(404, 405, 501)) {
                    R.string.file_versions_unavailable
                } else {
                    R.string.file_versions_error
                }
        } catch (_: Exception) {
            message = R.string.file_versions_error
        } finally {
            loading = false
        }
    }
    AlertDialog(
        onDismissRequest = { if (!restoring) onDismiss() },
        title = { Text(stringResource(R.string.file_versions_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm)) {
                Text(resource.name)
                if (loading) Text(stringResource(R.string.file_versions_loading))
                message?.let { Text(stringResource(it)) }
                if (!loading && !restored) {
                    VersionResults(versions, restoring, message, { attempt++ }, { selection = it })
                }
                if (restoring) Text(stringResource(R.string.file_versions_restoring))
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss, enabled = !restoring) { Text(stringResource(R.string.file_versions_close)) }
        },
    )
    selection?.let { version ->
        AlertDialog(
            onDismissRequest = { selection = null },
            title = { Text(stringResource(R.string.file_versions_restore)) },
            text = { Text(stringResource(R.string.file_versions_confirm, resource.name)) },
            dismissButton = {
                TextButton(
                    onClick = { selection = null },
                ) { Text(stringResource(R.string.file_versions_cancel)) }
            },
            confirmButton = {
                Button(onClick = {
                    selection = null
                    restoring = true
                    scope.launch {
                        try {
                            message =
                                restoreVersionMessage {
                                    (restoreVersion ?: manager::restore)(resource, version)
                                }
                            restored = message == R.string.file_versions_restored
                        } finally {
                            restoring = false
                        }
                    }
                }) { Text(stringResource(R.string.file_versions_restore)) }
            },
        )
    }
}

@Composable
private fun VersionResults(
    versions: List<RemoteFileVersion>,
    restoring: Boolean,
    message: Int?,
    retry: () -> Unit,
    select: (RemoteFileVersion) -> Unit,
) {
    Column {
        if (message == null && versions.isEmpty()) Text(stringResource(R.string.file_versions_empty))
        VersionRows(versions, !restoring, select)
        if (message != null) {
            FilledTonalButton(onClick = retry, enabled = !restoring) {
                Text(stringResource(R.string.file_versions_retry))
            }
        }
    }
}

@Suppress("TooGenericExceptionCaught") // Present a safe recovery message for any failed or ambiguous restore.
private suspend fun restoreVersionMessage(action: suspend () -> Unit): Int =
    try {
        withContext(Dispatchers.IO) { action() }
        R.string.file_versions_restored
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (_: Exception) {
        R.string.file_versions_restore_error
    }

@Composable
private fun VersionRows(
    versions: List<RemoteFileVersion>,
    enabled: Boolean,
    onRestore: (RemoteFileVersion) -> Unit,
) {
    val context = LocalContext.current
    LazyColumn(
        Modifier.heightIn(max = OpenCloudDimensions.VersionHistoryListHeight),
        verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
    ) {
        items(versions, key = { it.id }) { version ->
            Text(
                version.modifiedAt?.let { DateFormat.getDateTimeInstance().format(Date(it)) }
                    ?: stringResource(R.string.file_versions_unknown_date),
            )
            Text(
                version.sizeBytes?.let { Formatter.formatFileSize(context, it) }
                    ?: stringResource(R.string.file_versions_unknown_size),
            )
            FilledTonalButton(
                onClick = { onRestore(version) },
                enabled = enabled,
            ) { Text(stringResource(R.string.file_versions_restore)) }
            HorizontalDivider()
        }
    }
}
