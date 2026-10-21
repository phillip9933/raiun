package eu.opencloud.android.next.feature.transfers

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.window.Dialog
import androidx.lifecycle.viewmodel.compose.viewModel
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.sync.DocumentEdit
import eu.opencloud.android.next.core.sync.DocumentEditState

@Composable
fun DocumentEditsDialog(
    accountId: String,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: DocumentEditsViewModel = viewModel(key = "document-edits-$accountId"),
) {
    val state by viewModel.state.collectAsState()
    var exportId by rememberSaveable { mutableStateOf<String?>(null) }
    val export =
        rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
            if (uri != null) exportId?.let { viewModel.export(it, uri) }
        }
    LaunchedEffect(accountId) { viewModel.load(accountId) }
    DocumentEditsContent(
        state,
        onExport = {
            exportId = it.id
            export.launch(it.name)
        },
        onDiscard = viewModel::discard,
        onRefresh = viewModel::refresh,
        onDismiss = onDismiss,
        modifier = modifier,
    )
}

// Explicit callbacks keep recovery actions independently testable without a database or document picker.
@Suppress("LongParameterList")
@Composable
fun DocumentEditsContent(
    state: DocumentEditsState,
    onExport: (DocumentEdit) -> Unit,
    onDiscard: (DocumentEdit) -> Unit,
    onRefresh: () -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var discard by remember { mutableStateOf<DocumentEdit?>(null) }
    Dialog(onDismissRequest = onDismiss) {
        Surface(modifier = modifier.fillMaxWidth().fillMaxHeight(0.8f), shape = MaterialTheme.shapes.extraLarge) {
            Column(
                Modifier.padding(OpenCloudDimensions.SpacingMd),
                verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
            ) {
                Text(stringResource(R.string.document_edits_title), style = MaterialTheme.typography.titleLarge)
                Text(stringResource(R.string.document_edits_warning))
                if (state.busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                if (state.inventory.unreadableCount > 0) {
                    Text(
                        pluralStringResource(
                            R.plurals.document_edits_unreadable_records,
                            state.inventory.unreadableCount,
                            state.inventory.unreadableCount,
                        ),
                    )
                }
                state.message?.let { message ->
                    val messageResource =
                        when (message) {
                            DocumentEditsMessage.RECOVERY_COPY_EXPORTED ->
                                R.string.document_edits_recovery_copy_exported
                            DocumentEditsMessage.ACTION_FAILED -> R.string.document_edits_action_failed
                        }
                    Text(stringResource(messageResource))
                }
                LazyColumn(
                    Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
                ) {
                    if (state.inventory.edits.isEmpty()) {
                        item { Text(stringResource(R.string.document_edits_empty)) }
                    }
                    items(state.inventory.edits, key = { it.id }) { edit ->
                        DocumentEditRow(edit, state, onExport = {
                            onExport(edit)
                        }, onDiscard = { discard = edit })
                    }
                }
                Row {
                    TextButton(onClick = onRefresh, enabled = !state.busy) {
                        Text(stringResource(R.string.document_edits_refresh))
                    }
                    TextButton(onClick = onDismiss) { Text(stringResource(R.string.document_edits_close)) }
                }
            }
        }
    }
    discard?.let { edit ->
        AlertDialog(
            onDismissRequest = { discard = null },
            title = { Text(stringResource(R.string.document_edits_discard_title)) },
            text = {
                Text(stringResource(R.string.document_edits_discard_confirmation, edit.name))
            },
            confirmButton = {
                TextButton(onClick = {
                    onDiscard(edit)
                    discard = null
                }) { Text(stringResource(R.string.document_edits_discard_action)) }
            },
            dismissButton = {
                TextButton(onClick = { discard = null }) {
                    Text(stringResource(R.string.document_edits_cancel))
                }
            },
        )
    }
}

@Composable
private fun DocumentEditRow(
    edit: DocumentEdit,
    state: DocumentEditsState,
    onExport: () -> Unit,
    onDiscard: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val active = edit.id in state.activeIds
    Column(modifier) {
        Text(edit.name, style = MaterialTheme.typography.titleMedium)
        Text(edit.path, style = MaterialTheme.typography.bodySmall)
        val status =
            if (active) {
                R.string.document_edits_open_in_editor
            } else {
                when (edit.state) {
                    DocumentEditState.OPEN, DocumentEditState.REVIEW -> R.string.document_edits_needs_review
                    DocumentEditState.READY -> R.string.document_edits_save_pending
                    DocumentEditState.SUBMITTED -> R.string.document_edits_transfer_queued
                }
            }
        Text(stringResource(status))
        Row {
            TextButton(onClick = onExport, enabled = !state.busy && !active) {
                Text(stringResource(R.string.document_edits_export_copy))
            }
            if (edit.state in setOf(DocumentEditState.OPEN, DocumentEditState.REVIEW)) {
                TextButton(onClick = onDiscard, enabled = !state.busy && !active) {
                    Text(stringResource(R.string.document_edits_discard))
                }
            }
        }
        HorizontalDivider()
    }
}
