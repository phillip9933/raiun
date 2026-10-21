package eu.opencloud.android.next.feature.files

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import eu.opencloud.android.next.core.ui.SharedTextEditorScreen

@Composable
@Suppress("LongParameterList") // Screen state, explicit actions and scoped editor identity.
fun TextEditorRoute(
    accountId: String,
    spaceId: String,
    resourceId: String,
    onClose: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: TextEditorViewModel = viewModel(key = "editor-$accountId-$spaceId-$resourceId"),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    LaunchedEffect(accountId, spaceId, resourceId) { viewModel.load(accountId, spaceId, resourceId) }
    BackHandler { viewModel.close(onClose) }
    TextEditorScreen(
        state,
        viewModel::edit,
        viewModel::save,
        viewModel::refresh,
        { viewModel.close(onClose) },
        modifier,
        onDiscard = { viewModel.discard(onClose) },
        onResumeDraft = viewModel::resumeDraft,
    )
}

@Composable
@Suppress("LongParameterList") // Screen state, explicit actions and scoped editor identity.
fun TextEditorScreen(
    state: TextEditorState,
    onEdit: (String) -> Unit,
    onSave: () -> Unit,
    onRefresh: () -> Unit,
    onClose: () -> Unit,
    modifier: Modifier = Modifier,
    onDiscard: () -> Unit = {},
    onResumeDraft: () -> Unit = {},
) {
    val queued = state.draft?.queuedId != null
    val editable = !state.busy && !state.chooseDraft && !queued && state.draft != null
    SharedTextEditorScreen(
        title = state.draft?.name ?: stringResource(R.string.document_edit_text),
        text = state.draft?.text.orEmpty(),
        fieldLabel = stringResource(R.string.document_utf8_text),
        backDescription = stringResource(R.string.document_back),
        saveLabel = stringResource(R.string.document_save_server),
        saveEnabled = editable,
        backEnabled = !state.busy,
        readOnly = !editable,
        showTextField = state.draft != null,
        onTextChange = onEdit,
        onBack = onClose,
        onSave = onSave,
        modifier = modifier,
        beforeEditor = {
            if (state.busy) androidx.compose.material3.CircularProgressIndicator()
            state.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            DraftChangeNotice(state, onClose, onResumeDraft, onDiscard)
        },
        footerStatus = {
            Text(
                stringResource(
                    if (queued) {
                        R.string.editor_upload_queued
                    } else if (state.savingDraft) {
                        R.string.editor_saving
                    } else {
                        R.string.editor_saved
                    },
                ),
                style = MaterialTheme.typography.bodySmall,
            )
        },
        footerActions = {
            if (queued) {
                OutlinedButton(onClick = onRefresh, enabled = !state.busy) {
                    Text(stringResource(R.string.document_check_save))
                }
            } else {
                DiscardDraftButton(enabled = !state.busy && state.draft != null, onDiscard = onDiscard)
            }
        },
    )
}

@Composable
private fun DraftChangeNotice(
    state: TextEditorState,
    onClose: () -> Unit,
    onResumeDraft: () -> Unit,
    onDiscard: () -> Unit,
) {
    if (state.chooseDraft) {
        AlertDialog(
            onDismissRequest = onClose,
            title = { Text(stringResource(R.string.editor_changed_title)) },
            text = {
                Column {
                    Text(stringResource(R.string.editor_changed_message))
                    DiscardDraftButton(enabled = !state.busy && state.draft?.queuedId == null, onDiscard = onDiscard)
                }
            },
            confirmButton = {
                FilledTonalButton(
                    onClick = onResumeDraft,
                ) { Text(stringResource(R.string.document_resume_draft)) }
            },
            dismissButton = {
                OutlinedButton(
                    onClick = onClose,
                ) { Text(stringResource(R.string.document_view_current)) }
            },
        )
    } else if (state.serverChanged) {
        Text(stringResource(R.string.editor_older_draft), style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun DiscardDraftButton(
    enabled: Boolean,
    onDiscard: () -> Unit,
) {
    var confirming by remember { mutableStateOf(false) }
    androidx.compose.foundation.layout.Box {
        OutlinedButton(
            onClick = { confirming = true },
            enabled = enabled,
        ) { Text(stringResource(R.string.document_discard_draft)) }
        if (confirming) {
            AlertDialog(
                onDismissRequest = { confirming = false },
                title = { Text(stringResource(R.string.document_discard_title)) },
                text = {
                    Text(
                        stringResource(R.string.document_discard_description),
                    )
                },
                confirmButton = {
                    TextButton(onClick = {
                        confirming = false
                        onDiscard()
                    }) { Text(stringResource(R.string.document_discard)) }
                },
                dismissButton = {
                    TextButton(
                        onClick = { confirming = false },
                    ) { Text(stringResource(R.string.document_cancel)) }
                },
            )
        }
    }
}
