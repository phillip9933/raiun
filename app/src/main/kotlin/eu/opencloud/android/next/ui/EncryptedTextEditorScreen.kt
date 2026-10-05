package eu.opencloud.android.next.ui

import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.R
import eu.opencloud.android.next.core.ui.SharedTextEditorScreen

@Composable
@Suppress("LongParameterList") // Presentation state plus independent text editor actions.
internal fun EncryptedTextEditorScreen(
    title: String,
    text: String,
    saving: Boolean,
    editable: Boolean,
    tooLarge: Boolean,
    error: VaultRouteError?,
    onChange: (String) -> Unit,
    onSave: () -> Unit,
    onCancel: () -> Unit,
    onClose: () -> Unit,
) {
    SharedTextEditorScreen(
        title = title,
        text = text,
        fieldLabel = stringResource(R.string.vault_text_edit_label),
        backDescription = stringResource(R.string.vault_close),
        saveLabel = stringResource(R.string.vault_text_save),
        saveEnabled = editable && !saving,
        backEnabled = !saving,
        readOnly = saving,
        showTextField = true,
        onTextChange = onChange,
        onBack = onClose,
        onSave = onSave,
        beforeEditor = {
            Text(stringResource(R.string.vault_text_edit_secure_note))
            if (tooLarge) Text(stringResource(R.string.vault_text_edit_too_large))
            error?.let { Text(stringResource(it.stringRes), color = MaterialTheme.colorScheme.error) }
        },
        footerStatus = { if (saving) CircularProgressIndicator() },
        footerActions = {
            OutlinedButton(onClick = onCancel, enabled = !saving) {
                Text(stringResource(eu.opencloud.android.next.core.ui.R.string.shared_editor_discard_draft))
            }
        },
    )
}
