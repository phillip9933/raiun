package eu.opencloud.android.next.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import eu.opencloud.android.next.R

/** One secure dialog window keeps keyboard/focus stable while selecting a verified root action. */
@Composable
internal fun EncryptedRootActionsContent(
    state: VaultRouteState,
    callbacks: VaultRouteCallbacks,
) {
    var selected by remember(state.lockRevision, state.selectedLocation?.id) { mutableStateOf<VaultEntryAction?>(null) }
    val title = state.selectedTitle.orEmpty()
    var name by remember(state.lockRevision, state.selectedLocation?.id, title) { mutableStateOf(title) }
    val folder = state.selectedLocation?.kind == VaultLocationKindUi.FOLDER_VAULT
    val dismiss = { if (selected == null) callbacks.onDismissRootActions() else selected = null }
    AlertDialog(
        onDismissRequest = dismiss,
        title = {
            Text(
                when (selected) {
                    VaultEntryAction.RENAME -> stringResource(R.string.vault_rename)
                    VaultEntryAction.DELETE -> stringResource(R.string.vault_delete)
                    else -> title
                },
            )
        },
        text = {
            when (selected) {
                VaultEntryAction.RENAME ->
                    OutlinedTextField(
                        value = name,
                        label = { Text(stringResource(R.string.vault_name)) },
                        onValueChange = { name = it },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                    )
                VaultEntryAction.DELETE -> Text(stringResource(R.string.vault_root_delete_warning, title))
                else ->
                    RootActionChoices(
                        folder,
                        state.loading,
                        onSelect = { selected = it },
                        onManage = callbacks.onManageLocation,
                    )
            }
        },
        confirmButton = {
            when (selected) {
                VaultEntryAction.RENAME ->
                    Button(
                        enabled = name.isNotBlank() && !state.loading,
                        onClick = {
                            callbacks.onDismissRootActions()
                            callbacks.onRenameRoot(name)
                        },
                    ) { Text(stringResource(R.string.vault_confirm)) }
                VaultEntryAction.DELETE ->
                    Button(
                        enabled = !state.loading,
                        onClick = {
                            callbacks.onDismissRootActions()
                            callbacks.onDeleteRoot()
                        },
                    ) { Text(stringResource(R.string.vault_delete)) }
                else ->
                    TextButton(
                        onClick = callbacks.onDismissRootActions,
                    ) { Text(stringResource(R.string.vault_close)) }
            }
        },
        dismissButton = {
            if (selected != null) {
                TextButton(onClick = { selected = null }) { Text(stringResource(R.string.vault_cancel)) }
            }
        },
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
    )
}

@Composable
private fun RootActionChoices(
    folder: Boolean,
    loading: Boolean,
    onSelect: (VaultEntryAction) -> Unit,
    onManage: () -> Unit,
) {
    Column {
        val header = if (folder) R.string.vault_encrypted_folder_header else R.string.vault_encrypted_space_header
        Text(stringResource(header))
        if (folder) {
            OutlinedButton(onClick = { onSelect(VaultEntryAction.RENAME) }, enabled = !loading) {
                Text(stringResource(R.string.vault_rename))
            }
            OutlinedButton(onClick = { onSelect(VaultEntryAction.DELETE) }, enabled = !loading) {
                Text(stringResource(R.string.vault_delete))
            }
        }
        OutlinedButton(onClick = onManage, enabled = !loading) {
            Text(stringResource(if (folder) R.string.vault_manage_collaborators else R.string.vault_manage_space))
        }
    }
}
