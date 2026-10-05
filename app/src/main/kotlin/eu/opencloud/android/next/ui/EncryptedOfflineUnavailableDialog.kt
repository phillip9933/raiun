package eu.opencloud.android.next.ui

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.R
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultLocationKind

@Composable
internal fun EncryptedOfflineUnavailableDialog(
    location: VaultLocation,
    onDismiss: () -> Unit,
) {
    val type =
        stringResource(
            if (location.kind == VaultLocationKind.SPACE || location.kind == VaultLocationKind.SPACE_VAULT) {
                R.string.vault_offline_unavailable_space
            } else {
                R.string.vault_offline_unavailable_folder
            },
        )
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.vault_offline_unavailable_title)) },
        text = {
            Text(stringResource(R.string.vault_offline_unavailable_message, type, location.title))
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.vault_close))
            }
        },
    )
}

internal inline fun dispatchOfflineAwareEncryptedLocation(
    location: VaultLocation,
    onOpen: (VaultLocation) -> Unit,
    onUnavailable: (VaultLocation) -> Unit,
) {
    if (location.offlineUnavailable) onUnavailable(location) else onOpen(location)
}
