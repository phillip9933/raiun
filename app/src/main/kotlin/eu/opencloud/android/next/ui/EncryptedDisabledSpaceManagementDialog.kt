package eu.opencloud.android.next.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import eu.opencloud.android.next.R
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.sync.EncryptedLocationManagementRepository
import eu.opencloud.android.next.core.sync.VaultLocation
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Manages a disabled encrypted Space through Graph metadata only; its encrypted DAV root stays closed. */
@Composable
@Suppress("TooGenericExceptionCaught") // Convert server errors to safe, localized dialog state; rethrow cancellation.
internal fun EncryptedDisabledSpaceManagementDialog(
    accountId: String,
    location: VaultLocation,
    onClose: () -> Unit,
    onLifecycleChange: (VaultLocation?) -> Unit,
    actionsOverride: EncryptedDisabledSpaceActions? = null,
) {
    val context = LocalContext.current
    val actions =
        actionsOverride ?: remember(context) {
            EncryptedDisabledSpaceRepositoryActions(EncryptedLocationManagementRepository(context))
        }
    val scope = rememberCoroutineScope()
    var busy by remember(location) { mutableStateOf(false) }
    var error by remember(location) { mutableStateOf<String?>(null) }
    var confirmPurge by remember(location) { mutableStateOf(false) }

    fun perform(action: suspend () -> VaultLocation?) {
        if (busy) return
        busy = true
        error = null
        scope.launch {
            try {
                val updated = withContext(Dispatchers.IO) { action() }
                onLifecycleChange(updated)
                onClose()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Exception) {
                error = failure.toOpenCloudError().safeMessage(context)
            } finally {
                busy = false
            }
        }
    }

    AlertDialog(
        onDismissRequest = { if (!busy) onClose() },
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
        title = { Text(stringResource(R.string.vault_disabled_management_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm)) {
                Text(location.title)
                Text(stringResource(R.string.vault_disabled_management_description))
                if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                error?.let { Text(it) }
            }
        },
        confirmButton = {
            FilledTonalButton(enabled = !busy, onClick = {
                perform { actions.restoreDisabledSpace(accountId, location) }
            }) { Text(stringResource(R.string.vault_disabled_restore)) }
        },
        dismissButton = {
            OutlinedButton(
                enabled = !busy,
                onClick = { confirmPurge = true },
                colors =
                    ButtonDefaults.outlinedButtonColors(
                        contentColor = androidx.compose.material3.MaterialTheme.colorScheme.error,
                    ),
            ) {
                Text(stringResource(R.string.vault_disabled_permanently_delete))
            }
        },
    )
    if (confirmPurge) {
        AlertDialog(
            onDismissRequest = { if (!busy) confirmPurge = false },
            properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
            title = { Text(stringResource(R.string.vault_disabled_permanently_delete)) },
            text = { Text(stringResource(R.string.vault_disabled_purge_confirm, location.title)) },
            confirmButton = {
                Button(
                    enabled = !busy,
                    onClick = {
                        perform {
                            actions.permanentlyDeleteDisabledSpace(accountId, location)
                            null
                        }
                    },
                    colors =
                        ButtonDefaults.buttonColors(
                            containerColor = androidx.compose.material3.MaterialTheme.colorScheme.error,
                        ),
                ) { Text(stringResource(R.string.vault_disabled_purge)) }
            },
            dismissButton = {
                TextButton(enabled = !busy, onClick = { confirmPurge = false }) {
                    Text(stringResource(R.string.vault_cancel))
                }
            },
        )
    }
}

internal interface EncryptedDisabledSpaceActions {
    suspend fun restoreDisabledSpace(
        accountId: String,
        location: VaultLocation,
    ): VaultLocation

    suspend fun permanentlyDeleteDisabledSpace(
        accountId: String,
        location: VaultLocation,
    )
}

private class EncryptedDisabledSpaceRepositoryActions(
    private val repository: EncryptedLocationManagementRepository,
) : EncryptedDisabledSpaceActions {
    override suspend fun restoreDisabledSpace(
        accountId: String,
        location: VaultLocation,
    ) = repository.restoreDisabledSpace(accountId, location)

    override suspend fun permanentlyDeleteDisabledSpace(
        accountId: String,
        location: VaultLocation,
    ) = repository.permanentlyDeleteDisabledSpace(accountId, location)
}
