package eu.opencloud.android.next.ui

import android.content.ClipData
import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import eu.opencloud.android.next.R
import eu.opencloud.android.next.core.sync.VaultExternalCopyLease
import eu.opencloud.android.next.core.ui.externalFileChooser

/** External plaintext handoff has a separate bounded lifetime; it never retains the unlocked session. */
@Composable
internal fun rememberVaultOpenWith(
    viewModel: VaultViewModel,
    state: VaultRouteState,
): (String?) -> Unit {
    val context = LocalContext.current
    var pending by remember(viewModel, state.lockRevision, state.currentPath) { mutableStateOf<OpenWithRequest?>(null) }
    var activeLease by remember { mutableStateOf<VaultExternalCopyLease?>(null) }
    val launcher =
        rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            activeLease?.cleanup()
            activeLease = null
        }
    DisposableEffect(viewModel) {
        onDispose {
            activeLease?.cleanup()
            activeLease = null
        }
    }
    pending?.let { request ->
        AlertDialog(
            onDismissRequest = { pending = null },
            properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
            title = { Text(stringResource(R.string.vault_open_with)) },
            text = { Text(stringResource(R.string.vault_open_with_warning)) },
            confirmButton = {
                TextButton(onClick = {
                    pending = null
                    viewModel.prepareOpenWith(request.id) { lease ->
                        activeLease?.cleanup()
                        val intent =
                            Intent(Intent.ACTION_VIEW).apply {
                                setDataAndType(lease.uri, context.contentResolver.getType(lease.uri))
                                clipData = ClipData.newRawUri("", lease.uri)
                                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                            }
                        launcher.launch(externalFileChooser(intent))
                        activeLease = lease
                    }
                }) { Text(stringResource(R.string.vault_open_with_continue)) }
            },
            dismissButton = {
                TextButton(onClick = { pending = null }) { Text(stringResource(R.string.vault_cancel)) }
            },
        )
    }
    return { id -> if (!state.loading && !state.previewSaving) pending = OpenWithRequest(id) }
}

private data class OpenWithRequest(
    val id: String?,
)
