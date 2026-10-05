package eu.opencloud.android.next.core.ui

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy

/** Shared copy/move destination collision prompt for ordinary and encrypted locations. */
@Composable
@Suppress("LongParameterList") // Shared collision UI keeps busy, secure-window, and outcome behavior explicit.
fun FileNameConflictDialog(
    name: String,
    proposedName: String,
    busy: Boolean,
    secureWindow: Boolean,
    onKeepBoth: () -> Unit,
    onCancel: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = { if (!busy) onCancel() },
        title = { Text(stringResource(R.string.file_name_conflict_title)) },
        text = {
            Text(stringResource(R.string.file_name_conflict_message, name, proposedName))
        },
        confirmButton = {
            Button(onClick = onKeepBoth, enabled = !busy) {
                Text(stringResource(R.string.file_name_conflict_keep_both))
            }
        },
        dismissButton = {
            TextButton(onClick = onCancel, enabled = !busy) {
                Text(stringResource(R.string.file_name_conflict_cancel))
            }
        },
        properties =
            DialogProperties(
                securePolicy = if (secureWindow) SecureFlagPolicy.SecureOn else SecureFlagPolicy.Inherit,
            ),
    )
}
