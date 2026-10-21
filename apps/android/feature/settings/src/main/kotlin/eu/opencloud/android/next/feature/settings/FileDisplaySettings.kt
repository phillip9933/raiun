package eu.opencloud.android.next.feature.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material.icons.filled.TextFields
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import eu.opencloud.android.next.core.datastore.FileDisplayOptions
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions

@Composable
internal fun FileDisplaySettings(
    options: FileDisplayOptions,
    onChange: (FileDisplayOptions) -> Unit,
) {
    Column {
        DisplayToggle(stringResource(R.string.settings_file_size), Icons.Default.Storage, options.showSize) {
            onChange(options.copy(showSize = it))
        }
        DisplayToggle(stringResource(R.string.settings_date_modified), Icons.Default.Schedule, options.showModified) {
            onChange(options.copy(showModified = it))
        }
        DisplayToggle(
            stringResource(R.string.settings_file_extensions),
            Icons.Default.TextFields,
            options.showExtensions,
        ) {
            onChange(options.copy(showExtensions = it))
        }
        DisplayToggle(stringResource(R.string.settings_hidden_files), Icons.Default.VisibilityOff, options.showHidden) {
            onChange(options.copy(showHidden = it))
        }
    }
}

@Composable
private fun DisplayToggle(
    label: String,
    icon: ImageVector,
    checked: Boolean,
    onChange: (Boolean) -> Unit,
) {
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = OpenCloudDimensions.TouchTarget)
            .toggleable(value = checked, role = Role.Switch, onValueChange = onChange)
            .semantics { contentDescription = label }
            .padding(horizontal = OpenCloudDimensions.SpacingMd),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingMd),
    ) {
        Icon(icon, null, Modifier.size(OpenCloudDimensions.IconMedium))
        Text(label, Modifier.weight(1f))
        Switch(checked, onCheckedChange = null)
    }
}

@Composable
internal fun TemporaryCleanupButton(onClear: () -> Unit) {
    var confirm by remember { mutableStateOf(false) }
    FilledTonalButton(
        onClick = { confirm = true },
        modifier = Modifier.fillMaxWidth(),
        colors =
            ButtonDefaults.filledTonalButtonColors(
                containerColor = MaterialTheme.colorScheme.errorContainer,
                contentColor = MaterialTheme.colorScheme.onErrorContainer,
            ),
    ) { Text(stringResource(R.string.settings_clear_temporary_copies_now)) }
    if (confirm) {
        AlertDialog(
            onDismissRequest = { confirm = false },
            title = { Text(stringResource(R.string.settings_clear_temporary_copies_title)) },
            text = { Text(stringResource(R.string.settings_clear_temporary_copies_confirmation)) },
            confirmButton = {
                TextButton(onClick = {
                    confirm = false
                    onClear()
                }) { Text(stringResource(R.string.settings_clear_temporary_copies)) }
            },
            dismissButton = {
                TextButton(onClick = { confirm = false }) { Text(stringResource(R.string.settings_cancel)) }
            },
        )
    }
}
