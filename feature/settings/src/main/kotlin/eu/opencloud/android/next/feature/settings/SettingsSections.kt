package eu.opencloud.android.next.feature.settings

import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Palette
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Upload
import androidx.compose.material3.Card
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import eu.opencloud.android.next.core.datastore.Appearance
import eu.opencloud.android.next.core.datastore.UserSettings
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.security.AppLock

@Composable
@Suppress("LongParameterList") // Explicit settings values and callbacks keep navigation out of the rendering layer.
internal fun SettingsSections(
    state: UserSettings,
    onOpenAppearance: () -> Unit,
    onBackup: () -> Unit,
    diagnostics: SettingsDiagnostics,
    onOpenVaultPreferences: () -> Unit,
    onPermissions: () -> Unit,
    onOpenTemporary: () -> Unit,
    onFileOpening: () -> Unit,
) {
    Column(
        Modifier.padding(OpenCloudDimensions.SpacingMd),
        verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingMd),
    ) {
        Text(stringResource(R.string.settings_appearance_defaults), style = MaterialTheme.typography.titleSmall)
        Card(onClick = onOpenAppearance, modifier = Modifier.fillMaxWidth()) {
            ListItem(
                headlineContent = { Text(stringResource(R.string.settings_appearance)) },
                supportingContent = { Text(stringResource(R.string.settings_appearance_summary)) },
                leadingContent = { Icon(Icons.Default.Palette, null) },
                trailingContent = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, null) },
                colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.surfaceContainerHighest),
            )
        }
        Card(onClick = onFileOpening, modifier = Modifier.fillMaxWidth()) {
            ListItem(
                headlineContent = { Text(stringResource(R.string.settings_opening_files)) },
                supportingContent = { Text(stringResource(R.string.settings_opening_summary)) },
                leadingContent = { Icon(Icons.Default.FolderOpen, null) },
                trailingContent = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, null) },
                colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.surfaceContainerHighest),
            )
        }
        Text(stringResource(R.string.settings_security), style = MaterialTheme.typography.titleSmall)
        AppLockMainCard()
        Card(onClick = onOpenVaultPreferences, modifier = Modifier.fillMaxWidth()) {
            ListItem(
                headlineContent = { Text(stringResource(R.string.settings_encrypted_preferences)) },
                leadingContent = { Icon(Icons.Default.Fingerprint, null) },
                supportingContent = { Text(stringResource(R.string.settings_encrypted_preferences_summary)) },
                trailingContent = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, null) },
                colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.surfaceContainerHighest),
            )
        }
        Card(onClick = onPermissions, modifier = Modifier.fillMaxWidth()) {
            ListItem(
                headlineContent = { Text(stringResource(R.string.settings_permissions)) },
                leadingContent = { Icon(Icons.Default.Security, null) },
                supportingContent = { Text(stringResource(R.string.settings_permissions_summary)) },
                trailingContent = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, null) },
                colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.surfaceContainerHighest),
            )
        }
        Text(stringResource(R.string.settings_data), style = MaterialTheme.typography.titleSmall)
        Card(onClick = onBackup, modifier = Modifier.fillMaxWidth()) {
            ListItem(
                headlineContent = { Text(stringResource(R.string.settings_folder_camera_backup)) },
                supportingContent = { Text(stringResource(R.string.settings_manage_automatic_uploads)) },
                leadingContent = { Icon(Icons.Default.Upload, null) },
                trailingContent = {
                    Icon(
                        Icons.AutoMirrored.Filled.KeyboardArrowRight,
                        contentDescription = stringResource(R.string.settings_open_backup_configuration),
                    )
                },
                colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.surfaceContainerHighest),
            )
        }
        Card(onClick = onOpenTemporary, modifier = Modifier.fillMaxWidth()) {
            ListItem(
                headlineContent = { Text(stringResource(R.string.settings_temporary_files)) },
                leadingContent = { Icon(Icons.Default.History, null) },
                supportingContent = { Text(stringResource(R.string.settings_temporary_copy_retention_description)) },
                trailingContent = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, null) },
                colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.surfaceContainerHighest),
            )
        }
        Text(stringResource(R.string.settings_troubleshooting), style = MaterialTheme.typography.titleSmall)
        DiagnosticsCard(state, diagnostics)
    }
}

@Composable
private fun AppLockMainCard() {
    val context = LocalContext.current
    val lock = remember(context) { AppLock(context) }
    var revision by remember { mutableIntStateOf(0) }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { revision++ }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { revision++ }
    val enabled = remember(revision) { lock.enabled }
    Card(modifier = Modifier.fillMaxWidth()) {
        ListItem(
            headlineContent = { Text(stringResource(R.string.settings_app_lock)) },
            supportingContent = { Text(stringResource(R.string.settings_app_lock_summary)) },
            leadingContent = { Icon(Icons.Default.Lock, null) },
            trailingContent = {
                Switch(
                    checked = enabled,
                    onCheckedChange = { turnOn ->
                        launcher.launch(
                            Intent()
                                .setClassName(context.packageName, AppLock.AUTH_ACTIVITY)
                                .setAction(if (turnOn) "enable-lock" else "disable-lock"),
                        )
                    },
                    enabled = lock.deviceSecure,
                )
            },
            colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.surfaceContainerHighest),
        )
    }
}

@Composable
internal fun SettingsChoice(
    description: String,
    current: String,
    options: List<String>,
    onSelect: (String) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    Box {
        FilledTonalButton(
            onClick = { expanded = true },
            shape = RoundedCornerShape(OpenCloudDimensions.SpacingMd),
            modifier = Modifier.semantics { contentDescription = description },
        ) {
            Text(current)
            Icon(Icons.Default.ArrowDropDown, null)
        }
        DropdownMenu(expanded, onDismissRequest = { expanded = false }) {
            options.forEach { option ->
                DropdownMenuItem(
                    text = { Text(option) },
                    onClick = {
                        expanded = false
                        onSelect(option)
                    },
                    leadingIcon = {
                        if (option == current) {
                            Icon(Icons.Default.Check, contentDescription = stringResource(R.string.settings_selected))
                        }
                    },
                    modifier = Modifier.semantics { selected = option == current },
                )
            }
        }
    }
}

@Composable
private fun DiagnosticsCard(
    state: UserSettings,
    diagnostics: SettingsDiagnostics,
) {
    val diagnosticsLabel = stringResource(R.string.settings_local_diagnostics)
    Card {
        ListItem(
            headlineContent = { Text(stringResource(R.string.settings_local_diagnostics)) },
            leadingContent = { Icon(Icons.Default.BugReport, null) },
            supportingContent = {
                Text(stringResource(R.string.settings_diagnostics_description, 100))
            },
            colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.surfaceContainerHighest),
            trailingContent = {
                Switch(
                    state.localDiagnosticsEnabled,
                    diagnostics.onSetEnabled,
                    Modifier.semantics { contentDescription = diagnosticsLabel },
                )
            },
        )
        if (state.localDiagnosticsEnabled) {
            TextButton(onClick = diagnostics.onRead) { Text(stringResource(R.string.settings_view_local_diagnostics)) }
        }
    }
}

internal fun Appearance.resourceId() =
    when (this) {
        Appearance.LIGHT -> R.string.settings_appearance_light
        Appearance.DARK -> R.string.settings_appearance_dark
        Appearance.SYSTEM -> R.string.settings_appearance_system
    }
