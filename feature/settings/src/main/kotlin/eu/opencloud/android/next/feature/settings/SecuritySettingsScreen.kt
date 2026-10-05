package eu.opencloud.android.next.feature.settings

import android.content.Intent
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.security.AppLock

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecuritySettingsScreen(
    onNavigateBack: () -> Unit,
    modifier: Modifier = Modifier,
    accountId: String? = null,
) {
    BackHandler(onBack = onNavigateBack)
    val context = LocalContext.current
    val lock = remember(context, accountId) { AppLock(context) }
    var revision by remember { mutableIntStateOf(0) }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { revision++ }
    androidx.lifecycle.compose.LifecycleEventEffect(androidx.lifecycle.Lifecycle.Event.ON_RESUME) { revision++ }
    val enabled = remember(revision) { lock.enabled }
    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.settings_app_lock)) },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.settings_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier.padding(padding).verticalScroll(rememberScrollState()).padding(OpenCloudDimensions.SpacingMd),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingMd),
        ) {
            AppLockSettingsCard(lock, enabled, onAuthenticate = { launcher.launch(it) }, onChange = { revision++ })
        }
    }
}

@Composable
private fun AppLockSettingsCard(
    lock: AppLock,
    enabled: Boolean,
    onAuthenticate: (Intent) -> Unit,
    onChange: () -> Unit,
) {
    val context = LocalContext.current
    val lockDelayOptions = LockDelayOptions()
    val currentLockDelay =
        lockDelayOptions.firstOrNull { it.first == lock.timeoutMinutes }?.second
            ?: pluralStringResource(R.plurals.settings_lock_delay_minutes, lock.timeoutMinutes, lock.timeoutMinutes)
    Card {
        ListItem(
            colors =
                ListItemDefaults.colors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainerHighest,
                ),
            headlineContent = { Text(stringResource(R.string.settings_app_lock)) },
            supportingContent = {
                Text(
                    if (lock.deviceSecure) {
                        stringResource(R.string.settings_app_lock_summary)
                    } else {
                        stringResource(R.string.settings_app_lock_setup_device)
                    },
                )
            },
            trailingContent = {
                Switch(
                    enabled,
                    onCheckedChange = { value ->
                        onAuthenticate(
                            Intent()
                                .setClassName(context.packageName, AppLock.AUTH_ACTIVITY)
                                .setAction(if (value) "enable-lock" else "disable-lock"),
                        )
                    },
                    enabled = lock.deviceSecure,
                )
            },
        )
        if (enabled) {
            ListItem(
                colors =
                    ListItemDefaults.colors(
                        containerColor = MaterialTheme.colorScheme.surfaceContainerHighest,
                    ),
                headlineContent = { Text(stringResource(R.string.settings_biometric_unlock)) },
                supportingContent = {
                    Text(
                        if (lock.biometricAvailable) {
                            stringResource(R.string.settings_biometric_description_available)
                        } else {
                            stringResource(R.string.settings_biometric_description_unavailable)
                        },
                    )
                },
                trailingContent = {
                    Switch(
                        lock.biometricEnabled,
                        {
                            lock.setBiometricEnabled(it)
                            onChange()
                        },
                        enabled = lock.biometricAvailable || lock.biometricEnabled,
                    )
                },
            )
            ListItem(
                colors =
                    ListItemDefaults.colors(
                        containerColor = MaterialTheme.colorScheme.surfaceContainerHighest,
                    ),
                headlineContent = { Text(stringResource(R.string.settings_lock_after_leaving)) },
                supportingContent = {
                    Text(stringResource(R.string.settings_lock_after_leaving_description))
                },
                trailingContent = {
                    SettingsChoice(
                        stringResource(R.string.settings_change_lock_delay),
                        currentLockDelay,
                        lockDelayOptions.map { it.second },
                    ) { label ->
                        lock.setTimeout(lockDelayOptions.first { it.second == label }.first)
                        onChange()
                    }
                },
            )
            ListItem(
                colors =
                    ListItemDefaults.colors(
                        containerColor = MaterialTheme.colorScheme.surfaceContainerHighest,
                    ),
                headlineContent = { Text(stringResource(R.string.settings_protect_other_apps)) },
                supportingContent = {
                    Text(stringResource(R.string.settings_protect_other_apps_description))
                },
                trailingContent = {
                    Switch(
                        lock.protectDocuments,
                        {
                            lock.setProtectDocuments(it)
                            onChange()
                        },
                    )
                },
            )
            TextButton(
                onClick = {
                    onAuthenticate(Intent().setClassName(context.packageName, AppLock.AUTH_ACTIVITY))
                },
            ) { Text(stringResource(R.string.settings_unlock_file_picker)) }
        }
    }
}

@Composable
private fun LockDelayOptions() =
    listOf(
        0 to stringResource(R.string.settings_lock_delay_immediately),
        1 to pluralStringResource(R.plurals.settings_lock_delay_minutes, 1, 1),
        5 to pluralStringResource(R.plurals.settings_lock_delay_minutes, 5, 5),
        30 to pluralStringResource(R.plurals.settings_lock_delay_minutes, 30, 30),
    )
