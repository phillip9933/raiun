package eu.opencloud.android.next.feature.settings

import android.app.Application
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import io.github.phillip9933.appupdater.AndroidUpdateChannel
import io.github.phillip9933.appupdater.UpdateError
import io.github.phillip9933.appupdater.UpdateManager
import io.github.phillip9933.appupdater.UpdateState
import kotlinx.coroutines.launch

class AppUpdatesViewModel(
    application: Application,
    val manager: UpdateManager,
) : AndroidViewModel(application) {
    constructor(application: Application) : this(application, RaiunUpdates.get(application))

    val state = manager.state

    fun check() {
        viewModelScope.launch { manager.checkNow() }
    }

    fun checkWhenDue() {
        viewModelScope.launch { manager.checkNow(force = false) }
    }

    fun download() {
        viewModelScope.launch { manager.download() }
    }

    fun channel(value: AndroidUpdateChannel) {
        manager.setChannel(value)
        check()
    }
}

@Composable
fun AppUpdatesRoute(
    onNavigateBack: () -> Unit,
    model: AppUpdatesViewModel = viewModel(),
) {
    val context = LocalContext.current
    val state by model.state.collectAsState()
    AppUpdatesScreen(
        state = state,
        onNavigateBack = onNavigateBack,
        actions =
            UpdateActions(
                onCheck = model::check,
                onDownload = model::download,
                onCancel = model.manager::cancelDownload,
                onAutomatic = model.manager::setAutomaticChecks,
                onWifi = model.manager::setWifiDownload,
                onChannel = model::channel,
                onOpenLink = { url ->
                    try {
                        context.startActivity(
                            Intent(Intent.ACTION_VIEW, Uri.parse(url)).addCategory(Intent.CATEGORY_BROWSABLE),
                        )
                    } catch (_: ActivityNotFoundException) {
                        // The updater remains usable when no browser is installed.
                    } catch (_: SecurityException) {
                        // A device policy may block external browsing.
                    }
                },
            ),
        installControl = { UpdateInstallButton(model.manager) },
    )
}

/** All presentation inputs are explicit so settings can be tested without contacting GitHub. */
data class UpdateActions(
    val onCheck: () -> Unit = {},
    val onDownload: () -> Unit = {},
    val onCancel: () -> Unit = {},
    val onAutomatic: (Boolean) -> Unit = {},
    val onWifi: (Boolean) -> Unit = {},
    val onChannel: (AndroidUpdateChannel) -> Unit = {},
    val onOpenLink: (String) -> Unit = {},
)

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun AppUpdatesScreen(
    state: UpdateState,
    onNavigateBack: () -> Unit,
    actions: UpdateActions,
    modifier: Modifier = Modifier,
    installControl: @Composable () -> Unit = {},
) {
    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.updates_title)) },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.updates_back))
                    }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier.padding(padding).verticalScroll(rememberScrollState()).padding(OpenCloudDimensions.SpacingMd),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingMd),
        ) {
            Text(stringResource(R.string.updates_installed, state.installedVersion))
            Text(stringResource(R.string.updates_about), style = MaterialTheme.typography.bodyMedium)
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs),
                verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs),
            ) {
                TextButton(onClick = { actions.onOpenLink(RaiunUpdates.PROJECT_URL) }) {
                    Text(stringResource(R.string.updates_project_link))
                }
                RaiunUpdates.installedReleaseUrl(state.installedVersion)?.let { url ->
                    TextButton(onClick = { actions.onOpenLink(url) }) {
                        Text(stringResource(R.string.updates_installed_release_link))
                    }
                }
            }
            val automaticLabel = stringResource(R.string.updates_automatic)
            val wifiLabel = stringResource(R.string.updates_wifi)
            Card(Modifier.fillMaxWidth()) {
                ListItem(
                    headlineContent = { Text(automaticLabel) },
                    supportingContent = { Text(stringResource(R.string.updates_automatic_summary)) },
                    trailingContent = {
                        Switch(
                            state.automaticChecks,
                            actions.onAutomatic,
                            Modifier.semantics {
                                contentDescription =
                                    automaticLabel
                            },
                        )
                    },
                )
                ListItem(
                    headlineContent = { Text(wifiLabel) },
                    supportingContent = { Text(stringResource(R.string.updates_wifi_summary)) },
                    trailingContent = {
                        Switch(
                            state.wifiDownload,
                            actions.onWifi,
                            Modifier.semantics {
                                contentDescription =
                                    wifiLabel
                            },
                        )
                    },
                )
            }
            Text(stringResource(R.string.updates_channel), style = MaterialTheme.typography.titleSmall)
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs),
                verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs),
            ) {
                FilterChip(
                    selected = state.channel == AndroidUpdateChannel.STABLE,
                    onClick = { actions.onChannel(AndroidUpdateChannel.STABLE) },
                    label = { Text(stringResource(R.string.updates_stable)) },
                )
                FilterChip(
                    selected = state.channel == AndroidUpdateChannel.BETA,
                    onClick = { actions.onChannel(AndroidUpdateChannel.BETA) },
                    label = { Text(stringResource(R.string.updates_beta)) },
                )
            }
            if (state.channel == AndroidUpdateChannel.BETA) Text(stringResource(R.string.updates_beta_warning))
            OutlinedButton(onClick = actions.onCheck, enabled = !state.checking && !state.downloading) {
                Text(stringResource(if (state.checking) R.string.updates_checking else R.string.updates_check))
            }
            UpdateStatus(state)
            if (state.available != null) {
                UpdateReleaseContents(state)
                UpdatePrimaryAction(state, actions.onDownload, actions.onCancel, installControl)
                Text(stringResource(R.string.updates_install_info), style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

/** Foreground-only offer; Android's installer is never opened by a background worker. */
@Composable
fun AppUpdateNotice(model: AppUpdatesViewModel = viewModel()) {
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) { model.checkWhenDue() }
    val state by model.state.collectAsState()
    AppUpdateNoticeDialog(
        state = state,
        onDismiss = model.manager::dismissOffer,
        onDownload = model::download,
        onCancel = model.manager::cancelDownload,
        installControl = { UpdateInstallButton(model.manager) },
    )
}

/** Presentation preserves the updater engine's persistent offer/dismissal policy. */
@Composable
fun AppUpdateNoticeDialog(
    state: UpdateState,
    onDismiss: () -> Unit,
    onDownload: () -> Unit,
    onCancel: () -> Unit,
    installControl: @Composable () -> Unit,
) {
    if (!state.offer || state.available == null) return
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.updates_new_version_title)) },
        text = {
            Column(
                Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
            ) {
                UpdateStatus(state)
                UpdateReleaseContents(state)
                Text(stringResource(R.string.updates_install_info), style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = {
            UpdatePrimaryAction(state, onDownload, onCancel, installControl)
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.updates_later)) }
        },
    )
}

@Composable
private fun UpdateStatus(state: UpdateState) {
    Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs)) {
        state.error?.let { Text(stringResource(updateErrorText(it)), color = MaterialTheme.colorScheme.error) }
        if (state.available == null && !state.checking && state.error == null) {
            Text(stringResource(if (state.lastChecked > 0) R.string.updates_current else R.string.updates_unchecked))
        }
        if (state.ready) Text(stringResource(R.string.updates_ready))
    }
}

@Composable
private fun UpdateReleaseContents(state: UpdateState) {
    val release = state.available ?: return
    Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm)) {
        Text(stringResource(R.string.updates_available, release.tag.removePrefix("android-v").removePrefix("v")))
        if (state.downloading) {
            val progress =
                (
                    state.bytesDownloaded.toDouble() /
                        release.sizeBytes.coerceAtLeast(
                            1,
                        )
                ).coerceIn(0.0, 1.0).toFloat()
            LinearProgressIndicator(progress = { progress }, modifier = Modifier.fillMaxWidth())
            Text(stringResource(R.string.updates_downloading, (progress * 100).toInt()))
        }
        Text(stringResource(R.string.updates_notes), style = MaterialTheme.typography.titleSmall)
        // Render untrusted release notes as plain text without remote content.
        Text(release.notes.ifBlank { stringResource(R.string.updates_no_notes) })
    }
}

@Composable
private fun UpdatePrimaryAction(
    state: UpdateState,
    onDownload: () -> Unit,
    onCancel: () -> Unit,
    installControl: @Composable () -> Unit,
) {
    when {
        state.downloading -> OutlinedButton(onClick = onCancel) { Text(stringResource(R.string.updates_cancel)) }
        state.ready -> installControl()
        else ->
            Button(
                onClick = onDownload,
                enabled = !state.checking,
            ) { Text(stringResource(R.string.updates_download)) }
    }
}

@Composable
private fun UpdateInstallButton(manager: UpdateManager) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<Int?>(null) }
    val installer =
        rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            // Returning from the installer does not establish that installation succeeded.
            busy = false
        }
    val install = {
        scope.launch {
            busy = true
            error = null
            try {
                manager.prepareInstall()?.let { installer.launch(it) }
            } catch (_: ActivityNotFoundException) {
                error = R.string.updates_installer_error
            } catch (_: SecurityException) {
                error = R.string.updates_installer_error
            } finally {
                busy = false
            }
        }
        Unit
    }
    val permission =
        rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            if (context.packageManager.canRequestPackageInstalls()) {
                install()
            } else {
                error =
                    R.string.updates_permission_error
            }
        }
    Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs)) {
        Button(
            enabled = !busy,
            onClick = {
                if (context.packageManager.canRequestPackageInstalls()) {
                    install()
                } else {
                    try {
                        permission.launch(
                            Intent(
                                Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                                Uri.parse("package:${context.packageName}"),
                            ),
                        )
                    } catch (_: ActivityNotFoundException) {
                        error = R.string.updates_installer_error
                    } catch (_: SecurityException) {
                        error = R.string.updates_permission_error
                    }
                }
            },
        ) { Text(stringResource(if (busy) R.string.updates_installing else R.string.updates_install)) }
        error?.let { Text(stringResource(it), color = MaterialTheme.colorScheme.error) }
    }
}

internal fun updateErrorText(error: UpdateError): Int =
    when (error) {
        UpdateError.NETWORK -> R.string.updates_network_error
        UpdateError.INVALID_RELEASE, UpdateError.INVALID_APK -> R.string.updates_invalid_error
        UpdateError.DOWNLOAD_FAILED -> R.string.updates_download_error
        UpdateError.SIZE_MISMATCH, UpdateError.HASH_MISMATCH -> R.string.updates_integrity_error
        UpdateError.WRONG_PACKAGE -> R.string.updates_package_error
        UpdateError.DEBUG_APK -> R.string.updates_debug_error
        UpdateError.INCOMPATIBLE_SDK -> R.string.updates_android_error
        UpdateError.OLD_VERSION -> R.string.updates_old_error
        UpdateError.VERSION_MISMATCH -> R.string.updates_version_error
        UpdateError.SIGNATURE_MISMATCH -> R.string.updates_signature_error
        UpdateError.STORAGE -> R.string.updates_storage_error
        UpdateError.CANCELLED -> R.string.updates_cancelled
    }
