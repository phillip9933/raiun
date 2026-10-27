package eu.opencloud.android.next.feature.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.security.WifiRouteStatus

internal enum class ConnectionMode { PUBLIC, AUTOMATIC }

internal data class ConnectionViewState(
    val serverUrl: String,
    val enabled: Boolean,
    val localAddress: String,
    val ssid: String,
    val mode: ConnectionMode,
    val status: WifiRouteStatus?,
    val testing: Boolean,
    val testResult: Boolean?,
    val busy: Boolean,
    val loading: Boolean,
    val loadFailed: Boolean,
    val origins: String,
    val certificateSelected: Boolean,
    val canRemoveCertificate: Boolean,
    val removingCertificate: Boolean,
)

internal data class ConnectionViewActions(
    val onEnabledChange: (Boolean) -> Unit,
    val onLocalAddressChange: (String) -> Unit,
    val onSsidChange: (String) -> Unit,
    val onModeChange: (ConnectionMode) -> Unit,
    val onCurrentWifi: () -> Unit,
    val onTest: () -> Unit,
    val onOriginsChange: (String) -> Unit,
    val onChooseCertificate: () -> Unit,
    val onRemoveCertificate: () -> Unit,
    val onCancelRemoval: () -> Unit,
    val onCancel: () -> Unit,
    val onSave: () -> Unit,
)

@Composable
internal fun ConnectionScreenContent(
    state: ConnectionViewState,
    actions: ConnectionViewActions,
    onNavigateBack: () -> Unit,
    snackbarHostState: SnackbarHostState,
) {
    ConnectionSettingsLayout(
        onNavigateBack = onNavigateBack,
        snackbarHostState = snackbarHostState,
        wifiCard = {
            WifiConnectionCard(state, actions)
        },
        certificateCard = {
            ClientCertificateCard(state, actions)
        },
        actions = {
            ConnectionSaveActions(state, actions)
        },
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun ConnectionSettingsLayout(
    onNavigateBack: () -> Unit,
    snackbarHostState: SnackbarHostState,
    wifiCard: @Composable () -> Unit,
    certificateCard: @Composable () -> Unit,
    actions: @Composable () -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.connection_title)) },
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
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { insets ->
        Column(
            Modifier
                .padding(insets)
                .verticalScroll(rememberScrollState())
                .padding(OpenCloudDimensions.SpacingMd),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingMd),
        ) {
            wifiCard()
            certificateCard()
            actions()
        }
    }
}

@Composable
internal fun WifiConnectionCard(
    state: ConnectionViewState,
    actions: ConnectionViewActions,
) {
    Card {
        Column(
            Modifier.padding(OpenCloudDimensions.SpacingMd),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
        ) {
            Text(stringResource(R.string.connection_wifi_title), style = MaterialTheme.typography.titleMedium)
            Text(stringResource(R.string.connection_wifi_summary), style = MaterialTheme.typography.bodyMedium)
            Text(stringResource(R.string.connection_server_scope), style = MaterialTheme.typography.bodySmall)
            Text(stringResource(R.string.connection_canonical), style = MaterialTheme.typography.labelMedium)
            Text(state.serverUrl, style = MaterialTheme.typography.bodyMedium)
            if (state.loadFailed) {
                Text(
                    stringResource(R.string.connection_invalid),
                    color = MaterialTheme.colorScheme.error,
                )
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.connection_wifi_enabled), Modifier.weight(1f))
                Switch(checked = state.enabled, onCheckedChange = actions.onEnabledChange)
            }
            OutlinedTextField(
                value = state.localAddress,
                onValueChange = actions.onLocalAddressChange,
                modifier = Modifier.fillMaxWidth(),
                label = { Text(stringResource(R.string.connection_local)) },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                singleLine = true,
            )
            OutlinedTextField(
                value = state.ssid,
                onValueChange = actions.onSsidChange,
                modifier = Modifier.fillMaxWidth(),
                label = { Text(stringResource(R.string.connection_ssid)) },
                singleLine = true,
            )
            Text(stringResource(R.string.connection_location_explanation), style = MaterialTheme.typography.bodySmall)
            OutlinedButton(onClick = actions.onCurrentWifi) { Text(stringResource(R.string.connection_current_wifi)) }
            Text(
                stringResource(
                    R.string.connection_status,
                    state.status?.toDisplayString() ?: stringResource(R.string.connection_status_disabled),
                ),
                style = MaterialTheme.typography.bodyMedium,
            )
            HorizontalDivider()
            Text(stringResource(R.string.connection_mode), style = MaterialTheme.typography.titleSmall)
            ConnectionMode.entries.forEach { item ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(selected = state.mode == item, onClick = { actions.onModeChange(item) })
                    Text(item.toDisplayString())
                }
            }
            Text(stringResource(R.string.connection_mode_help), style = MaterialTheme.typography.bodySmall)
            Text(stringResource(R.string.connection_local_tls_note), style = MaterialTheme.typography.bodySmall)
            Text(stringResource(R.string.connection_test_note), style = MaterialTheme.typography.bodySmall)
            OutlinedButton(enabled = !state.testing && !state.busy && !state.loadFailed, onClick = actions.onTest) {
                Text(stringResource(if (state.testing) R.string.connection_test_running else R.string.connection_test))
            }
            state.testResult?.let { ok ->
                Text(stringResource(if (ok) R.string.connection_test_success else R.string.connection_test_failed))
            }
        }
    }
}

@Composable
internal fun ClientCertificateCard(
    state: ConnectionViewState,
    actions: ConnectionViewActions,
) {
    Card {
        Column(
            Modifier.padding(OpenCloudDimensions.SpacingMd),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
        ) {
            Text(stringResource(R.string.connection_cert_title), style = MaterialTheme.typography.titleMedium)
            Text(stringResource(R.string.connection_cert_summary), style = MaterialTheme.typography.bodyMedium)
            OutlinedTextField(
                value = state.origins,
                onValueChange = actions.onOriginsChange,
                modifier = Modifier.fillMaxWidth(),
                label = { Text(stringResource(R.string.connection_cert_origins)) },
                minLines = 2,
            )
            Text(
                stringResource(
                    if (state.certificateSelected) R.string.connection_cert_selected else R.string.connection_cert_none,
                ),
                style = MaterialTheme.typography.bodySmall,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm)) {
                OutlinedButton(enabled = state.origins.isNotBlank(), onClick = actions.onChooseCertificate) {
                    Text(stringResource(R.string.connection_cert_select))
                }
                if (state.canRemoveCertificate && !state.removingCertificate) {
                    TextButton(
                        onClick = actions.onRemoveCertificate,
                    ) { Text(stringResource(R.string.connection_cert_remove)) }
                }
                if (state.removingCertificate) {
                    TextButton(onClick = actions.onCancelRemoval) { Text(stringResource(R.string.connection_cancel)) }
                }
            }
            Text(stringResource(R.string.connection_cert_note), style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
internal fun ConnectionSaveActions(
    state: ConnectionViewState,
    actions: ConnectionViewActions,
) {
    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm, Alignment.End),
    ) {
        TextButton(onClick = actions.onCancel, enabled = !state.busy && !state.testing) {
            Text(stringResource(R.string.connection_cancel))
        }
        Button(
            enabled = !state.busy && !state.testing && !state.loading && !state.loadFailed,
            onClick = actions.onSave,
        ) {
            Text(stringResource(R.string.connection_save))
        }
    }
}

@Composable
private fun ConnectionMode.toDisplayString(): String =
    stringResource(
        when (this) {
            ConnectionMode.PUBLIC -> R.string.connection_mode_public
            ConnectionMode.AUTOMATIC -> R.string.connection_mode_automatic
        },
    )

@Composable
private fun WifiRouteStatus.toDisplayString(): String =
    stringResource(
        when (this) {
            WifiRouteStatus.DISABLED -> R.string.connection_status_disabled
            WifiRouteStatus.LOCATION_UNAVAILABLE -> R.string.connection_status_location
            WifiRouteStatus.NOT_WIFI -> R.string.connection_status_not_wifi
            WifiRouteStatus.SSID_UNAVAILABLE -> R.string.connection_status_ssid
            WifiRouteStatus.SSID_MISMATCH -> R.string.connection_status_mismatch
            WifiRouteStatus.ACTIVE -> R.string.connection_status_active
        },
    )
