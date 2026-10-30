package eu.opencloud.android.next.feature.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.Card
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.security.WifiRouteStatus

@Composable
internal fun WifiConnectionCard(
    state: ConnectionViewState,
    actions: ConnectionViewActions,
) {
    var showHelp by rememberSaveable { mutableStateOf(false) }
    val enabled = !state.loading && !state.loadFailed && !state.busy && !state.testing
    val switchLabel = stringResource(R.string.connection_wifi_enabled)
    Card(Modifier.fillMaxWidth()) {
        ListItem(
            headlineContent = { Text(stringResource(R.string.connection_wifi_title)) },
            supportingContent = { Text(stringResource(R.string.connection_wifi_summary)) },
            leadingContent = { Icon(Icons.Default.Wifi, null) },
            trailingContent = {
                Switch(
                    checked = state.enabled,
                    onCheckedChange = actions.onEnabledChange,
                    enabled = enabled,
                    modifier = Modifier.semantics { contentDescription = switchLabel },
                )
            },
            colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.surfaceContainerHighest),
        )
        Column(
            Modifier.padding(horizontal = OpenCloudDimensions.SpacingMd, vertical = OpenCloudDimensions.SpacingXs),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
        ) {
            if (state.enabled) WifiConnectionFields(state, actions)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    stringResource(
                        R.string.connection_status,
                        state.status?.toDisplayString() ?: stringResource(R.string.connection_status_disabled),
                    ),
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.bodySmall,
                )
                IconButton(onClick = { showHelp = true }) {
                    Icon(Icons.Default.Info, stringResource(R.string.connection_wifi_help))
                }
            }
            Text(stringResource(R.string.connection_test_note), style = MaterialTheme.typography.bodySmall)
            FilledTonalButton(enabled = enabled, onClick = actions.onTest) {
                Text(stringResource(if (state.testing) R.string.connection_test_running else R.string.connection_test))
            }
            state.testResult?.let { ok ->
                Text(stringResource(if (ok) R.string.connection_test_success else R.string.connection_test_failed))
            }
        }
    }
    if (showHelp) {
        ConnectionHelpDialog(
            title = stringResource(R.string.connection_wifi_title),
            body =
                listOf(
                    stringResource(R.string.connection_mode_help),
                    stringResource(R.string.connection_location_explanation),
                    stringResource(R.string.connection_local_tls_note),
                ).joinToString("\n\n"),
            onDismiss = { showHelp = false },
        )
    }
}

@Composable
private fun WifiConnectionFields(
    state: ConnectionViewState,
    actions: ConnectionViewActions,
) {
    val enabled = !state.loading && !state.busy && !state.testing && !state.loadFailed
    Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm)) {
        OutlinedTextField(
            value = state.localAddress,
            onValueChange = actions.onLocalAddressChange,
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.connection_local)) },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
            singleLine = true,
            enabled = enabled,
        )
        OutlinedTextField(
            value = state.ssid,
            onValueChange = actions.onSsidChange,
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.connection_ssid)) },
            singleLine = true,
            enabled = enabled,
        )
        FilledTonalButton(onClick = actions.onCurrentWifi, enabled = enabled) {
            Text(stringResource(R.string.connection_current_wifi))
        }
        Text(stringResource(R.string.connection_mode), style = MaterialTheme.typography.titleSmall)
        Column {
            ConnectionMode.entries.forEach { item ->
                Row(
                    Modifier
                        .fillMaxWidth()
                        .selectable(
                            selected = state.mode == item,
                            enabled = enabled,
                            role = Role.RadioButton,
                            onClick = { actions.onModeChange(item) },
                        ).padding(vertical = OpenCloudDimensions.SpacingXs),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
                ) {
                    RadioButton(selected = state.mode == item, onClick = null, enabled = enabled)
                    val label =
                        when (item) {
                            ConnectionMode.PUBLIC -> R.string.connection_mode_public
                            ConnectionMode.AUTOMATIC -> R.string.connection_mode_automatic
                        }
                    Text(stringResource(label))
                }
            }
        }
    }
}

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
