package eu.opencloud.android.next.feature.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.designsystem.component.HorizontalDivider
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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun ConnectionScreenContent(
    state: ConnectionViewState,
    actions: ConnectionViewActions,
    onNavigateBack: () -> Unit,
    snackbarHostState: SnackbarHostState,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.connection_title)) },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.settings_back))
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
        bottomBar = {
            Surface {
                Column(Modifier.navigationBarsPadding().imePadding()) {
                    HorizontalDivider()
                    ConnectionSaveActions(state, actions)
                }
            }
        },
    ) { insets ->
        Column(
            Modifier
                .padding(insets)
                .verticalScroll(rememberScrollState())
                .padding(OpenCloudDimensions.SpacingMd),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingMd),
        ) {
            Card(Modifier.fillMaxWidth()) {
                Column(
                    Modifier.padding(OpenCloudDimensions.SpacingMd),
                    verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs),
                ) {
                    Text(
                        stringResource(R.string.connection_server_heading),
                        style = MaterialTheme.typography.labelMedium,
                    )
                    Text(state.serverUrl, style = MaterialTheme.typography.bodyMedium)
                    Text(stringResource(R.string.connection_server_scope), style = MaterialTheme.typography.bodySmall)
                    if (state.loadFailed) {
                        Text(stringResource(R.string.connection_invalid), color = MaterialTheme.colorScheme.error)
                    }
                }
            }
            WifiConnectionCard(state, actions)
            ClientCertificateCard(state, actions)
        }
    }
}

@Composable
internal fun ConnectionSaveActions(
    state: ConnectionViewState,
    actions: ConnectionViewActions,
) {
    Row(
        Modifier.fillMaxWidth().padding(OpenCloudDimensions.SpacingMd),
        horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
    ) {
        FilledTonalButton(
            onClick = actions.onCancel,
            enabled = !state.busy && !state.testing,
            modifier = Modifier.weight(1f),
        ) { Text(stringResource(R.string.connection_cancel)) }
        Button(
            enabled = !state.busy && !state.testing && !state.loading && !state.loadFailed,
            onClick = actions.onSave,
            modifier = Modifier.weight(1f),
        ) { Text(stringResource(R.string.connection_save)) }
    }
}

@Composable
internal fun ConnectionHelpDialog(
    title: String,
    body: String,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { Text(body, Modifier.verticalScroll(rememberScrollState())) },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.connection_help_done)) }
        },
    )
}
