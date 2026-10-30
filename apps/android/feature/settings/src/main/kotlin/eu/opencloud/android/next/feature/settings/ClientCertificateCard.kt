package eu.opencloud.android.next.feature.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.Card
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions

@Composable
internal fun ClientCertificateCard(
    state: ConnectionViewState,
    actions: ConnectionViewActions,
) {
    var expanded by rememberSaveable { mutableStateOf(false) }
    var showHelp by rememberSaveable { mutableStateOf(false) }
    Card(Modifier.fillMaxWidth()) {
        ListItem(
            headlineContent = { Text(stringResource(R.string.connection_cert_title)) },
            supportingContent = { Text(stringResource(R.string.connection_cert_summary)) },
            leadingContent = { Icon(Icons.Default.VpnKey, null) },
            trailingContent = {
                IconButton(onClick = { showHelp = true }) {
                    Icon(Icons.Default.Info, stringResource(R.string.connection_cert_help))
                }
            },
            colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.surfaceContainerHighest),
        )
        Column(
            Modifier.padding(horizontal = OpenCloudDimensions.SpacingMd, vertical = OpenCloudDimensions.SpacingSm),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
            ) {
                Text(
                    stringResource(
                        when {
                            state.removingCertificate -> R.string.connection_cert_removing
                            state.certificateSelected -> R.string.connection_cert_selected
                            else -> R.string.connection_cert_none
                        },
                    ),
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.bodyMedium,
                )
                FilledTonalButton(onClick = { expanded = !expanded }) {
                    Text(
                        stringResource(
                            if (expanded) R.string.connection_cert_hide else R.string.connection_cert_configure,
                        ),
                    )
                }
            }
            if (expanded) CertificateFields(state, actions)
        }
    }
    if (showHelp) {
        ConnectionHelpDialog(
            title = stringResource(R.string.connection_cert_title),
            body = stringResource(R.string.connection_cert_note),
            onDismiss = { showHelp = false },
        )
    }
}

@Composable
private fun CertificateFields(
    state: ConnectionViewState,
    actions: ConnectionViewActions,
) {
    val enabled = !state.loading && !state.busy && !state.testing && !state.loadFailed
    Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm)) {
        OutlinedTextField(
            value = state.origins,
            onValueChange = actions.onOriginsChange,
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.connection_cert_origins)) },
            supportingText = { Text(stringResource(R.string.connection_origins_help)) },
            minLines = 2,
            enabled = enabled,
        )
        FilledTonalButton(
            enabled = enabled && state.origins.isNotBlank(),
            onClick = actions.onChooseCertificate,
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(R.string.connection_cert_select)) }
        if (state.canRemoveCertificate) {
            OutlinedButton(
                enabled = enabled,
                onClick = if (state.removingCertificate) actions.onCancelRemoval else actions.onRemoveCertificate,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    stringResource(
                        if (state.removingCertificate) R.string.connection_undo else R.string.connection_cert_remove,
                    ),
                )
            }
        }
    }
}
