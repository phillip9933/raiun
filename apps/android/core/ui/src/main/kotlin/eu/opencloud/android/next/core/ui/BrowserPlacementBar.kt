package eu.opencloud.android.next.core.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions

/** Shared destination-selection controls for ordinary and encrypted browsers. */

@Composable
fun BrowserPlacementBar(
    sourceSummary: String,
    state: BrowserPlacementBarState,
    onPlace: () -> Unit,
    onCancel: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier, verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm)) {
        Text(sourceSummary)
        Row(horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm)) {
            Button(onClick = onPlace, enabled = !state.busy && state.enabled) {
                Text(stringResource(state.actionLabel))
            }
            if (state.showCancel) {
                OutlinedButton(onClick = onCancel, enabled = !state.busy) {
                    Text(stringResource(state.cancelLabel))
                }
            }
        }
    }
}
