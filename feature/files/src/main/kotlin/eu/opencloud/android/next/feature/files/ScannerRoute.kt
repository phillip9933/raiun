package eu.opencloud.android.next.feature.files

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import dev.offlinescan.core.ScanResult
import dev.offlinescan.ui.ScannerFlow
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions

@Composable
internal fun ScannerRoute(
    target: List<String>,
    onClose: () -> Unit,
    model: ScannerViewModel = viewModel(key = "scan-${target[3]}"),
) {
    val state by model.state.collectAsStateWithLifecycle()
    var confirmDiscard by remember { mutableStateOf(false) }
    val openLocation = rememberScannerLocationPicker(state, model)
    LaunchedEffect(target) { model.start(target[0], target[1], target[2]) }
    LaunchedEffect(state.done, onClose) { if (state.done) onClose() }
    Surface(Modifier.fillMaxSize()) {
        val output = state.outputDirectory
        if (output != null) {
            ScannerFlow(
                outputDirectory = output,
                saveDestination = { enabled ->
                    ScannerLocationButton(state.locationLabel, enabled, openLocation)
                },
                includeDiagnostics = false,
            ) { result ->
                when (result) {
                    is ScanResult.Completed -> model.completed(result.output)
                    ScanResult.Cancelled -> model.discard()
                    is ScanResult.Failed -> model.failed()
                }
            }
        } else {
            BackHandler { if (!state.busy) confirmDiscard = true }
            Column(
                Modifier.fillMaxSize().safeDrawingPadding().padding(OpenCloudDimensions.SpacingMd),
                verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingMd, Alignment.CenterVertically),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                if (state.busy) {
                    CircularProgressIndicator()
                    Text(stringResource(R.string.scanner_uploading))
                }
                if (state.failed) {
                    Text(stringResource(R.string.scanner_failed))
                    FilledTonalButton(onClick = model::retry) { Text(stringResource(R.string.scanner_retry)) }
                    TextButton(onClick = { confirmDiscard = true }) { Text(stringResource(R.string.scanner_discard)) }
                }
            }
        }
    }
    if (confirmDiscard) {
        AlertDialog(
            onDismissRequest = { confirmDiscard = false },
            title = { Text(stringResource(R.string.scanner_discard_title)) },
            text = { Text(stringResource(R.string.scanner_discard_body)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmDiscard = false
                    model.discard()
                }) {
                    Text(stringResource(R.string.scanner_discard))
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmDiscard = false }) { Text(stringResource(R.string.scanner_keep)) }
            },
        )
    }
}
