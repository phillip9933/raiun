package eu.opencloud.android.next.feature.files

import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel

@Composable
internal fun ScannerDestinationPicker(
    accountId: String,
    spaceId: String,
    path: String,
    onChoose: (spaceId: String, path: String) -> Unit,
    onDismiss: () -> Unit,
) {
    ScannerDestinationPickerRoute(ScannerDestinationRequest(accountId, spaceId, path), onChoose, onDismiss)
}

private data class ScannerDestinationRequest(
    val account: String,
    val space: String,
    val path: String,
)

@Composable
private fun ScannerDestinationPickerRoute(
    request: ScannerDestinationRequest,
    onChoose: (String, String) -> Unit,
    onDismiss: () -> Unit,
    model: ScannerDestinationPickerViewModel = viewModel(key = "scanner-destination-${request.account}"),
) {
    val state by model.state.collectAsStateWithLifecycle()
    LaunchedEffect(request) { model.load(request.account, request.space, request.path) }
    DisposableEffect(model) { onDispose { model.stop() } }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        ScannerDestinationScreen(
            state = state,
            actions =
                ScannerDestinationActions(
                    onDismiss,
                    { state.spaceId?.let { onChoose(it, state.path) } },
                    model::showSpaces,
                    model::chooseSpace,
                    model::openBreadcrumb,
                    model::openFolder,
                    model::up,
                    model::retry,
                ),
        )
    }
}
