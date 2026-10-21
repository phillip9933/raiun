package eu.opencloud.android.next.feature.files

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.res.stringResource
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

@Composable
internal fun rememberScannerLocationPicker(
    state: ScannerState,
    model: ScannerViewModel,
): () -> Unit {
    var chooseLocation by remember { mutableStateOf(false) }
    var changingLocation by remember { mutableStateOf(false) }
    var locationError by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val location = state.location
    if (chooseLocation && location != null) {
        ScannerDestinationPicker(
            accountId = location.accountId,
            spaceId = location.spaceId,
            path = location.parentPath,
            onChoose = { space, path ->
                if (!changingLocation) {
                    changingLocation = true
                    scope.launch {
                        try {
                            model.changeLocation(space, path)
                            chooseLocation = false
                        } catch (cancelled: CancellationException) {
                            throw cancelled
                        } catch (_: Exception) {
                            locationError = true
                        } finally {
                            changingLocation = false
                        }
                    }
                }
            },
            onDismiss = { if (!changingLocation) chooseLocation = false },
        )
    }
    if (locationError) {
        AlertDialog(
            onDismissRequest = { locationError = false },
            text = { Text(stringResource(R.string.scanner_location_failed)) },
            confirmButton = {
                TextButton(onClick = { locationError = false }) { Text(stringResource(R.string.scanner_location_ok)) }
            },
        )
    }
    return { if (!changingLocation) chooseLocation = true }
}
