package eu.opencloud.android.next.core.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.res.stringResource
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
@Suppress("TooGenericExceptionCaught") // Queue preparation errors remain visible.
fun FolderDownloadDialog(
    name: String,
    onClose: () -> Unit,
    enqueue: suspend (suspend (Int) -> Unit) -> Int,
) {
    val scope = rememberCoroutineScope()
    var pending by remember { mutableStateOf<Job?>(null) }
    var started by remember { mutableStateOf(false) }
    var done by remember { mutableStateOf(false) }
    var failed by remember { mutableStateOf(false) }
    var count by remember { mutableIntStateOf(0) }
    AlertDialog(onDismissRequest = {
        pending?.cancel()
        onClose()
    }, title = { Text(name) }, text = {
        Column {
            Text(stringResource(R.string.folder_download_explanation))
            if (started) Text(stringResource(R.string.folder_download_count, count))
            if (started && !done) LinearProgressIndicator()
            if (failed) Text(stringResource(R.string.folder_download_failed))
        }
    }, confirmButton = {
        Button(enabled = !started || done, onClick = {
            if (done) {
                onClose()
            } else {
                started = true
                pending =
                    scope.launch {
                        try {
                            withContext(Dispatchers.IO) {
                                enqueue { value -> withContext(Dispatchers.Main) { count = value } }
                            }
                        } catch (
                            cancelled: CancellationException,
                        ) {
                            throw cancelled
                        } catch (_: Exception) {
                            failed = true
                        } finally {
                            done = true
                        }
                    }
            }
        }) { Text(stringResource(if (done) R.string.folder_shortcut_close else R.string.folder_download)) }
    }, dismissButton = {
        if (!done) {
            TextButton(onClick = {
                pending?.cancel()
                onClose()
            }) {
                Text(stringResource(R.string.folder_shortcut_cancel))
            }
        }
    })
}
