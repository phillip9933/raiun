package eu.opencloud.android.next.core.ui

import android.content.Intent
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

data class PreparedExternalFile(
    val intent: Intent,
    val onOpened: () -> Unit = {},
)

/** Downloads are owned by the transfer queue; navigation cancels only the pending external launch. */
@Composable
@Suppress("TooGenericExceptionCaught") // The caller presents preparation and Android launch failures.
fun rememberExternalFileLauncher(onError: (Exception) -> Unit): (suspend () -> PreparedExternalFile) -> Unit {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val currentError by rememberUpdatedState(onError)
    var opening by remember { mutableStateOf(false) }
    return launch@{ prepare ->
        if (opening) return@launch
        opening = true
        scope.launch {
            try {
                val prepared = prepare()
                context.startActivity(prepared.intent)
                prepared.onOpened()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Exception) {
                currentError(failure)
            } finally {
                opening = false
            }
        }
    }
}

fun externalFileChooser(intent: Intent): Intent =
    Intent.createChooser(intent, null).apply {
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        clipData = intent.clipData
    }
