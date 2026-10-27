package eu.opencloud.android.next.feature.settings

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.sync.accountServerForConnectionSettings
import kotlinx.coroutines.CancellationException

@Composable
internal fun AccountServerConnectionScreen(
    accountId: String?,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    var server by remember(accountId) { mutableStateOf<String?>(null) }
    var loading by remember(accountId) { mutableStateOf(true) }
    LaunchedEffect(accountId) {
        try {
            server = accountId?.let { accountServerForConnectionSettings(context, it) }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: IllegalStateException) {
            server = null
        } finally {
            loading = false
        }
    }
    val loaded = server
    if (loaded != null) {
        ServerConnectionScreen(loaded, onBack)
    } else {
        BackHandler(onBack = onBack)
        Column {
            if (loading) CircularProgressIndicator() else Text(stringResource(R.string.connection_error))
            TextButton(onClick = onBack) { Text(stringResource(R.string.settings_back)) }
        }
    }
}
