package eu.opencloud.android.next.ui

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.sync.FolderShortcutTarget
import eu.opencloud.android.next.core.sync.FolderShortcuts
import eu.opencloud.android.next.feature.files.R
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

// App entry boundary, account switch, and consumption callbacks.
@Suppress("LongParameterList", "TooGenericExceptionCaught")
@Composable
internal fun FolderShortcutEntry(
    uri: String?,
    activeAccount: String?,
    restoringSession: Boolean,
    switchAccount: (String) -> Unit,
    open: (ResourceEntity) -> Unit,
    consume: () -> Unit,
    openShared: (eu.opencloud.android.next.core.sync.SharedFolderRequest) -> Unit,
) {
    val context = LocalContext.current
    var error by remember { mutableStateOf(false) }
    val currentSwitchAccount by rememberUpdatedState(switchAccount)
    val currentOpen by rememberUpdatedState(open)
    val currentOpenShared by rememberUpdatedState(openShared)
    val currentConsume by rememberUpdatedState(consume)
    LaunchedEffect(uri, activeAccount, restoringSession) {
        if (uri == null || restoringSession) return@LaunchedEffect
        try {
            val shared =
                eu.opencloud.android.next.core.sync.SharedFolderShortcutTarget
                    .parse(uri)
            if (shared != null) {
                if (activeAccount != shared.request.account) {
                    currentSwitchAccount(shared.request.account)
                } else {
                    withContext(Dispatchers.IO) {
                        eu.opencloud.android.next.core.sync
                            .SharedFolderShortcuts(context)
                            .resolve(shared)
                    }
                    currentOpenShared(shared.request)
                    currentConsume()
                }
                return@LaunchedEffect
            }
            val target = requireNotNull(FolderShortcutTarget.parse(uri))
            val resource = withContext(Dispatchers.IO) { FolderShortcuts(context).resolve(target) }
            if (activeAccount != target.account) {
                currentSwitchAccount(target.account)
            } else {
                currentOpen(resource)
                currentConsume()
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            error = true
            currentConsume()
        }
    }
    if (error) {
        AlertDialog(
            onDismissRequest = { error = false },
            text = { Text(stringResource(R.string.folder_shortcut_unavailable)) },
            confirmButton = {
                TextButton(
                    onClick = { error = false },
                ) { Text(stringResource(R.string.folder_shortcut_close)) }
            },
        )
    }
}
