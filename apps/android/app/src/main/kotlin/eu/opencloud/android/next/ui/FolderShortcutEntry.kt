package eu.opencloud.android.next.ui

import androidx.compose.material3.AlertDialog
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
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.sync.FolderShortcutTarget
import eu.opencloud.android.next.core.sync.FolderShortcuts
import eu.opencloud.android.next.core.sync.SharedFolderRequest
import eu.opencloud.android.next.core.sync.SharedFolderShortcutTarget
import eu.opencloud.android.next.core.sync.SharedFolderShortcuts
import eu.opencloud.android.next.feature.files.R
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

// App entry boundary, account switch, and consumption callbacks.
@Suppress("LongParameterList", "TooGenericExceptionCaught")
@Composable
internal fun FolderShortcutEntry(
    uri: String?,
    requestId: Long?,
    activeAccount: String?,
    restoringSession: Boolean,
    switchAccount: (String) -> Unit,
    open: (ResourceEntity) -> Unit,
    onUnavailable: () -> Boolean,
    isCurrent: () -> Boolean,
    openShared: (eu.opencloud.android.next.core.sync.SharedFolderRequest) -> Unit,
    access: FolderShortcutAccess = rememberFolderShortcutAccess(),
) {
    var error by remember { mutableStateOf(false) }
    // An old resolution must retain its own event/account guard and acknowledgement. Updating
    // these to B's latest callbacks would allow a late A result to act under B's admission.
    val callbacks =
        remember(requestId, activeAccount, restoringSession) {
            FolderShortcutCallbacks(switchAccount, open, onUnavailable, isCurrent, openShared)
        }
    LaunchedEffect(requestId, activeAccount, restoringSession) {
        if (uri == null || restoringSession) return@LaunchedEffect
        try {
            val shared = SharedFolderShortcutTarget.parse(uri)
            if (shared != null) {
                if (activeAccount != shared.request.account) {
                    callbacks.switchTo(shared.request.account)
                } else {
                    withContext(Dispatchers.IO) { access.resolveShared(shared) }
                    callbacks.openSharedFolder(shared.request)
                }
                return@LaunchedEffect
            }
            val target = requireNotNull(FolderShortcutTarget.parse(uri))
            val resource = withContext(Dispatchers.IO) { access.resolve(target) }
            if (activeAccount != target.account) {
                callbacks.switchTo(target.account)
            } else {
                callbacks.openFolder(resource)
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            if (callbacks.unavailable()) error = true
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

private class FolderShortcutCallbacks(
    private val switchAccount: (String) -> Unit,
    private val open: (ResourceEntity) -> Unit,
    private val onUnavailable: () -> Boolean,
    private val isCurrent: () -> Boolean,
    private val openShared: (SharedFolderRequest) -> Unit,
) {
    fun switchTo(account: String) {
        if (isCurrent()) switchAccount(account)
    }

    fun openFolder(resource: ResourceEntity) {
        if (isCurrent()) open(resource)
    }

    fun openSharedFolder(request: SharedFolderRequest) {
        if (isCurrent()) openShared(request)
    }

    fun unavailable(): Boolean = isCurrent() && onUnavailable()
}

internal interface FolderShortcutAccess {
    suspend fun resolve(target: FolderShortcutTarget): ResourceEntity

    suspend fun resolveShared(target: SharedFolderShortcutTarget)
}

@Composable
private fun rememberFolderShortcutAccess(): FolderShortcutAccess {
    val context = LocalContext.current
    return remember(context) {
        object : FolderShortcutAccess {
            override suspend fun resolve(target: FolderShortcutTarget): ResourceEntity =
                FolderShortcuts(context).resolve(target)

            override suspend fun resolveShared(target: SharedFolderShortcutTarget) {
                SharedFolderShortcuts(context).resolve(target)
            }
        }
    }
}
