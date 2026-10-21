package eu.opencloud.android.next.feature.shares

import androidx.compose.foundation.layout.Box
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.OfflinePin
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.ui.BrowserAction
import eu.opencloud.android.next.core.ui.BrowserActionSheet

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun IncomingCopyMenu(
    file: IncomingBrowserItem.File,
    onAction: (IncomingBrowserItem.File, SharedCopyAction) -> Unit,
    onFileAction: (IncomingBrowserItem.File, IncomingFileAction) -> Unit = { _, _ -> },
) {
    var expanded by remember(file) { mutableStateOf(false) }
    Box {
        IconButton(onClick = { expanded = true }) {
            Icon(Icons.Default.MoreVert, stringResource(R.string.shares_actions_for_file, file.name))
        }
        if (expanded) {
            BrowserActionSheet(file.name, { expanded = false }) {
                BrowserAction(stringResource(R.string.incoming_open_with), Icons.AutoMirrored.Filled.OpenInNew) {
                    expanded = false
                    onFileAction(file, IncomingFileAction.OPEN_WITH)
                }
                BrowserAction(stringResource(R.string.incoming_send), Icons.AutoMirrored.Filled.Send) {
                    expanded = false
                    onFileAction(file, IncomingFileAction.SEND)
                }
                BrowserAction(stringResource(R.string.incoming_details), Icons.Default.Info) {
                    expanded = false
                    onFileAction(file, IncomingFileAction.DETAILS)
                }
                val kept = file.localCopy?.offlinePinned == true
                BrowserAction(
                    stringResource(if (kept) R.string.shares_make_copy_temporary else R.string.shares_keep_local_copy),
                    Icons.Default.OfflinePin,
                ) {
                    expanded = false
                    onAction(file, if (kept) SharedCopyAction.TEMPORARY else SharedCopyAction.KEEP)
                }
                if (file.localCopy != null) {
                    BrowserAction(stringResource(R.string.shares_remove_local_copy), Icons.Default.DeleteSweep) {
                        expanded = false
                        onAction(file, SharedCopyAction.REMOVE)
                    }
                }
            }
        }
    }
}
