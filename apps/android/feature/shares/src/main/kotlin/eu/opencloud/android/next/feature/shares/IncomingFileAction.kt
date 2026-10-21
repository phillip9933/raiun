package eu.opencloud.android.next.feature.shares

import android.content.Intent
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.documentsprovider.sharedFileViewIntent
import eu.opencloud.android.next.core.model.fileMimeType
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.security.AppLock
import eu.opencloud.android.next.core.sync.SharedReadPreparation
import eu.opencloud.android.next.core.ui.PreparedExternalFile
import eu.opencloud.android.next.core.ui.externalFileChooser
import eu.opencloud.android.next.core.ui.rememberExternalFileLauncher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

enum class IncomingFileAction { OPEN, OPEN_WITH, SEND, DETAILS }

@Composable
internal fun rememberIncomingFileActions(
    onError: (String?) -> Unit,
): (IncomingBrowserItem.File, IncomingFileAction) -> Unit {
    val context = LocalContext.current
    var details by remember { mutableStateOf<IncomingBrowserItem.File?>(null) }
    val noApp = stringResource(R.string.incoming_open_no_app)
    val launch =
        rememberExternalFileLauncher { failure ->
            val message =
                if (failure is android.content.ActivityNotFoundException) {
                    noApp
                } else {
                    failure.toOpenCloudError().safeMessage(context)
                }
            onError(message)
        }
    details?.let { file ->
        AlertDialog(onDismissRequest = { details = null }, title = { Text(file.name) }, text = {
            Column {
                eu.opencloud.android.next.core.ui.ItemActivitiesAction(
                    file.request.accountId,
                    file.request.file.remoteId,
                    file.name,
                )
                Text(fileMimeType(file.name, file.mimeType))
                Text(
                    android.text.format.Formatter
                        .formatShortFileSize(context, file.request.file.sizeBytes),
                )
                Text(file.request.file.path)
            }
        }, confirmButton = {
            TextButton(
                onClick = { details = null },
            ) { Text(stringResource(R.string.incoming_close)) }
        })
    }
    return action@{ file, action ->
        if (action == IncomingFileAction.DETAILS) {
            details = file
            return@action
        }
        launch {
            onError(null)
            AppLock(context).allowDocumentOpenFromApp()
            withContext(Dispatchers.IO) { SharedReadPreparation.open(context, file.request).close() }
            AppLock(context).allowDocumentOpenFromApp()
            val view = sharedFileViewIntent(context, file.request, fileMimeType(file.name, file.mimeType))
            val intent =
                if (action == IncomingFileAction.SEND) {
                    Intent(Intent.ACTION_SEND).apply {
                        type = view.type
                        putExtra(Intent.EXTRA_STREAM, view.data)
                        clipData = view.clipData
                        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    }
                } else {
                    view
                }
            PreparedExternalFile(if (action == IncomingFileAction.OPEN) intent else externalFileChooser(intent))
        }
    }
}
