package eu.opencloud.android.next.feature.files

import android.content.ActivityNotFoundException
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.ui.PreparedExternalFile
import eu.opencloud.android.next.core.ui.externalFileChooser
import eu.opencloud.android.next.core.ui.rememberExternalFileLauncher

@Composable
internal fun rememberFileOpener(viewModel: FileBrowserViewModel): (ResourceEntity, ExternalAction) -> Unit {
    val context = LocalContext.current
    val launch =
        rememberExternalFileLauncher { failure ->
            viewModel.reportOpenError(
                when (failure) {
                    is ActivityNotFoundException -> "No installed app can open this file type."
                    is SecurityException ->
                        "Android blocked opening this file. Check app permissions or use Copy to device."
                    else -> "This file could not be opened. Check the transfer status and try again."
                },
            )
        }
    return { resource, action ->
        launch {
            val prepared = viewModel.prepareExternalFile(resource)
            val intent =
                if (action == ExternalAction.SEND) {
                    externalSendIntent(context, prepared)
                } else {
                    externalFileIntent(context, prepared)
                }
            PreparedExternalFile(
                if (action == ExternalAction.OPEN) intent else externalFileChooser(intent),
                onOpened = { viewModel.recordOpened(prepared) },
            )
        }
    }
}
