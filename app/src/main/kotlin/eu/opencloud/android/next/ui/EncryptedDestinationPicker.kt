package eu.opencloud.android.next.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.R
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.ui.BrowserContent

/** Renders destination items inside the encrypted browser's existing viewport. */
@Composable
internal fun EncryptedDestinationPicker(
    state: VaultRouteState,
    source: VaultRouteEntry,
    presentation: EncryptedBrowserPresentation,
    onOpenFolder: (String) -> Unit,
) {
    val entries =
        state.destinationPickerEntries
            .filter { presentation.display.showHidden || !it.name.startsWith('.') }
            .filterNot { isInsideSourceFolder(source, it) }
            .sortedWith(compareBy<VaultRouteEntry> { !it.isFolder }.thenBy(String.CASE_INSENSITIVE_ORDER) { it.name })
    Column(Modifier.fillMaxSize()) {
        if (state.destinationPickerLoading) {
            CircularProgressIndicator(Modifier.padding(OpenCloudDimensions.SpacingMd))
        }
        state.destinationPickerError?.let { error ->
            Text(
                stringResource(error.stringRes),
                Modifier.padding(horizontal = OpenCloudDimensions.SpacingMd),
            )
        }
        BrowserContent(
            entries = entries,
            key = { it.id },
            layout = presentation.layout,
            padding =
                androidx.compose.foundation.layout
                    .PaddingValues(OpenCloudDimensions.Zero),
            notice = {
                if (!state.destinationPickerLoading && state.destinationPickerError == null && entries.isEmpty()) {
                    Text(
                        stringResource(R.string.vault_destination_empty),
                        Modifier.padding(OpenCloudDimensions.SpacingMd),
                    )
                }
            },
        ) { entry ->
            EncryptedBrowserEntry(
                entry = entry,
                layout = presentation.layout,
                display = presentation.display,
                enabled = !state.loading && !state.destinationPickerLoading && entry.isFolder,
                offline = false,
                revision = presentation.revision,
                loadThumbnail = presentation.loadThumbnail,
                selectionMode = true,
                onOpen = { if (entry.isFolder) onOpenFolder(entry.path) },
                onAction = {},
            )
        }
    }
}

private fun isInsideSourceFolder(
    source: VaultRouteEntry,
    candidate: VaultRouteEntry,
): Boolean = source.isFolder && (candidate.path == source.path || candidate.path.startsWith(source.path + "/"))
