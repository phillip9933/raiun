package eu.opencloud.android.next.feature.files

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.datastore.SettingsBrowserLayout
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.ui.BrowserEntry

/** Presentation only: encrypted roots never become ordinary cached resources or transfer inputs. */
internal data class MixedBrowserEntry(
    val resource: ResourceEntity? = null,
    val encrypted: VaultLocation? = null,
) {
    val name: String get() = resource?.name ?: requireNotNull(encrypted).title
    val key: String get() =
        resource?.let { "plain:${it.selectionKey}" }
            ?: requireNotNull(encrypted).let { "encrypted:${it.driveId}:${it.vaultPath}" }
    val folder: Boolean get() = resource?.kind != ResourceKind.FILE
}

internal fun mixedBrowserEntries(
    resources: List<ResourceEntity>,
    encrypted: List<VaultLocation>,
    criterion: BrowserSortCriterion,
    ascending: Boolean,
): List<MixedBrowserEntry> {
    val entries =
        resources.filterNot { it.matchesEncryptedFolder(encrypted) }.map { MixedBrowserEntry(resource = it) } +
            encrypted.map { MixedBrowserEntry(encrypted = it) }
    // No metadata is guessed for a locked root. Unknown dates/sizes sort as zero.
    val byName = compareBy(String.CASE_INSENSITIVE_ORDER) { entry: MixedBrowserEntry -> entry.name }
    val comparator =
        when (criterion) {
            BrowserSortCriterion.Name -> byName
            BrowserSortCriterion.DateModified ->
                compareBy<MixedBrowserEntry> {
                    it.resource?.modifiedAtEpochMillis ?: 0
                }
            BrowserSortCriterion.DateOpened -> compareBy<MixedBrowserEntry> { it.resource?.createdAtEpochMillis ?: 0 }
            BrowserSortCriterion.Size -> compareBy<MixedBrowserEntry> { it.resource?.sizeBytes ?: 0 }
            BrowserSortCriterion.Type ->
                compareBy(String.CASE_INSENSITIVE_ORDER) { entry: MixedBrowserEntry ->
                    entry.name.substringAfterLast('.', "").ifBlank { entry.resource?.mimeType.orEmpty() }
                }
        }.then(byName)
    return entries.sortedWith(
        compareBy<MixedBrowserEntry> {
            !it.folder
        }.then(if (ascending) comparator else comparator.reversed()),
    )
}

@Composable
internal fun EncryptedFolderEntry(
    location: VaultLocation,
    layout: SettingsBrowserLayout,
    onOpen: (VaultLocation) -> Unit,
    onActions: (VaultLocation) -> Unit = onOpen,
) {
    BrowserEntry(
        layout = layout,
        onOpen = { onOpen(location) },
        name = { Text(location.title, maxLines = 1) },
        thumbnail = { modifier ->
            Box(modifier, contentAlignment = Alignment.Center) {
                Box(Modifier.size(OpenCloudDimensions.TouchTarget)) {
                    Icon(Icons.Default.Folder, null, Modifier.fillMaxSize())
                    Icon(
                        Icons.Default.Lock,
                        stringResource(R.string.browser_encrypted_locked),
                        Modifier
                            .align(Alignment.BottomEnd)
                            .size(OpenCloudDimensions.IconMedium)
                            .background(MaterialTheme.colorScheme.secondaryContainer, CircleShape)
                            .border(OpenCloudDimensions.StrokeThin, MaterialTheme.colorScheme.surface, CircleShape)
                            .padding(OpenCloudDimensions.SpacingXxs),
                        tint = MaterialTheme.colorScheme.onSecondaryContainer,
                    )
                }
            }
        },
        metadata = {},
        actions = {
            IconButton(onClick = { onActions(location) }) {
                Icon(Icons.Default.MoreVert, stringResource(R.string.browser_encrypted_actions, location.title))
            }
        },
    )
}

internal fun ResourceEntity.matchesEncryptedFolder(locations: List<VaultLocation>): Boolean =
    locations.any {
        accountId == it.accountId &&
            spaceId == it.driveId &&
            (remoteId == it.remoteVaultId || path.trim('/') == it.vaultPath)
    }

internal fun FileBrowserUiState.withEncryptedFolders(
    entries: List<VaultLocation>,
    error: String?,
): FileBrowserUiState {
    val hiddenKeys =
        (resources + searchResults + offlineResources)
            .filter { it.matchesEncryptedFolder(entries) }
            .map { it.selectionKey }
            .toSet()
    return copy(
        encryptedFolders = entries,
        encryptedFoldersError = error,
        selectedIds = selectedIds - hiddenKeys,
        actionResource = actionResource?.takeUnless { it.matchesEncryptedFolder(entries) },
    )
}
