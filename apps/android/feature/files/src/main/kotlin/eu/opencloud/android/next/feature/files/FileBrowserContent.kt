package eu.opencloud.android.next.feature.files

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.InsertDriveFile
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.RadioButtonUnchecked
import androidx.compose.material.icons.filled.Star
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.datastore.FileDisplayOptions
import eu.opencloud.android.next.core.datastore.SettingsBrowserLayout
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.isVideoPreview
import eu.opencloud.android.next.core.ui.BrowserContent
import eu.opencloud.android.next.core.ui.BrowserEntry

@Composable
internal fun FavoritesEmpty(contentPadding: PaddingValues) {
    Box(
        modifier = Modifier.fillMaxSize().padding(contentPadding),
        contentAlignment = Alignment.Center,
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs),
        ) {
            Icon(Icons.Default.Star, contentDescription = null)
            Text(stringResource(R.string.browser_no_favorites_yet), style = MaterialTheme.typography.titleMedium)
            Text(stringResource(R.string.browser_favorites_offline))
        }
    }
}

@Composable
@Suppress("LongParameterList")
internal fun BrowserList(
    offlinePins: List<ResourceEntity>,
    resources: List<ResourceEntity>,
    selectedIds: Set<String>,
    selectionMode: Boolean,
    condensed: Boolean,
    contentPadding: PaddingValues,
    onOpen: (ResourceEntity) -> Unit,
    onToggleSelection: (String) -> Unit,
    onShowActions: (ResourceEntity) -> Unit,
    display: FileDisplayOptions = FileDisplayOptions(),
    encryptedFolders: List<VaultLocation> = emptyList(),
    onOpenEncryptedLocation: (VaultLocation) -> Unit = {},
    onEncryptedLocationActions: (VaultLocation) -> Unit = {},
    sortCriterion: BrowserSortCriterion = BrowserSortCriterion.Name,
    sortAscending: Boolean = true,
    directoryEntries: List<MixedBrowserEntry>? = null,
) = ResourceBrowserContent(
    offlinePins,
    resources,
    selectedIds,
    selectionMode,
    if (condensed) SettingsBrowserLayout.CONDENSED_TABLE else SettingsBrowserLayout.DEFAULT_TABLE,
    contentPadding,
    onOpen,
    onToggleSelection,
    onShowActions,
    display,
    encryptedFolders,
    onOpenEncryptedLocation,
    onEncryptedLocationActions,
    sortCriterion,
    sortAscending,
    directoryEntries,
)

@Composable
@Suppress("LongParameterList")
internal fun BrowserGrid(
    offlinePins: List<ResourceEntity>,
    resources: List<ResourceEntity>,
    selectedIds: Set<String>,
    selectionMode: Boolean,
    contentPadding: PaddingValues,
    onOpen: (ResourceEntity) -> Unit,
    onToggleSelection: (String) -> Unit,
    onShowActions: (ResourceEntity) -> Unit,
    display: FileDisplayOptions = FileDisplayOptions(),
    encryptedFolders: List<VaultLocation> = emptyList(),
    onOpenEncryptedLocation: (VaultLocation) -> Unit = {},
    onEncryptedLocationActions: (VaultLocation) -> Unit = {},
    sortCriterion: BrowserSortCriterion = BrowserSortCriterion.Name,
    sortAscending: Boolean = true,
    directoryEntries: List<MixedBrowserEntry>? = null,
) = ResourceBrowserContent(
    offlinePins,
    resources,
    selectedIds,
    selectionMode,
    SettingsBrowserLayout.TILES,
    contentPadding,
    onOpen,
    onToggleSelection,
    onShowActions,
    display,
    encryptedFolders,
    onOpenEncryptedLocation,
    onEncryptedLocationActions,
    sortCriterion,
    sortAscending,
    directoryEntries,
)

@Composable
@Suppress("LongParameterList")
private fun ResourceBrowserContent(
    offlinePins: List<ResourceEntity>,
    resources: List<ResourceEntity>,
    selectedIds: Set<String>,
    selectionMode: Boolean,
    layout: SettingsBrowserLayout,
    contentPadding: PaddingValues,
    onOpen: (ResourceEntity) -> Unit,
    onToggleSelection: (String) -> Unit,
    onShowActions: (ResourceEntity) -> Unit,
    display: FileDisplayOptions,
    encryptedFolders: List<VaultLocation>,
    onOpenEncryptedLocation: (VaultLocation) -> Unit,
    onEncryptedLocationActions: (VaultLocation) -> Unit,
    sortCriterion: BrowserSortCriterion,
    sortAscending: Boolean,
    directoryEntries: List<MixedBrowserEntry>?,
) {
    BrowserContent(
        directoryEntries ?: mixedBrowserEntries(resources, encryptedFolders, sortCriterion, sortAscending),
        { it.key },
        layout,
        padding = contentPadding,
        footer = {
            if (directoryEntries == null) {
                FolderSummary(
                    resources.filterNot { it.matchesEncryptedFolder(encryptedFolders) },
                    encryptedFolders.size,
                )
            }
        },
    ) { entry ->
        val item = entry.resource
        if (item == null) {
            EncryptedFolderEntry(
                requireNotNull(entry.encrypted),
                layout,
                onOpenEncryptedLocation,
                onEncryptedLocationActions,
            )
            return@BrowserContent
        }
        val selected = item.selectionKey in selectedIds
        BrowserEntry(
            layout = layout,
            selected = selected,
            onOpen = { if (selectionMode) onToggleSelection(item.selectionKey) else onOpen(item) },
            onLongClick = { onToggleSelection(item.selectionKey) },
            name = {
                if (layout == SettingsBrowserLayout.TILES) {
                    Text(
                        displayFileName(item, display),
                        style = MaterialTheme.typography.labelLarge,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                } else {
                    ResourceName(item, display = display)
                }
            },
            thumbnail = { modifier ->
                Box(modifier, contentAlignment = Alignment.Center) {
                    BadgedResourceThumbnail(
                        item,
                        if (layout == SettingsBrowserLayout.TILES && !item.isImagePreview() && !item.isVideoPreview()) {
                            Modifier.size(OpenCloudDimensions.TouchTarget)
                        } else {
                            Modifier.fillMaxSize()
                        },
                    )
                }
            },
            metadata = { ResourceMetadata(item, isKeptOffline(item, offlinePins), display) },
            actions = {
                if (selectionMode) {
                    SelectionCircle(selected, item.name, { onToggleSelection(item.selectionKey) })
                } else {
                    IconButton(onClick = { onShowActions(item) }) {
                        Icon(Icons.Default.MoreVert, stringResource(R.string.browser_actions_for, item.name))
                    }
                }
            },
        )
    }
}

@Composable
private fun ResourceName(
    resource: ResourceEntity,
    modifier: Modifier = Modifier,
    display: FileDisplayOptions = FileDisplayOptions(),
) {
    Row(
        modifier = modifier,
        horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXxs),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(displayFileName(resource, display), modifier = Modifier.weight(1f, fill = false), maxLines = 1)
    }
}

@Composable
private fun BadgedResourceThumbnail(
    resource: ResourceEntity,
    modifier: Modifier = Modifier,
) {
    Box(modifier.size(OpenCloudDimensions.TouchTarget)) {
        ResourceThumbnail(resource, Modifier.matchParentSize())
        if (resource.isFavorite) {
            Icon(
                Icons.Default.Star,
                stringResource(R.string.browser_favorite),
                Modifier
                    .align(Alignment.BottomEnd)
                    .size(OpenCloudDimensions.SpacingMd)
                    .background(MaterialTheme.colorScheme.surface, androidx.compose.foundation.shape.CircleShape),
                tint = MaterialTheme.colorScheme.primary,
            )
        }
    }
}

@Composable
private fun SelectionCircle(
    selected: Boolean,
    resourceName: String,
    onSelect: () -> Unit,
    modifier: Modifier = Modifier,
) {
    IconButton(onClick = onSelect, modifier = modifier) {
        Icon(
            imageVector = if (selected) Icons.Default.CheckCircle else Icons.Default.RadioButtonUnchecked,
            contentDescription =
                stringResource(
                    if (selected) R.string.browser_deselect_item else R.string.browser_select_item,
                    resourceName,
                ),
            tint = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
internal fun ResourceIcon(
    kind: ResourceKind,
    modifier: Modifier = Modifier,
) {
    val icon =
        if (kind == ResourceKind.FOLDER) {
            Icons.Default.Folder
        } else {
            Icons.AutoMirrored.Filled.InsertDriveFile
        }
    val description =
        stringResource(
            if (kind ==
                ResourceKind.FOLDER
            ) {
                R.string.browser_folder
            } else {
                R.string.browser_file
            },
        )
    Icon(
        imageVector = icon,
        contentDescription = description,
        modifier = modifier,
        tint =
            if (kind ==
                ResourceKind.FOLDER
            ) {
                MaterialTheme.colorScheme.primary
            } else {
                MaterialTheme.colorScheme.secondary
            },
    )
}

@Composable
private fun ResourceMetadata(
    resource: ResourceEntity,
    keptOffline: Boolean,
    display: FileDisplayOptions = FileDisplayOptions(),
) {
    Row(
        horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXxs),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        FileMetadataText(resource, Modifier.weight(1f, fill = false), display)
        LocalAvailabilityIcon(resource, keptOffline)
    }
}
