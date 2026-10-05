package eu.opencloud.android.next.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.DriveFileMove
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.OfflinePin
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import eu.opencloud.android.next.R
import eu.opencloud.android.next.core.datastore.FileDisplayOptions
import eu.opencloud.android.next.core.datastore.SettingsBrowserLayout
import eu.opencloud.android.next.core.datastore.SettingsRepository
import eu.opencloud.android.next.core.datastore.UserSettings
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.ui.BrowserContent
import eu.opencloud.android.next.core.ui.BrowserEntry
import eu.opencloud.android.next.core.ui.BrowserItemMetadataText
import eu.opencloud.android.next.core.ui.BrowserPlacementBar
import eu.opencloud.android.next.core.ui.BrowserPlacementBarState
import eu.opencloud.android.next.core.ui.BrowserToolbar
import eu.opencloud.android.next.core.ui.ResourceMetadataDetails
import eu.opencloud.android.next.core.ui.browserDisplayName
import kotlinx.coroutines.launch

@Composable
@OptIn(ExperimentalMaterial3Api::class)
internal fun EncryptedBrowserContent(
    state: VaultRouteState,
    callbacks: VaultRouteCallbacks,
    createFolderDialogVisible: Boolean,
    onDismissCreateFolderDialog: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val settings = remember(context) { SettingsRepository.create(context) }
    val preferences by settings.settings.collectAsState(UserSettings())
    val scope = rememberCoroutineScope()
    var action by remember(state.lockRevision) { mutableStateOf<Pair<VaultRouteEntry, VaultEntryAction>?>(null) }
    var destinationAction by remember(state.lockRevision) {
        mutableStateOf<Pair<VaultRouteEntry, VaultEntryAction>?>(null)
    }
    val layout = preferences.browserLayout
    val display = preferences.fileDisplay
    val navigatingDestination = destinationAction != null
    LaunchedEffect(state.destinationPickerPath) {
        if (state.destinationPickerPath == null) destinationAction = null
    }
    BackHandler(enabled = navigatingDestination) {
        val path = state.destinationPickerPath.orEmpty()
        if (path.isNotEmpty()) {
            callbacks.onLoadDestinationFolders(parentEncryptedPath(path))
        } else {
            destinationAction = null
            callbacks.onDismissDestinationPicker()
        }
    }
    Column(modifier) {
        EncryptedLocationHeader(state)
        EncryptedBrowserToolbar(state, navigatingDestination, layout, callbacks) {
            scope.launch { settings.setBrowserLayout(nextEncryptedLayout(layout)) }
        }
        EncryptedBrowserViewport(
            state,
            callbacks,
            EncryptedBrowserPresentation(layout, display, state.lockRevision, callbacks.onLoadThumbnail),
            destinationAction?.first,
            onAction = { entry, selected ->
                when (selected) {
                    VaultEntryAction.OPEN_WITH -> callbacks.onEntryAction(entry.id, selected, null)
                    VaultEntryAction.COPY, VaultEntryAction.MOVE -> {
                        destinationAction = entry to selected
                        callbacks.onLoadDestinationFolders(state.currentPath)
                    }
                    else -> action = entry to selected
                }
            },
            modifier = Modifier.weight(1f),
        )
        EncryptedBrowserPlacementFooter(destinationAction, state, callbacks, { destinationAction = null })
    }
    if (createFolderDialogVisible) {
        EncryptedNameDialog(
            title = stringResource(R.string.vault_new_folder),
            initialValue = "",
            onDismiss = onDismissCreateFolderDialog,
            onConfirm = {
                onDismissCreateFolderDialog()
                callbacks.onCreateFolder(it)
            },
        )
    }
    action?.let { (entry, selected) ->
        EncryptedEntryActionDialog(
            EncryptedEntryDialogData(entry, display, state.offline),
            selected,
            onDismiss = { action = null },
        ) { value ->
            action = null
            callbacks.onEntryAction(entry.id, selected, value)
        }
    }
}

private fun nextEncryptedLayout(layout: SettingsBrowserLayout): SettingsBrowserLayout =
    when (layout) {
        SettingsBrowserLayout.DEFAULT_TABLE -> SettingsBrowserLayout.CONDENSED_TABLE
        SettingsBrowserLayout.CONDENSED_TABLE -> SettingsBrowserLayout.TILES
        SettingsBrowserLayout.TILES -> SettingsBrowserLayout.DEFAULT_TABLE
    }

private fun parentEncryptedPath(path: String): String =
    path.trimEnd('/').substringBeforeLast('/', missingDelimiterValue = "")

@Composable
private fun EncryptedBrowserToolbar(
    state: VaultRouteState,
    selectingDestination: Boolean,
    layout: SettingsBrowserLayout,
    callbacks: VaultRouteCallbacks,
    onToggleLayout: () -> Unit,
) {
    var menuExpanded by remember(state.lockRevision) { mutableStateOf(false) }
    BrowserToolbar(
        canNavigateUp =
            if (selectingDestination) {
                !state.destinationPickerPath.isNullOrEmpty()
            } else {
                state.currentPath
                    .isNotEmpty()
            },
        layout = layout,
        onNavigateUp = {
            if (selectingDestination) {
                callbacks.onLoadDestinationFolders(parentEncryptedPath(state.destinationPickerPath.orEmpty()))
            } else {
                callbacks.onUp()
            }
        },
        onToggleLayout = onToggleLayout,
    ) {
        val path = state.destinationPickerPath.orEmpty()
        val title =
            if (selectingDestination) {
                if (path.isEmpty()) state.selectedTitle.orEmpty() else "${state.selectedTitle} / $path"
            } else {
                state.currentPath.substringAfterLast('/').ifEmpty { state.selectedTitle.orEmpty() }
            }
        Text(title, Modifier.weight(1f), maxLines = 1)
        if (!selectingDestination) {
            Box {
                IconButton(onClick = { menuExpanded = true }, enabled = !state.loading) {
                    Icon(
                        Icons.Default.MoreVert,
                        stringResource(R.string.vault_entry_actions, state.selectedTitle.orEmpty()),
                    )
                }
                DropdownMenu(menuExpanded, onDismissRequest = { menuExpanded = false }) {
                    DropdownMenuItem(
                        text = {
                            Text(
                                stringResource(
                                    if (state.offline) R.string.vault_remove_offline else R.string.vault_keep_offline,
                                ),
                            )
                        },
                        onClick = {
                            menuExpanded = false
                            callbacks.onShowOfflineActions()
                        },
                    )
                }
            }
        }
    }
}

@Composable
@Suppress("LongParameterList") // Browser source, presentation and independently owned action/navigation callbacks.
private fun EncryptedBrowserViewport(
    state: VaultRouteState,
    callbacks: VaultRouteCallbacks,
    presentation: EncryptedBrowserPresentation,
    destinationSource: VaultRouteEntry?,
    onAction: (VaultRouteEntry, VaultEntryAction) -> Unit,
    modifier: Modifier = Modifier,
) {
    PullToRefreshBox(
        isRefreshing = if (destinationSource != null) state.destinationPickerLoading else state.loading,
        onRefresh = {
            if (destinationSource != null) {
                callbacks.onLoadDestinationFolders(state.destinationPickerPath.orEmpty())
            } else {
                callbacks.onRetry()
            }
        },
        modifier = modifier,
    ) {
        if (destinationSource == null) {
            EncryptedEntriesList(state, presentation.layout, presentation.display, callbacks, onAction)
        } else {
            EncryptedDestinationPicker(
                state,
                destinationSource,
                presentation,
                callbacks.onLoadDestinationFolders,
            )
        }
    }
}

@Composable
private fun EncryptedEntriesList(
    state: VaultRouteState,
    layout: SettingsBrowserLayout,
    display: FileDisplayOptions,
    callbacks: VaultRouteCallbacks,
    onAction: (VaultRouteEntry, VaultEntryAction) -> Unit,
) {
    BrowserContent(
        entries =
            state.entries
                .filter { display.showHidden || !it.name.startsWith('.') }
                .sortedWith(
                    compareBy<VaultRouteEntry> { !it.isFolder }.thenBy(String.CASE_INSENSITIVE_ORDER) { it.name },
                ),
        key = { it.id },
        layout = layout,
        padding = PaddingValues(OpenCloudDimensions.Zero),
        notice = {
            if (!state.loading && state.error == null && state.entries.isEmpty()) {
                Text(stringResource(R.string.vault_contents_empty), Modifier.padding(OpenCloudDimensions.SpacingMd))
            }
        },
    ) { entry ->
        EncryptedBrowserEntry(
            entry = entry,
            layout = layout,
            display = display,
            enabled = !state.loading,
            offline = state.offline,
            revision = state.lockRevision,
            loadThumbnail = callbacks.onLoadThumbnail,
            onOpen = {
                if (entry.isFolder) {
                    callbacks.onOpenVaultFolder(
                        entry.id,
                    )
                } else {
                    callbacks.onOpenPreview(entry.id)
                }
            },
            onAction = { onAction(entry, it) },
        )
    }
}

@Composable
private fun EncryptedBrowserPlacementFooter(
    destinationAction: Pair<VaultRouteEntry, VaultEntryAction>?,
    state: VaultRouteState,
    callbacks: VaultRouteCallbacks,
    onClear: () -> Unit,
) {
    destinationAction?.let { (source, selected) ->
        Surface(color = MaterialTheme.colorScheme.surfaceContainer) {
            Column(Modifier.fillMaxWidth().padding(OpenCloudDimensions.SpacingMd)) {
                BrowserPlacementBar(
                    sourceSummary = stringResource(R.string.vault_destination_choose, source.name),
                    state =
                        BrowserPlacementBarState(
                            actionLabel =
                                if (selected ==
                                    VaultEntryAction.COPY
                                ) {
                                    R.string.vault_copy_here
                                } else {
                                    R.string.vault_move_here
                                },
                            cancelLabel = R.string.vault_cancel,
                            busy = state.loading || state.destinationPickerLoading,
                            enabled = state.destinationPickerError == null,
                        ),
                    onPlace = {
                        callbacks.onEntryAction(source.id, selected, state.destinationPickerPath.orEmpty())
                        onClear()
                        callbacks.onDismissDestinationPicker()
                    },
                    onCancel = {
                        onClear()
                        callbacks.onDismissDestinationPicker()
                    },
                )
            }
        }
    }
}

@Composable
private fun EncryptedLocationHeader(state: VaultRouteState) {
    Surface(
        color = MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.55f),
        contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
    ) {
        Row(
            Modifier.fillMaxWidth().padding(OpenCloudDimensions.SpacingSm),
            horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(Icons.Default.Lock, null)
            Text(
                stringResource(
                    if (state.offline) {
                        R.string.vault_offline_copy
                    } else if (state.selectedLocation?.kind == VaultLocationKindUi.SPACE_VAULT) {
                        R.string.vault_encrypted_space_header
                    } else {
                        R.string.vault_encrypted_folder_header
                    },
                ),
                style = MaterialTheme.typography.labelLarge,
            )
        }
    }
}

@Composable
@Suppress("LongParameterList") // Browser presentation and explicit action callbacks stay separate.
internal fun EncryptedBrowserEntry(
    entry: VaultRouteEntry,
    layout: SettingsBrowserLayout,
    display: FileDisplayOptions,
    enabled: Boolean,
    offline: Boolean,
    revision: Long,
    loadThumbnail: suspend (String) -> ByteArray?,
    onOpen: () -> Unit,
    selectionMode: Boolean = false,
    onAction: (VaultEntryAction) -> Unit,
) {
    var expanded by remember(entry.id) { mutableStateOf(false) }
    BrowserEntry(
        layout = layout,
        onOpen = { if (enabled && (!selectionMode || entry.isFolder)) onOpen() },
        name = { Text(browserDisplayName(entry.name, entry.isFolder, display), maxLines = 1) },
        thumbnail = { modifier ->
            EncryptedThumbnail(entry, revision, enabled, modifier, loadThumbnail)
        },
        metadata = {
            EncryptedEntryMetadata(entry, offline, display)
        },
        actions = {
            if (!selectionMode) {
                Box {
                    IconButton(onClick = { expanded = true }, enabled = enabled) {
                        Icon(Icons.Default.MoreVert, stringResource(R.string.vault_entry_actions, entry.name))
                    }
                    DropdownMenu(expanded, onDismissRequest = { expanded = false }) {
                        VaultEntryAction.entries
                            .filter {
                                !entry.isFolder ||
                                    it != VaultEntryAction.SAVE_COPY &&
                                    it != VaultEntryAction.OPEN_WITH
                            }.filter {
                                !offline ||
                                    it in
                                    setOf(
                                        VaultEntryAction.SAVE_COPY,
                                        VaultEntryAction.DETAILS,
                                        VaultEntryAction.OPEN_WITH,
                                    )
                            }.forEach { action ->
                                DropdownMenuItem(
                                    text = { Text(stringResource(action.label)) },
                                    leadingIcon = { Icon(action.icon, null) },
                                    onClick = {
                                        expanded = false
                                        onAction(action)
                                    },
                                )
                            }
                    }
                }
            }
        },
    )
}

@Composable
private fun EncryptedEntryMetadata(
    entry: VaultRouteEntry,
    offline: Boolean,
    display: FileDisplayOptions,
) {
    val context = LocalContext.current
    val metadata =
        if (!display.showSize) {
            ""
        } else if (entry.isFolder) {
            stringResource(R.string.vault_entry_folder_type)
        } else {
            entry.displaySize
                ?.let {
                    android.text.format.Formatter
                        .formatShortFileSize(context, it)
                }.orEmpty()
        }
    Row(
        horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXxs),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        BrowserItemMetadataText(metadata, Modifier.weight(1f, fill = false))
        Icon(
            modifier = Modifier.size(OpenCloudDimensions.SpacingMd),
            imageVector =
                if (offline ||
                    entry.offlineAvailable == true
                ) {
                    Icons.Default.OfflinePin
                } else {
                    Icons.Default.Cloud
                },
            contentDescription =
                stringResource(
                    when {
                        offline || entry.offlineAvailable == true -> R.string.vault_entry_offline_status
                        entry.offlineAvailable == false -> R.string.vault_entry_cloud_only_status
                        else -> R.string.vault_entry_online_unknown_status
                    },
                ),
            tint =
                if (offline ||
                    entry.offlineAvailable == true
                ) {
                    MaterialTheme.colorScheme.primary
                } else {
                    MaterialTheme.colorScheme.onSurfaceVariant
                },
        )
    }
}

private fun encryptedContentType(
    declaredType: String?,
    fileName: String,
): String? {
    val declared = declaredType?.substringBefore(';')?.trim()?.takeIf(String::isNotBlank)
    if (declared != null) return declared
    val extension = fileName.substringAfterLast('.', "").lowercase().takeIf(String::isNotBlank)
    return extension?.let {
        android.webkit.MimeTypeMap
            .getSingleton()
            .getMimeTypeFromExtension(it)
    }
}

internal val VaultEntryAction.label: Int get() =
    when (this) {
        VaultEntryAction.RENAME -> R.string.vault_rename
        VaultEntryAction.DELETE -> R.string.vault_delete
        VaultEntryAction.COPY -> R.string.vault_copy
        VaultEntryAction.MOVE -> R.string.vault_move
        VaultEntryAction.SAVE_COPY -> R.string.vault_save_copy
        VaultEntryAction.OPEN_WITH -> R.string.vault_open_with
        VaultEntryAction.KEEP_OFFLINE -> R.string.vault_keep_offline
        VaultEntryAction.DETAILS -> R.string.vault_details
    }

private val VaultEntryAction.icon
    get() =
        when (this) {
            VaultEntryAction.RENAME -> Icons.Default.Edit
            VaultEntryAction.DELETE -> Icons.Default.Delete
            VaultEntryAction.COPY, VaultEntryAction.SAVE_COPY -> Icons.Default.ContentCopy
            VaultEntryAction.MOVE -> Icons.AutoMirrored.Filled.DriveFileMove
            VaultEntryAction.OPEN_WITH -> Icons.AutoMirrored.Filled.OpenInNew
            VaultEntryAction.KEEP_OFFLINE -> Icons.Default.OfflinePin
            VaultEntryAction.DETAILS -> Icons.Default.Info
        }

private data class EncryptedEntryDialogData(
    val entry: VaultRouteEntry,
    val display: FileDisplayOptions,
    val offline: Boolean,
)

@Composable
private fun EncryptedEntryActionDialog(
    data: EncryptedEntryDialogData,
    action: VaultEntryAction,
    onDismiss: () -> Unit,
    onConfirm: (String?) -> Unit,
) {
    val entry = data.entry
    val display = data.display
    when (action) {
        VaultEntryAction.RENAME -> EncryptedNameDialog(stringResource(action.label), entry.name, onDismiss, onConfirm)
        VaultEntryAction.COPY, VaultEntryAction.MOVE -> Unit
        VaultEntryAction.KEEP_OFFLINE, VaultEntryAction.SAVE_COPY ->
            AlertDialog(
                onDismissRequest = onDismiss,
                title = { Text(stringResource(action.label)) },
                text = {
                    Text(
                        stringResource(
                            if (action ==
                                VaultEntryAction.KEEP_OFFLINE
                            ) {
                                R.string.vault_keep_offline_warning
                            } else {
                                R.string.vault_save_copy_warning
                            },
                        ),
                    )
                },
                confirmButton = {
                    Button(
                        onClick = { onConfirm(null) },
                    ) { Text(stringResource(R.string.vault_confirm)) }
                },
                dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.vault_cancel)) } },
                properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
            )
        else ->
            AlertDialog(
                onDismissRequest = onDismiss,
                title = { Text(browserDisplayName(entry.name, entry.isFolder, display)) },
                text =
                    if (action == VaultEntryAction.DELETE) {
                        { Text(stringResource(R.string.vault_delete_confirm)) }
                    } else {
                        { EncryptedEntryDetails(entry, display, data.offline) }
                    },
                confirmButton =
                    if (action == VaultEntryAction.DELETE) {
                        {
                            Button(onClick = { onConfirm(null) }) {
                                Text(stringResource(R.string.vault_delete))
                            }
                        }
                    } else {
                        { TextButton(onClick = onDismiss) { Text(stringResource(R.string.vault_close)) } }
                    },
                dismissButton = {
                    if (action ==
                        VaultEntryAction.DELETE
                    ) {
                        TextButton(onClick = onDismiss) { Text(stringResource(R.string.vault_cancel)) }
                    }
                },
                properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
            )
    }
}

@Composable
private fun EncryptedEntryDetails(
    entry: VaultRouteEntry,
    display: FileDisplayOptions,
    offline: Boolean,
) {
    val context = LocalContext.current
    val type =
        if (entry.isFolder) {
            stringResource(R.string.vault_entry_folder_type)
        } else {
            encryptedContentType(entry.contentType, entry.name) ?: stringResource(R.string.vault_entry_unknown_type)
        }
    Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm)) {
        ResourceMetadataDetails(
            location = stringResource(R.string.vault_details_path, entry.path),
            type = stringResource(R.string.vault_details_type, type),
            size =
                entry.displaySize?.takeIf { display.showSize }?.let {
                    stringResource(
                        R.string.vault_details_size,
                        android.text.format.Formatter
                            .formatShortFileSize(context, it),
                    )
                },
            modified = null,
        )
        val availability =
            when {
                offline || entry.offlineAvailable == true -> R.string.vault_entry_offline_status
                entry.offlineAvailable == false -> R.string.vault_entry_cloud_only_status
                else -> R.string.vault_entry_online_unknown_status
            }
        Text(stringResource(availability))
        Text(stringResource(R.string.vault_preview_memory_only_note))
    }
}

@Composable
internal fun EncryptedNameDialog(
    title: String,
    initialValue: String,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit,
    hint: String? = null,
) {
    var value by remember { mutableStateOf(initialValue) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column {
                hint?.let { Text(it) }
                OutlinedTextField(value, onValueChange = { value = it }, singleLine = true)
            }
        },
        confirmButton = {
            Button(onClick = { onConfirm(value) }, enabled = value.isNotBlank() || hint != null) {
                Text(stringResource(R.string.vault_confirm))
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.vault_cancel)) } },
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
    )
}
