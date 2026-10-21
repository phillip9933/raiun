package eu.opencloud.android.next.feature.shares

import android.content.Intent
import android.graphics.Bitmap
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.InsertDriveFile
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.datastore.SettingsBrowserLayout
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.documentsprovider.sharedFileViewIntent
import eu.opencloud.android.next.core.model.fileMimeType
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.ui.BrowserContent
import eu.opencloud.android.next.core.ui.BrowserEntry
import eu.opencloud.android.next.core.ui.BrowserToolbar
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

@Composable
internal fun IncomingBrowserRoute(
    account: String,
    initialFolder: eu.opencloud.android.next.core.sync.SharedFolderRequest? = null,
    onConsumeInitialFolder: () -> Unit = {},
) {
    val context = LocalContext.current
    val owner = rememberCoroutineScope()
    var savedTrail by rememberSaveable(account) { mutableStateOf(emptyList<String>()) }
    val controller =
        remember(account) {
            val backend = AndroidIncomingBrowserBackend(context)
            IncomingBrowserController(
                owner,
                backend,
                errorMessage = { it.safeMessage(context) },
                onTrailChanged = { savedTrail = IncomingBrowserTrail.save(it) },
                performCopyAction = backend::changeCopy,
            )
        }
    val state by controller.state.collectAsState()
    var folderActions by remember(account) { mutableStateOf<IncomingBrowserItem.Folder?>(null) }
    var openError by remember(account) { mutableStateOf<String?>(null) }
    var preview by remember(account) { mutableStateOf<IncomingBrowserItem.File?>(null) }
    val settings by remember(context) {
        eu.opencloud.android.next.core.datastore.SettingsRepository
            .create(context)
            .settings
    }.collectAsState(
        initial =
            eu.opencloud.android.next.core.datastore
                .UserSettings(),
    )
    val fileActions = rememberIncomingFileActions { openError = it }
    val upload = incomingUploadPicker(state, controller) { openError = it }
    LaunchedEffect(controller) { controller.load(account, IncomingBrowserTrail.restore(account, savedTrail)) }
    val consumeInitialFolder by rememberUpdatedState(onConsumeInitialFolder)
    LaunchedEffect(controller, initialFolder) {
        if (initialFolder != null && initialFolder.account == account) {
            controller.openShortcut(
                IncomingBrowserItem.Folder(
                    initialFolder.path.substringAfterLast('/').ifBlank { "Shared folder" },
                    initialFolder,
                ),
            )
            consumeInitialFolder()
        }
    }
    DisposableEffect(controller) { onDispose { controller.clear() } }
    BackHandler(state.trail.isNotEmpty()) { controller.back() }
    preview?.let { item ->
        eu.opencloud.android.next.core.ui.FilePreviewRoute(
            item.name,
            requireNotNull(
                eu.opencloud.android.next.core.datastore
                    .previewKind(item.name, item.mimeType),
            ),
            onClose = { preview = null },
            onOpenWith = { fileActions(item, IncomingFileAction.OPEN_WITH) },
            load = { destination ->
                eu.opencloud.android.next.core.security
                    .AppLock(context)
                    .allowDocumentOpenFromApp()
                val uri =
                    requireNotNull(
                        sharedFileViewIntent(context, item.request, fileMimeType(item.name, item.mimeType)).data,
                    )
                eu.opencloud.android.next.core.ui.copyPreview(
                    requireNotNull(context.contentResolver.openInputStream(uri)),
                    destination,
                )
            },
        )
        return
    }
    folderActions?.let { folder ->
        IncomingFolderActions(folder, onOpen = {
            folderActions = null
            if (state.trail.lastOrNull()?.request != folder.request) controller.open(folder)
        }, onChange = controller::refresh, onClose = { folderActions = null })
    }
    IncomingBrowserScreen(
        state,
        controller::back,
        {
            openError = null
            controller.refresh()
        },
        { item ->
            openError = null
            when (item) {
                is IncomingBrowserItem.Folder -> controller.open(item)
                is IncomingBrowserItem.File -> {
                    if (settings.fileOpening.usesPreview(
                            eu.opencloud.android.next.core.datastore
                                .previewKind(item.name, item.mimeType),
                        )
                    ) {
                        preview = item
                    } else {
                        fileActions(item, IncomingFileAction.OPEN)
                    }
                }
            }
        },
        openError,
        controller::changeCopy,
        upload,
        layout = settings.browserLayout,
        onLayout = { layout ->
            owner.launch {
                eu.opencloud.android.next.core.datastore.SettingsRepository
                    .create(
                        context,
                    ).setBrowserLayout(layout)
            }
        },
        onFileAction = fileActions,
        onFolderActions = { folderActions = it },
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Suppress("LongParameterList") // Independent navigation, opening and local-copy actions.
fun IncomingBrowserScreen(
    state: IncomingBrowserState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onOpen: (IncomingBrowserItem) -> Unit,
    openError: String?,
    onCopyAction: (IncomingBrowserItem.File, SharedCopyAction) -> Unit,
    onUpload: () -> Unit,
    modifier: Modifier = Modifier,
    layout: SettingsBrowserLayout = SettingsBrowserLayout.DEFAULT_TABLE,
    onLayout: (SettingsBrowserLayout) -> Unit = {},
    onFileAction: (IncomingBrowserItem.File, IncomingFileAction) -> Unit = { _, _ -> },
    onFolderActions: (IncomingBrowserItem.Folder) -> Unit = {},
) {
    var showHidden by rememberSaveable(state.account) { mutableStateOf(false) }
    val displayedItems = state.items.filter { showHidden || !it.isHiddenFolder() }
    val displayedState = state.copy(items = displayedItems)
    val showEmpty = !state.loading && displayedItems.isEmpty()
    val showNotice = state.unavailable > 0 || openError != null || state.error != null || showEmpty
    Column(modifier.fillMaxSize()) {
        BrowserToolbar(
            state.trail.isNotEmpty(),
            layout,
            onBack,
            { onLayout(SettingsBrowserLayout.entries[(layout.ordinal + 1) % SettingsBrowserLayout.entries.size]) },
        ) {
            Text(
                state.trail.lastOrNull()?.name ?: stringResource(R.string.incoming_shared_folders),
                Modifier.weight(1f),
                maxLines = 1,
            )
            IconButton(onClick = onRefresh) {
                Icon(Icons.Default.Refresh, stringResource(R.string.incoming_refresh_folder))
            }
            state.trail.lastOrNull()?.let { folder ->
                FolderActionsButton(folder) { onFolderActions(folder) }
            }
            if (state.uploadDestination != null) {
                TextButton(onClick = onUpload) { Text(stringResource(R.string.incoming_upload)) }
            }
        }
        if (state.trail.isEmpty() && state.items.any { it.isHiddenFolder() }) {
            TextButton(onClick = { showHidden = !showHidden }) {
                Text(stringResource(if (showHidden) R.string.incoming_hide_hidden else R.string.incoming_show_hidden))
            }
        }
        PullToRefreshBox(isRefreshing = state.loading, onRefresh = onRefresh, modifier = Modifier.fillMaxSize()) {
            BrowserContent(
                displayedItems,
                ::incomingBrowserKey,
                layout,
                notice =
                    if (showNotice) {
                        { IncomingBrowserNotice(displayedState, openError, onRefresh) }
                    } else {
                        null
                    },
            ) { item ->
                IncomingBrowserRow(item, onOpen, onCopyAction, onFileAction, layout, onFolderActions)
            }
        }
    }
}

private fun incomingBrowserKey(item: IncomingBrowserItem): String =
    when (item) {
        is IncomingBrowserItem.Folder ->
            listOf(
                "folder",
                item.request.share,
                item.request.scope,
                item.request.remoteId,
            ).toString()
        is IncomingBrowserItem.File ->
            listOf(
                "file",
                item.request.shareId,
                item.request.scopeId,
                item.request.file.remoteId,
            ).toString()
    }

@Composable
private fun incomingUploadPicker(
    state: IncomingBrowserState,
    controller: IncomingBrowserController,
    onError: (String?) -> Unit,
): () -> Unit {
    val context = LocalContext.current
    val sourceAccessError = stringResource(R.string.incoming_upload_source_unavailable)
    var target by rememberSaveable(state.account) { mutableStateOf(emptyList<String>()) }
    val picker =
        rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            val destination = IncomingBrowserTrail.restore(state.account.orEmpty(), target).lastOrNull()?.request
            target = emptyList()
            if (uri != null && destination != null && destination == state.uploadDestination) {
                try {
                    context.contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    onError(null)
                    controller.upload(destination, uri.toString())
                } catch (_: SecurityException) {
                    onError(sourceAccessError)
                }
            }
        }
    return {
        target = IncomingBrowserTrail.save(state.trail)
        picker.launch(arrayOf("*/*"))
    }
}

@Composable
private fun IncomingBrowserNotice(
    state: IncomingBrowserState,
    openError: String?,
    onRefresh: () -> Unit,
) {
    Column(Modifier.padding(OpenCloudDimensions.SpacingMd)) {
        if (state.unavailable > 0) {
            Text(
                pluralStringResource(
                    R.plurals.incoming_unavailable_folders,
                    state.unavailable,
                    state.unavailable,
                ),
            )
        }
        val error = openError ?: state.error
        if (error != null) {
            Text(error)
            TextButton(onClick = onRefresh) { Text(stringResource(R.string.incoming_try_again)) }
        } else if (!state.loading && state.items.isEmpty()) {
            Text(
                stringResource(
                    if (state.trail.isEmpty()) R.string.incoming_no_shared_folders else R.string.incoming_empty_folder,
                ),
            )
        }
    }
}

@Composable
@Suppress("LongParameterList") // Distinct file/folder actions and browser presentation.
private fun IncomingBrowserRow(
    item: IncomingBrowserItem,
    onOpen: (IncomingBrowserItem) -> Unit,
    onCopyAction: (IncomingBrowserItem.File, SharedCopyAction) -> Unit,
    onFileAction: (IncomingBrowserItem.File, IncomingFileAction) -> Unit,
    layout: SettingsBrowserLayout,
    onFolderActions: (IncomingBrowserItem.Folder) -> Unit,
) {
    val context = LocalContext.current
    val videoThumbnail = incomingVideoThumbnail(context, item)
    BrowserEntry(
        layout = layout,
        onOpen = { onOpen(item) },
        name = { Text(item.name, maxLines = 1, overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis) },
        thumbnail = { modifier ->
            Box(modifier, contentAlignment = Alignment.Center) {
                val thumbnail = videoThumbnail
                if (thumbnail != null) {
                    Image(
                        thumbnail.asImageBitmap(),
                        contentDescription = null,
                        modifier =
                            if (layout == SettingsBrowserLayout.TILES) {
                                Modifier.fillMaxSize()
                            } else {
                                Modifier.size(OpenCloudDimensions.TouchTarget)
                            },
                        contentScale = ContentScale.Crop,
                    )
                } else {
                    Icon(
                        if (item is IncomingBrowserItem.Folder) {
                            Icons.Default.Folder
                        } else {
                            Icons.AutoMirrored.Filled.InsertDriveFile
                        },
                        contentDescription = null,
                        modifier = Modifier.size(OpenCloudDimensions.TouchTarget),
                        tint = androidx.compose.material3.MaterialTheme.colorScheme.primary,
                    )
                }
            }
        },
        metadata = {
            if (item is IncomingBrowserItem.Folder && item.hidden) Text(stringResource(R.string.incoming_hidden))
            if (item is IncomingBrowserItem.File) {
                Text(
                    stringResource(
                        when (item.localCopy?.offlinePinned) {
                            true -> R.string.incoming_copy_kept_online_required
                            false -> R.string.incoming_copy_temporary
                            null -> R.string.incoming_copy_cloud_only
                        },
                    ),
                    style = androidx.compose.material3.MaterialTheme.typography.bodySmall,
                )
            }
        },
        actions = {
            when (item) {
                is IncomingBrowserItem.File -> IncomingCopyMenu(item, onCopyAction, onFileAction)
                is IncomingBrowserItem.Folder -> FolderActionsButton(item) { onFolderActions(item) }
            }
        },
    )
}

@Composable
private fun incomingVideoThumbnail(
    context: android.content.Context,
    item: IncomingBrowserItem,
): Bitmap? {
    val thumbnail by produceState<Bitmap?>(null, item) {
        val file = item as? IncomingBrowserItem.File
        if (file == null || !file.isVideoPreview()) {
            value = null
            return@produceState
        }
        value =
            try {
                loadIncomingVideoThumbnail(context, file.request, file.localCopy != null)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                null
            }
    }
    return thumbnail
}

private fun IncomingBrowserItem.File.isVideoPreview(): Boolean =
    mimeType?.substringBefore(';')?.startsWith("video/", ignoreCase = true) == true ||
        name.substringAfterLast('.', "").lowercase() in
        setOf("3gp", "avi", "m4v", "mkv", "mov", "mp4", "mpeg", "mpg", "webm")

@Composable
private fun FolderActionsButton(
    folder: IncomingBrowserItem.Folder,
    onClick: () -> Unit,
) {
    IconButton(onClick = onClick) {
        Icon(Icons.Default.MoreVert, stringResource(R.string.shares_actions_for_file, folder.name))
    }
}

private fun IncomingBrowserItem.isHiddenFolder() = this is IncomingBrowserItem.Folder && hidden
