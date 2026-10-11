package eu.opencloud.android.next.feature.files

import android.content.Intent
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.DriveFileMove
import androidx.compose.material.icons.automirrored.filled.InsertDriveFile
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.CameraAlt
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.CloudSync
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Forum
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.OfflinePin
import androidx.compose.material.icons.filled.RadioButtonUnchecked
import androidx.compose.material.icons.filled.Remove
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Smartphone
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.outlined.People
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.LocalRippleConfiguration
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationDrawerItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.material3.rememberDrawerState
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.movableContentOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import eu.opencloud.android.next.core.database.FolderBackupEntity
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.database.TransferState
import eu.opencloud.android.next.core.datastore.FileDisplayOptions
import eu.opencloud.android.next.core.datastore.SettingsBrowserLayout
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudColor
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.sync.BackupExclusions
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.formatBackupDateFolder
import eu.opencloud.android.next.core.sync.isVideoPreview
import eu.opencloud.android.next.core.ui.BrowserAction
import eu.opencloud.android.next.core.ui.BrowserActionSheet
import eu.opencloud.android.next.core.ui.BrowserContent
import eu.opencloud.android.next.core.ui.BrowserEntry
import eu.opencloud.android.next.core.ui.BrowserToolbar
import kotlinx.coroutines.launch

@Composable
// Explicit browser action wiring.
@Suppress("FunctionNaming", "LongParameterList", "LongMethod", "ktlint:standard:function-naming")
fun FileBrowserRoute(
    accountId: String,
    releaseVersion: String,
    destinations: FileBrowserDestinations,
    sharesContent: @Composable (PaddingValues, (ResourceEntity) -> Unit) -> Unit,
    spacesContent: @Composable (PaddingValues, (String) -> Unit, Int) -> Unit,
    modifier: Modifier = Modifier,
    encryptedReturnRevision: Int = 0,
    openAddMenuRequest: Int = 0,
    onConsumeAddMenuRequest: () -> Unit = {},
    sharedShortcut: eu.opencloud.android.next.core.sync.SharedFolderRequest? = null,
    shortcutFolder: ResourceEntity? = null,
    onConsumeShortcutFolder: () -> Unit = {},
    viewModel: FileBrowserViewModel = viewModel(key = "files-$accountId"),
    favoritesViewModel: FavoritesViewModel = viewModel(key = "favorites-$accountId"),
) {
    val context = LocalContext.current
    val state by viewModel.state.collectAsStateWithLifecycle()
    val favoritesState by favoritesViewModel.state.collectAsStateWithLifecycle()
    val exportFile = rememberDeviceExportLauncher(accountId, viewModel, state.exporting)
    val openFile = rememberFileOpener(viewModel)
    val uploadLauncher = rememberFileUploadLauncher(viewModel)
    var scanTarget by rememberSaveable(accountId) { mutableStateOf<ArrayList<String>?>(null) }
    var previewTarget by remember(accountId) { mutableStateOf<ResourceEntity?>(null) }
    val openingSettings by remember(context) {
        eu.opencloud.android.next.core.datastore.SettingsRepository
            .create(context)
            .settings
    }.collectAsStateWithLifecycle(
        initialValue =
            eu.opencloud.android.next.core.datastore
                .UserSettings(),
    )
    viewModel.load(accountId)
    LaunchedEffect(accountId, encryptedReturnRevision) {
        if (encryptedReturnRevision > 0) viewModel.refresh()
    }
    favoritesViewModel.load(accountId)
    var folderOpenRequest by remember(accountId) { mutableIntStateOf(0) }
    ApplyFolderShortcut(shortcutFolder, state.spaces, accountId) {
        viewModel.browseSharedResource(it)
        folderOpenRequest++
        onConsumeShortcutFolder()
    }
    scanTarget?.let { target ->
        ScannerRoute(target, onClose = { scanTarget = null })
        return
    }
    Box(modifier) {
        FileBrowserScreen(
            accountId = accountId,
            releaseVersion = releaseVersion,
            openAddMenuRequest = openAddMenuRequest,
            openFolderRequest = folderOpenRequest,
            onConsumeAddMenuRequest = onConsumeAddMenuRequest,
            state = state,
            favoritesState = favoritesState,
            onSelectSpace = viewModel::selectSpace,
            onOpen = {
                if (it.kind == ResourceKind.FOLDER) {
                    viewModel.open(it)
                } else if (openingSettings.fileOpening.usesPreview(
                        eu.opencloud.android.next.core.datastore
                            .previewKind(it.name, it.mimeType),
                    )
                ) {
                    previewTarget = it
                } else {
                    openFile(it, ExternalAction.OPEN)
                }
            },
            onPrepareDetails = viewModel::prepareExternalFile,
            onOpenWith = { openFile(it, ExternalAction.OPEN_WITH) },
            onSend = { openFile(it, ExternalAction.SEND) },
            onExport = exportFile,
            onDismissExportStatus = viewModel::dismissExportStatus,
            onRefresh = viewModel::refresh,
            onMoveSelection = viewModel::moveSelection,
            onCopySelection = viewModel::copySelection,
            onFavoriteSelection = viewModel::favoriteSelection,
            onRemoveLocalSelection = viewModel::removeSelectedLocalCopies,
            onNavigateUp = viewModel::navigateUp,
            onSetLayout = viewModel::setLayout,
            onToggleSelection = viewModel::toggleSelection,
            onClearSelection = viewModel::clearSelection,
            onDownloadSelection = viewModel::downloadSelection,
            onDeleteSelection = viewModel::deleteSelected,
            onShowActions = viewModel::showActions,
            onDismissActions = viewModel::dismissActions,
            onCreateFolder = viewModel::createFolder,
            onCreateSpace = viewModel::createSpace,
            onCreateEncryptedFolder = viewModel::createEncryptedFolder,
            onCreateEncryptedSpace = viewModel::createEncryptedSpace,
            onRename = viewModel::rename,
            onMove = viewModel::move,
            onCopy = viewModel::copy,
            operationControls = {
                FileOperationControls(
                    state,
                    viewModel::place,
                    viewModel::cancelPlacement,
                    viewModel::retryOperation,
                    viewModel::dismissOperation,
                    viewModel::keepBothPlacementConflict,
                )
            },
            onDelete = viewModel::delete,
            onUpload = { uploadLauncher.launch(arrayOf("*/*")) },
            onScan = {
                state.spaceId?.let { space ->
                    scanTarget =
                        arrayListOf(
                            accountId,
                            space,
                            state.folderTrail.joinToString("/", "/") {
                                it.name
                            },
                            java.util.UUID
                                .randomUUID()
                                .toString(),
                        )
                }
            },
            onDownloadForOffline = viewModel::downloadForOffline,
            onRemoveLocalCopy = viewModel::removeLocalCopy,
            onToggleFavorite = viewModel::toggleFavorite,
            onResolveConflict = viewModel::resolveConflict,
            onClearMessage = viewModel::clearMessage,
            onSearchQueryChange = viewModel::setSearchQuery,
            onOpenTransfers = destinations.onOpenTransfers,
            onRemoveFavorite = favoritesViewModel::remove,
            onDismissFavoriteError = favoritesViewModel::dismissError,
            onRefreshFavorites = favoritesViewModel::refresh,
            onOpenDeletedFiles = destinations.onOpenDeletedFiles,
            onOpenSettings = destinations.onOpenSettings,
            onOpenVaults = destinations.onOpenVaults,
            onOpenEncryptedOffline = destinations.onOpenEncryptedOffline,
            onOpenEncryptedLocation = destinations.onOpenEncryptedLocation,
            onEncryptedLocationActions = destinations.onEncryptedLocationActions,
            onOpenAccount = destinations.onOpenAccount,
            onShareResource = destinations.onShareResource,
            sharedShortcut = sharedShortcut,
            notifications = { openShares -> ServerNotificationsBell(accountId, openShares) },
            sharesContent = sharesContent,
            onBrowseShare = viewModel::browseSharedResource,
            spacesContent = spacesContent,
        )
        previewTarget?.let { target ->
            androidx.compose.runtime.key(target.accountId, target.spaceId, target.remoteId) {
                FileReadingRoute(
                    target,
                    viewModel::prepareExternalFile,
                    viewModel::recordOpened,
                    { previewTarget = null },
                    { openFile(target, ExternalAction.OPEN_WITH) },
                )
            }
        }
    }
}

@Composable
private fun rememberFileUploadLauncher(
    viewModel: FileBrowserViewModel,
): androidx.activity.result.ActivityResultLauncher<Array<String>> {
    val context = LocalContext.current
    val mediaPermission = rememberOriginalMediaPermission { files -> files.forEach(viewModel::upload) }
    return rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let { selected ->
            runCatching {
                context.contentResolver.takePersistableUriPermission(selected, Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            mediaPermission(listOf(selected))
        }
    }
}

data class FileBrowserDestinations(
    val onOpenTransfers: () -> Unit,
    val onOpenDeletedFiles: () -> Unit,
    val onOpenSettings: () -> Unit,
    val onOpenAccount: () -> Unit,
    val onShareResource: (ResourceEntity) -> Unit,
    val onOpenVaults: (() -> Unit)? = null,
    val onOpenEncryptedOffline: (() -> Unit)? = null,
    val onOpenEncryptedLocation: (VaultLocation) -> Unit = {},
    val onEncryptedLocationActions: (VaultLocation) -> Unit = {},
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Suppress("ComposableParamOrder", "CyclomaticComplexMethod", "LongMethod", "LongParameterList")
fun FileBrowserScreen(
    accountId: String,
    releaseVersion: String,
    state: FileBrowserUiState,
    favoritesState: FavoritesUiState = FavoritesUiState(),
    onSelectSpace: (String) -> Unit,
    onOpen: (ResourceEntity) -> Unit,
    onNavigateUp: () -> Unit,
    onSetLayout: (BrowserLayout) -> Unit,
    onToggleSelection: (String) -> Unit,
    onClearSelection: () -> Unit,
    onDownloadSelection: () -> Unit,
    onDeleteSelection: () -> Unit,
    onShowActions: (ResourceEntity?) -> Unit,
    onDismissActions: () -> Unit,
    onCreateFolder: (String) -> Unit,
    onCreateSpace: (String) -> Unit,
    onRename: (ResourceEntity, String) -> Unit,
    onMove: (ResourceEntity) -> Unit,
    onCopy: (ResourceEntity) -> Unit,
    onDelete: (ResourceEntity) -> Unit,
    onUpload: () -> Unit,
    onDownloadForOffline: (ResourceEntity) -> Unit,
    onToggleFavorite: (ResourceEntity) -> Unit,
    onResolveConflict: (TransferEntity, ConflictDecision) -> Unit,
    onClearMessage: () -> Unit,
    onSearchQueryChange: (String) -> Unit,
    onOpenTransfers: () -> Unit,
    onRemoveFavorite: (ResourceEntity) -> Unit = {},
    onDismissFavoriteError: () -> Unit = {},
    onRefreshFavorites: () -> Unit = {},
    onOpenDeletedFiles: () -> Unit,
    onOpenSettings: () -> Unit,
    onOpenVaults: (() -> Unit)? = null,
    onOpenEncryptedOffline: (() -> Unit)? = null,
    onOpenEncryptedLocation: (VaultLocation) -> Unit = {},
    onEncryptedLocationActions: (VaultLocation) -> Unit = {},
    onOpenAccount: () -> Unit,
    onShareResource: (ResourceEntity) -> Unit,
    sharesContent: @Composable (PaddingValues, (ResourceEntity) -> Unit) -> Unit = { _, _ -> },
    spacesContent: @Composable (PaddingValues, (String) -> Unit, Int) -> Unit = { _, _, _ -> },
    sharedShortcut: eu.opencloud.android.next.core.sync.SharedFolderRequest? = null,
    notifications: @Composable (() -> Unit) -> Unit = {},
    modifier: Modifier = Modifier,
    initialDestination: FileBrowserDestination = FileBrowserDestination.Personal,
    openFolderRequest: Int = 0,
    openAddMenuRequest: Int = 0,
    onConsumeAddMenuRequest: () -> Unit = {},
    onCreateEncryptedFolder: ((String, CharArray) -> Unit)? = null,
    onCreateEncryptedSpace: ((String, CharArray) -> Unit)? = null,
    operationControls: @Composable () -> Unit = {},
    onOpenWith: (ResourceEntity) -> Unit = {},
    onSend: (ResourceEntity) -> Unit = {},
    onPrepareDetails: (suspend (ResourceEntity) -> ResourceEntity)? = null,
    onRefresh: () -> Unit = {},
    onMoveSelection: () -> Unit = {},
    onCopySelection: () -> Unit = {},
    onFavoriteSelection: () -> Unit = {},
    onRemoveLocalSelection: () -> Unit = {},
    onBrowseShare: (ResourceEntity) -> Unit = {},
    onExport: (ResourceEntity, Boolean) -> Unit = { _, _ -> },
    onDismissExportStatus: () -> Unit = {},
    onRemoveLocalCopy: (ResourceEntity) -> Unit = {},
    onScan: () -> Unit = {},
) {
    var dialog by remember { mutableStateOf<BrowserDialog?>(null) }
    var offlineFilter by rememberSaveable(accountId) { mutableStateOf(OfflineFilter.ALL) }
    var details by remember { mutableStateOf<ResourceEntity?>(null) }
    var expandedAdd by rememberSaveable { mutableStateOf(false) }
    var sortCriterion by rememberSaveable(accountId) { mutableStateOf(BrowserSortCriterion.Name) }
    var sortAscending by rememberSaveable(accountId) { mutableStateOf(true) }
    var showSortMenu by remember { mutableStateOf(false) }
    var favoritesQuery by rememberSaveable(accountId) { mutableStateOf("") }
    // Keep the in-session tab selection through recomposition, but start a fresh app launch
    // on Personal instead of restoring a previously selected Space.
    var selectedDestination by remember(accountId) { mutableStateOf(initialDestination) }
    val currentNotifications by rememberUpdatedState(notifications)
    val notificationContent =
        remember(accountId) {
            movableContentOf { currentNotifications { selectedDestination = FileBrowserDestination.Shares } }
        }
    LaunchedEffect(sharedShortcut) {
        if (sharedShortcut != null) selectedDestination = FileBrowserDestination.Shares
    }
    LaunchedEffect(openFolderRequest) {
        if (openFolderRequest > 0) selectedDestination = FileBrowserDestination.Personal
    }
    var appliedPersonalRequest by remember(accountId) { mutableIntStateOf(0) }
    val currentOnSelectSpace by rememberUpdatedState(onSelectSpace)
    val currentOnConsumeAddMenuRequest by rememberUpdatedState(onConsumeAddMenuRequest)
    LaunchedEffect(openAddMenuRequest) {
        if (openAddMenuRequest > 0) {
            selectedDestination = FileBrowserDestination.Personal
            expandedAdd = true
        }
    }
    LaunchedEffect(openAddMenuRequest, state.spaces) {
        if (openAddMenuRequest > appliedPersonalRequest) {
            state.spaces.firstOrNull { it.type.equals("personal", ignoreCase = true) }?.let { personal ->
                currentOnSelectSpace(personal.driveId)
                appliedPersonalRequest = openAddMenuRequest
                currentOnConsumeAddMenuRequest()
            }
        }
    }
    val activeProjectSpace = state.spaces.firstOrNull { it.driveId == state.spaceId && it.type == "project" }
    val browsingProjectSpace = selectedDestination == FileBrowserDestination.Personal && activeProjectSpace != null
    val browserDestination =
        selectedDestination == FileBrowserDestination.Personal ||
            selectedDestination == FileBrowserDestination.Favorites ||
            selectedDestination == FileBrowserDestination.Offline ||
            selectedDestination == FileBrowserDestination.Recents
    val selectionMode =
        selectedDestination in setOf(FileBrowserDestination.Personal, FileBrowserDestination.Offline) &&
            state.selectedIds.isNotEmpty()
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val drawerState = rememberDrawerState(DrawerValue.Closed)
    val scope = rememberCoroutineScope()
    val visibleResources =
        remember(state.resources, state.searchQuery, state.searchResults, sortCriterion, sortAscending) {
            val source = if (state.searchQuery.isBlank()) state.resources else state.searchResults
            source
                .sortedWith(sortCriterion.comparator(sortAscending))
        }
    val visibleFavorites =
        remember(favoritesState.resources, favoritesQuery, sortCriterion, sortAscending) {
            favoritesState.resources
                .filter { resource ->
                    favoritesQuery.isBlank() || resource.name.contains(favoritesQuery, ignoreCase = true)
                }.sortedWith(sortCriterion.comparator(sortAscending))
        }

    BackHandler(
        enabled =
            drawerState.isOpen ||
                selectionMode ||
                expandedAdd ||
                state.searchQuery.isNotEmpty() ||
                selectedDestination != FileBrowserDestination.Personal ||
                state.folderTrail.isNotEmpty() ||
                browsingProjectSpace,
    ) {
        when {
            drawerState.isOpen -> scope.launch { drawerState.close() }
            expandedAdd -> expandedAdd = false
            selectionMode -> onClearSelection()
            state.searchQuery.isNotEmpty() -> onSearchQueryChange("")
            selectedDestination != FileBrowserDestination.Personal ->
                selectedDestination =
                    FileBrowserDestination.Personal
            browsingProjectSpace && state.folderTrail.isEmpty() -> selectedDestination = FileBrowserDestination.Spaces
            else -> onNavigateUp()
        }
    }

    ModalNavigationDrawer(
        drawerState = drawerState,
        gesturesEnabled = !selectionMode,
        drawerContent = {
            BrowserNavigationDrawer(
                releaseVersion = releaseVersion,
                selectedDestination = selectedDestination,
                onRecents = {
                    onClearSelection()
                    selectedDestination = FileBrowserDestination.Recents
                    scope.launch { drawerState.close() }
                },
                onOffline = {
                    onClearSelection()
                    selectedDestination = FileBrowserDestination.Offline
                    scope.launch { drawerState.close() }
                },
                onShares = {
                    onClearSelection()
                    selectedDestination = FileBrowserDestination.Shares
                    scope.launch { drawerState.close() }
                },
                personalSpace = state.spaces.firstOrNull { it.type == "personal" },
                onTransfers = {
                    scope.launch { drawerState.close() }
                    onOpenTransfers()
                },
                onDeletedFiles = {
                    scope.launch { drawerState.close() }
                    onOpenDeletedFiles()
                },
                onSettings = {
                    scope.launch { drawerState.close() }
                    onOpenSettings()
                },
                onVaults =
                    onOpenVaults?.let { open ->
                        {
                            scope.launch { drawerState.close() }
                            onClearSelection()
                            open()
                        }
                    },
            )
        },
    ) {
        Scaffold(
            modifier = modifier,
            topBar = {
                Column {
                    if (selectionMode) {
                        Column {
                            SelectionTopAppBar(
                                selectedCount = state.selectedIds.size,
                                onClearSelection = onClearSelection,
                                onDownloadSelection = onDownloadSelection,
                            )
                            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                                SelectionAction(
                                    stringResource(R.string.browser_move),
                                    Icons.AutoMirrored.Filled.DriveFileMove,
                                    stringResource(R.string.browser_move_selected),
                                    onMoveSelection,
                                )
                                SelectionAction(
                                    stringResource(R.string.browser_copy),
                                    Icons.Default.ContentCopy,
                                    stringResource(R.string.browser_copy_selected),
                                    onCopySelection,
                                )
                                SelectionAction(
                                    stringResource(R.string.browser_favorite),
                                    Icons.Default.Star,
                                    stringResource(R.string.browser_favorite_selected),
                                    onFavoriteSelection,
                                )
                                SelectionAction(
                                    stringResource(R.string.browser_delete),
                                    Icons.Default.Delete,
                                    stringResource(R.string.browser_delete_selected),
                                    onDeleteSelection,
                                )
                                if ((state.resources + state.searchResults + state.offlineResources).any {
                                        it.selectionKey in state.selectedIds &&
                                            it.hasLocalCopy
                                    }
                                ) {
                                    SelectionAction(
                                        stringResource(R.string.browser_clear_local),
                                        cleanupIcon(),
                                        stringResource(R.string.browser_delete_local_copies),
                                        onRemoveLocalSelection,
                                    )
                                }
                            }
                            Surface(
                                modifier = Modifier.fillMaxWidth(),
                                color = MaterialTheme.colorScheme.surface,
                            ) {
                                Column {
                                    if (browsingProjectSpace) {
                                        ProjectSpaceHeader(requireNotNull(activeProjectSpace).name, state.folderTrail) {
                                            onClearSelection()
                                            selectedDestination = FileBrowserDestination.Spaces
                                        }
                                    }
                                    BrowserSubHeader(
                                        canNavigateUp = state.folderTrail.isNotEmpty(),
                                        layout = state.layout,
                                        sortCriterion = sortCriterion,
                                        sortAscending = sortAscending,
                                        showSortMenu = showSortMenu,
                                        onNavigateUp = onNavigateUp,
                                        onShowSortMenu = { showSortMenu = true },
                                        onDismissSortMenu = { showSortMenu = false },
                                        onSortSelect = { criterion ->
                                            if (sortCriterion == criterion) {
                                                sortAscending = !sortAscending
                                            } else {
                                                sortCriterion = criterion
                                                sortAscending = true
                                            }
                                            showSortMenu = false
                                        },
                                        onToggleLayout = {
                                            onSetLayout(state.layout.next())
                                        },
                                    )
                                    ExportStatus(state, onDismissExportStatus)
                                }
                            }
                        }
                    } else if (browserDestination) {
                        Column {
                            BrowserTopAppBar(
                                accountId = accountId,
                                query =
                                    if (selectedDestination == FileBrowserDestination.Favorites) {
                                        favoritesQuery
                                    } else {
                                        state.searchQuery
                                    },
                                onQueryChange =
                                    if (selectedDestination == FileBrowserDestination.Favorites) {
                                        { favoritesQuery = it }
                                    } else {
                                        onSearchQueryChange
                                    },
                                onOpenDrawer = { scope.launch { drawerState.open() } },
                                onOpenAccount = onOpenAccount,
                                notifications = notificationContent,
                            )
                            if (selectedDestination in
                                setOf(FileBrowserDestination.Offline, FileBrowserDestination.Recents)
                            ) {
                                Text(
                                    stringResource(selectedDestination.labelResource),
                                    Modifier.padding(horizontal = OpenCloudDimensions.SpacingMd),
                                    style = MaterialTheme.typography.titleMedium,
                                )
                            }
                            Surface(
                                modifier = Modifier.fillMaxWidth(),
                                color = MaterialTheme.colorScheme.surface,
                            ) {
                                Column {
                                    if (browsingProjectSpace) {
                                        ProjectSpaceHeader(requireNotNull(activeProjectSpace).name, state.folderTrail) {
                                            onClearSelection()
                                            selectedDestination = FileBrowserDestination.Spaces
                                        }
                                    }
                                    BrowserSubHeader(
                                        canNavigateUp =
                                            selectedDestination == FileBrowserDestination.Personal &&
                                                state.folderTrail.isNotEmpty(),
                                        layout = state.layout,
                                        sortCriterion = sortCriterion,
                                        sortAscending = sortAscending,
                                        showSortMenu = showSortMenu,
                                        onNavigateUp = onNavigateUp,
                                        onShowSortMenu = { showSortMenu = true },
                                        onDismissSortMenu = { showSortMenu = false },
                                        onSortSelect = { criterion ->
                                            if (sortCriterion == criterion) {
                                                sortAscending = !sortAscending
                                            } else {
                                                sortCriterion = criterion
                                                sortAscending = true
                                            }
                                            showSortMenu = false
                                        },
                                        onToggleLayout = {
                                            onSetLayout(state.layout.next())
                                        },
                                    )
                                    if (
                                        selectedDestination == FileBrowserDestination.Personal &&
                                        state.searchQuery.isNotBlank() &&
                                        state.isRemoteSearchLoading
                                    ) {
                                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                                    }
                                    if (selectedDestination == FileBrowserDestination.Personal) {
                                        ExportStatus(state, onDismissExportStatus)
                                        state.discoveryError?.let { message ->
                                            Text(
                                                stringResource(R.string.browser_refresh_failed, message),
                                                modifier = Modifier.padding(horizontal = OpenCloudDimensions.SpacingMd),
                                                style = MaterialTheme.typography.bodySmall,
                                                color = MaterialTheme.colorScheme.error,
                                            )
                                        }
                                    }
                                    if (selectedDestination == FileBrowserDestination.Favorites) {
                                        FavoritesSyncNotice(
                                            favoritesState.syncStatus,
                                            onRefreshFavorites,
                                            favoritesState.refreshError,
                                        )
                                    }
                                }
                            }
                        }
                    } else {
                        DestinationTopAppBar(
                            title = stringResource(selectedDestination.labelResource),
                            accountId = accountId,
                            onOpenDrawer = { scope.launch { drawerState.open() } },
                            onOpenAccount = onOpenAccount,
                            notifications = notificationContent,
                        )
                    }
                    TransferSummary(state.transfers, onOpenTransfers)
                }
            },
            bottomBar = {
                Column {
                    operationControls()
                    BrowserBottomNavigation(
                        selectedDestination =
                            if (browsingProjectSpace) FileBrowserDestination.Spaces else selectedDestination,
                        onPersonal = {
                            onClearSelection()
                            selectedDestination = FileBrowserDestination.Personal
                            state.spaces.firstOrNull { it.type == "personal" }?.let { onSelectSpace(it.driveId) }
                        },
                        onFavorites = {
                            onClearSelection()
                            selectedDestination = FileBrowserDestination.Favorites
                        },
                        onSpaces = {
                            onClearSelection()
                            selectedDestination = FileBrowserDestination.Spaces
                        },
                    )
                }
            },
            floatingActionButton = {
                if (selectedDestination == FileBrowserDestination.Spaces) {
                    FloatingActionButton(onClick = { dialog = BrowserDialog.CreateSpace }) {
                        Icon(Icons.Default.Add, stringResource(R.string.browser_create_space))
                    }
                } else if (!selectionMode && selectedDestination != FileBrowserDestination.Shares) {
                    Column(
                        horizontalAlignment = Alignment.End,
                        verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
                    ) {
                        if (expandedAdd) {
                            val uploadActionLabel = stringResource(R.string.browser_upload_file)
                            val scanActionLabel = stringResource(R.string.browser_scan)
                            val destinationSpace = state.spaces.firstOrNull { it.driveId == state.spaceId }
                            Surface(
                                shape = MaterialTheme.shapes.medium,
                                color = MaterialTheme.colorScheme.surfaceContainerHigh,
                            ) {
                                TextButton(onClick = { selectedDestination = FileBrowserDestination.Personal }) {
                                    Text(
                                        stringResource(
                                            R.string.browser_add_destination,
                                            (listOfNotNull(destinationSpace?.name) + state.folderTrail.map { it.name })
                                                .joinToString(" / "),
                                        ),
                                    )
                                }
                            }
                            ExtendedFloatingActionButton(
                                onClick = {
                                    expandedAdd = false
                                    onUpload()
                                },
                                icon = {
                                    Icon(
                                        Icons.Default.CloudUpload,
                                        null,
                                    )
                                },
                                text = { Text(stringResource(R.string.browser_upload_file)) },
                                modifier =
                                    Modifier.semantics { contentDescription = uploadActionLabel },
                            )
                            ExtendedFloatingActionButton(
                                onClick = {
                                    expandedAdd = false
                                    onScan()
                                },
                                icon = { Icon(Icons.Default.CameraAlt, null) },
                                text = { Text(scanActionLabel) },
                                modifier = Modifier.semantics { contentDescription = scanActionLabel },
                            )
                            ExtendedFloatingActionButton(onClick = {
                                expandedAdd = false
                                dialog =
                                    BrowserDialog.CreateFolder
                            }, icon = {
                                Icon(
                                    Icons.Default.Folder,
                                    null,
                                )
                            }, text = { Text(stringResource(R.string.browser_create_folder)) })
                            ExtendedFloatingActionButton(onClick = {
                                expandedAdd = false
                                dialog =
                                    BrowserDialog.CreateSpace
                            }, icon = {
                                Icon(
                                    Icons.Default.Apps,
                                    null,
                                )
                            }, text = { Text(stringResource(R.string.browser_create_space)) })
                        }
                        FloatingActionButton(onClick = { expandedAdd = !expandedAdd }) {
                            Icon(
                                if (expandedAdd) Icons.Default.Close else Icons.Default.Add,
                                contentDescription =
                                    stringResource(
                                        if (expandedAdd) R.string.browser_close_new_actions else R.string.browser_new,
                                    ),
                            )
                        }
                    }
                }
            },
        ) { outerPadding ->
            if (selectedDestination == FileBrowserDestination.Shares) {
                sharesContent(outerPadding) { resource ->
                    onClearSelection()
                    selectedDestination = FileBrowserDestination.Personal
                    onBrowseShare(resource)
                }
            } else if (selectedDestination == FileBrowserDestination.Spaces) {
                spacesContent(
                    outerPadding,
                    { spaceId ->
                        onClearSelection()
                        selectedDestination = FileBrowserDestination.Personal
                        onSelectSpace(spaceId)
                    },
                    state.encryptedSpaceCreationRevision,
                )
            } else {
                PullToRefreshBox(
                    isRefreshing =
                        if (selectedDestination ==
                            FileBrowserDestination.Favorites
                        ) {
                            favoritesState.syncStatus == FavoritesSyncStatus.RUNNING
                        } else {
                            delayedRefreshIndicator(state.refreshing, state.spaceId to state.currentFolderId)
                        },
                    onRefresh =
                        if (selectedDestination ==
                            FileBrowserDestination.Favorites
                        ) {
                            onRefreshFavorites
                        } else {
                            onRefresh
                        },
                    modifier = Modifier.fillMaxSize().padding(outerPadding),
                ) {
                    val padding = PaddingValues(OpenCloudDimensions.Zero)
                    val resources =
                        if (selectedDestination == FileBrowserDestination.Favorites) {
                            visibleFavorites
                        } else if (selectedDestination == FileBrowserDestination.Offline) {
                            state.offlineResources
                                .filter {
                                    it.name.contains(state.searchQuery, true) &&
                                        offlineFilter.matches(it, state.offlinePins)
                                }.sortedWith(sortCriterion.comparator(sortAscending))
                        } else if (selectedDestination == FileBrowserDestination.Recents) {
                            state.recentResources.filter { it.name.contains(state.searchQuery, true) }
                        } else {
                            visibleResources
                        }
                    val displayedResources =
                        resources.filter {
                            state.fileDisplay.showHidden ||
                                !it.name.startsWith(
                                    ".",
                                )
                        }
                    val encryptedFolders =
                        if (selectedDestination == FileBrowserDestination.Personal &&
                            state.searchQuery.isBlank()
                        ) {
                            state.encryptedFolders.filter { state.fileDisplay.showHidden || !it.title.startsWith(".") }
                        } else {
                            emptyList()
                        }
                    Column(Modifier.fillMaxSize()) {
                        if (selectedDestination == FileBrowserDestination.Personal) {
                            state.encryptedFoldersError?.let {
                                Text(
                                    stringResource(R.string.browser_encrypted_load_failed),
                                    Modifier.padding(OpenCloudDimensions.SpacingMd),
                                )
                            }
                        }
                        if (selectedDestination == FileBrowserDestination.Offline) {
                            onOpenEncryptedOffline?.let { open ->
                                Button(onClick = open, modifier = Modifier.fillMaxWidth()) {
                                    Icon(Icons.Default.Lock, contentDescription = null)
                                    Spacer(Modifier.width(OpenCloudDimensions.SpacingSm))
                                    Text(stringResource(R.string.browser_encrypted_offline))
                                }
                            }
                            OfflineHeader(state.offlineBytes, offlineFilter) {
                                offlineFilter = it
                                onClearSelection()
                            }
                        }
                        Box(Modifier.weight(1f)) {
                            if (selectedDestination == FileBrowserDestination.Favorites &&
                                displayedResources.isEmpty()
                            ) {
                                FavoritesEmpty(contentPadding = padding)
                            } else if (displayedResources.isEmpty() &&
                                selectedDestination in
                                setOf(FileBrowserDestination.Offline, FileBrowserDestination.Recents)
                            ) {
                                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                                    Text(
                                        if (selectedDestination ==
                                            FileBrowserDestination.Offline
                                        ) {
                                            stringResource(R.string.browser_no_downloaded_files)
                                        } else {
                                            stringResource(R.string.browser_opened_files_offline)
                                        },
                                    )
                                }
                            } else if (state.layout == BrowserLayout.TILES) {
                                BrowserGrid(
                                    offlinePins = state.offlinePins,
                                    resources = displayedResources,
                                    encryptedFolders = encryptedFolders,
                                    onOpenEncryptedLocation = onOpenEncryptedLocation,
                                    onEncryptedLocationActions = onEncryptedLocationActions,
                                    sortCriterion = sortCriterion,
                                    sortAscending = sortAscending,
                                    display = state.fileDisplay,
                                    selectedIds = state.selectedIds,
                                    selectionMode = selectionMode,
                                    contentPadding = padding,
                                    onOpen = onOpen,
                                    onToggleSelection = onToggleSelection,
                                    onShowActions = onShowActions,
                                )
                            } else {
                                BrowserList(
                                    offlinePins = state.offlinePins,
                                    resources = displayedResources,
                                    encryptedFolders = encryptedFolders,
                                    onOpenEncryptedLocation = onOpenEncryptedLocation,
                                    onEncryptedLocationActions = onEncryptedLocationActions,
                                    sortCriterion = sortCriterion,
                                    sortAscending = sortAscending,
                                    display = state.fileDisplay,
                                    selectedIds = state.selectedIds,
                                    selectionMode = selectionMode,
                                    condensed = state.layout == BrowserLayout.CONDENSED_TABLE,
                                    contentPadding = padding,
                                    onOpen = onOpen,
                                    onToggleSelection = onToggleSelection,
                                    onShowActions = onShowActions,
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    state.transfers.firstOrNull { it.state == TransferState.CONFLICT.name }?.let { conflict ->
        ConflictResolutionDialog(conflict = conflict, onDecision = { onResolveConflict(conflict, it) })
    }
    state.message?.let { BrowserNotice(stringResource(R.string.browser_notice), it, onClearMessage) }
    details?.let { resource ->
        ResourceDetailsDialog(
            resource = resource,
            options =
                ResourceDetailsOptions(
                    keptOffline = isKeptOffline(resource, state.offlinePins),
                    retentionHours = state.temporaryCopyRetentionHours,
                    display = state.fileDisplay,
                ),
            onDismiss = {
                details =
                    null
            },
            prepareFile = onPrepareDetails,
        )
    }
    state.error?.let { BrowserNotice(stringResource(R.string.browser_file_operation), it, onClearMessage) }
    favoritesState.error?.let { BrowserNotice(stringResource(R.string.browser_favorites), it, onDismissFavoriteError) }
    state.actionResource?.let { resource ->
        ResourceActionSheet(
            resource = resource,
            onDismiss = onDismissActions,
            onRename = {
                dialog = BrowserDialog.Rename(resource)
                onDismissActions()
            },
            onMove = { onMove(resource) },
            onCopy = { onCopy(resource) },
            onDownloadForOffline = { onDownloadForOffline(resource) },
            keptOffline = isKeptOffline(resource, state.offlinePins),
            onRemoveLocalCopy = { onRemoveLocalCopy(resource) },
            onToggleFavorite = {
                if (selectedDestination == FileBrowserDestination.Favorites) {
                    onRemoveFavorite(resource)
                } else {
                    onToggleFavorite(resource)
                }
            },
            onShare = {
                onDismissActions()
                onShareResource(resource)
            },
            onDelete = { onDelete(resource) },
            sheetState = sheetState,
            onOpenWith =
                if (resource.kind ==
                    ResourceKind.FILE
                ) {
                    (
                        {
                            onDismissActions()
                            onOpenWith(resource)
                        }
                    )
                } else {
                    null
                },
            onSend =
                if (resource.kind == ResourceKind.FILE) {
                    (
                        {
                            onDismissActions()
                            onSend(resource)
                        }
                    )
                } else {
                    null
                },
            onDetails = {
                onDismissActions()
                details = resource
            },
            onExport =
                if (resource.kind == ResourceKind.FILE) {
                    { move ->
                        onDismissActions()
                        onExport(resource, move)
                    }
                } else {
                    null
                },
        )
    }
    when (val currentDialog = dialog) {
        BrowserDialog.New ->
            AlertDialog(
                onDismissRequest = { dialog = null },
                title = { Text(stringResource(R.string.browser_new)) },
                text = {
                    Column {
                        SheetAction(stringResource(R.string.browser_upload_file), Icons.Default.CloudUpload) {
                            dialog = null
                            onUpload()
                        }
                        SheetAction(stringResource(R.string.browser_create_folder), Icons.Default.Folder) {
                            dialog =
                                BrowserDialog.CreateFolder
                        }
                        SheetAction(stringResource(R.string.browser_create_space), Icons.Default.Apps) {
                            dialog =
                                BrowserDialog.CreateSpace
                        }
                    }
                },
                confirmButton = {},
                dismissButton = {
                    TextButton(
                        onClick = { dialog = null },
                    ) { Text(stringResource(R.string.browser_cancel)) }
                },
            )
        BrowserDialog.CreateFolder ->
            BrowserCreationDialog(
                title = stringResource(R.string.browser_new_folder),
                encryptLabel = stringResource(R.string.browser_encrypt_folder),
                onPlainCreate = onCreateFolder,
                onEncryptedCreate = onCreateEncryptedFolder,
                onDismiss = { dialog = null },
                busy = state.encryptedCreationBusy,
            )
        BrowserDialog.CreateSpace ->
            BrowserCreationDialog(
                title = stringResource(R.string.browser_new_space),
                encryptLabel = stringResource(R.string.browser_encrypt_space),
                onPlainCreate = onCreateSpace,
                onEncryptedCreate = onCreateEncryptedSpace,
                onDismiss = { dialog = null },
                busy = state.encryptedCreationBusy,
            )
        is BrowserDialog.Rename ->
            NameDialog(
                title = stringResource(R.string.browser_rename),
                confirm = stringResource(R.string.browser_save),
                onDismiss = { dialog = null },
                initial = currentDialog.resource.name,
            ) { name ->
                onRename(currentDialog.resource, name)
                dialog = null
            }
        null -> Unit
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Suppress("LongParameterList")
private fun BrowserTopAppBar(
    accountId: String,
    query: String,
    onQueryChange: (String) -> Unit,
    onOpenDrawer: () -> Unit,
    onOpenAccount: () -> Unit,
    notifications: @Composable () -> Unit,
) = TopAppBar(
    title = {
        TextField(
            value = query,
            onValueChange = onQueryChange,
            modifier =
                Modifier
                    .fillMaxWidth()
                    .padding(horizontal = OpenCloudDimensions.SpacingXxs)
                    .browserDescription(R.string.browser_filter_files),
            placeholder = { Text(stringResource(R.string.browser_search_in_files)) },
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
            trailingIcon = {
                if (query.isNotEmpty()) {
                    IconButton(onClick = { onQueryChange("") }) {
                        Icon(Icons.Default.Close, contentDescription = stringResource(R.string.browser_clear_search))
                    }
                }
            },
            singleLine = true,
            shape = RoundedCornerShape(50),
        )
    },
    navigationIcon = {
        IconButton(
            onClick = onOpenDrawer,
            modifier = Modifier.size(OpenCloudDimensions.TouchTarget),
        ) {
            Icon(Icons.Default.Menu, contentDescription = stringResource(R.string.browser_open_navigation_drawer))
        }
    },
    actions = {
        notifications()
        Box(
            modifier = Modifier.padding(end = OpenCloudDimensions.SpacingMd),
            contentAlignment = Alignment.Center,
        ) {
            IconButton(
                onClick = onOpenAccount,
                modifier =
                    Modifier
                        .size(OpenCloudDimensions.TouchTarget)
                        .browserDescription(R.string.browser_open_account_information),
            ) {
                Surface(
                    modifier = Modifier.size(OpenCloudDimensions.AvatarSize),
                    shape = CircleShape,
                    color = MaterialTheme.colorScheme.primaryContainer,
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        eu.opencloud.android.next.core.ui
                            .ProfileAvatar(accountId)
                    }
                }
            }
        }
    },
    colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.surface),
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DestinationTopAppBar(
    title: String,
    accountId: String,
    onOpenDrawer: () -> Unit,
    onOpenAccount: () -> Unit,
    notifications: @Composable () -> Unit,
) = TopAppBar(
    title = { Text(title) },
    navigationIcon = {
        IconButton(onClick = onOpenDrawer, modifier = Modifier.size(OpenCloudDimensions.TouchTarget)) {
            Icon(Icons.Default.Menu, contentDescription = stringResource(R.string.browser_open_navigation_drawer))
        }
    },
    actions = {
        notifications()
        AccountAvatar(accountId, onOpenAccount)
    },
    colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.surface),
)

@Composable
private fun FavoritesEmpty(contentPadding: PaddingValues) {
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
private fun AccountAvatar(
    accountId: String,
    onOpenAccount: () -> Unit,
) {
    Box(
        modifier = Modifier.padding(end = OpenCloudDimensions.SpacingMd),
        contentAlignment = Alignment.Center,
    ) {
        IconButton(
            onClick = onOpenAccount,
            modifier =
                Modifier
                    .size(OpenCloudDimensions.TouchTarget)
                    .browserDescription(R.string.browser_open_account_information),
        ) {
            Surface(
                modifier = Modifier.size(OpenCloudDimensions.AvatarSize),
                shape = CircleShape,
                color = MaterialTheme.colorScheme.primaryContainer,
            ) {
                Box(contentAlignment = Alignment.Center) {
                    eu.opencloud.android.next.core.ui
                        .ProfileAvatar(accountId)
                }
            }
        }
    }
}

@Composable
@Suppress("LongParameterList")
private fun BrowserSubHeader(
    canNavigateUp: Boolean,
    layout: BrowserLayout,
    sortCriterion: BrowserSortCriterion,
    sortAscending: Boolean,
    showSortMenu: Boolean,
    onNavigateUp: () -> Unit,
    onShowSortMenu: () -> Unit,
    onDismissSortMenu: () -> Unit,
    onSortSelect: (BrowserSortCriterion) -> Unit,
    onToggleLayout: () -> Unit,
) {
    BrowserToolbar(
        canNavigateUp,
        SettingsBrowserLayout.valueOf(layout.name),
        onNavigateUp,
        onToggleLayout,
    ) {
        Box {
            TextButton(onClick = onShowSortMenu) {
                Text(stringResource(sortCriterion.labelResource))
                Icon(
                    imageVector =
                        if (sortAscending) {
                            Icons.Default.ArrowUpward
                        } else {
                            Icons.Default.ArrowDownward
                        },
                    contentDescription =
                        stringResource(
                            if (sortAscending) R.string.browser_ascending else R.string.browser_descending,
                        ),
                )
            }
            DropdownMenu(expanded = showSortMenu, onDismissRequest = onDismissSortMenu) {
                BrowserSortCriterion.entries.forEach { criterion ->
                    DropdownMenuItem(
                        text = { Text(stringResource(criterion.labelResource)) },
                        trailingIcon = {
                            if (criterion == sortCriterion) {
                                Icon(
                                    Icons.Default.Check,
                                    contentDescription = stringResource(R.string.browser_selected),
                                )
                            }
                        },
                        onClick = { onSortSelect(criterion) },
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SelectionTopAppBar(
    selectedCount: Int,
    onClearSelection: () -> Unit,
    onDownloadSelection: () -> Unit,
) = TopAppBar(
    title = { Text(pluralStringResource(R.plurals.browser_selected_count, selectedCount, selectedCount)) },
    navigationIcon = {
        IconButton(onClick = onClearSelection) {
            Icon(Icons.Default.Close, contentDescription = stringResource(R.string.browser_clear_selection))
        }
    },
    actions = {
        SelectionAction(
            stringResource(R.string.browser_keep_offline),
            Icons.Default.OfflinePin,
            stringResource(R.string.browser_download_selected_offline),
            onDownloadSelection,
        )
    },
    colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
)

@Composable
private fun TransferSummary(
    transfers: List<TransferEntity>,
    onOpenTransfers: () -> Unit,
) {
    val active =
        transfers.firstOrNull { it.state == TransferState.RUNNING.name }
            ?: transfers.firstOrNull { it.state in ACTIVE_TRANSFER_STATES }
            ?: transfers.firstOrNull { it.state in FAILED_TRANSFER_STATES }
            ?: return
    val progress =
        if (active.bytesTotal > 0) {
            (active.bytesTransferred.toFloat() / active.bytesTotal).coerceIn(0f, 1f)
        } else {
            0f
        }
    Column(
        modifier =
            Modifier
                .fillMaxWidth()
                .clickable(onClickLabel = stringResource(R.string.browser_open_transfers), onClick = onOpenTransfers)
                .padding(horizontal = OpenCloudDimensions.SpacingMd),
        verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXxs),
    ) {
        Text(
            text = browserTransferSummary(active),
            color =
                if (active.state in
                    FAILED_TRANSFER_STATES
                ) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.onSurface
                },
            style = MaterialTheme.typography.labelMedium,
        )
        if (active.state in ACTIVE_TRANSFER_STATES) {
            if (active.bytesTotal >
                0
            ) {
                LinearProgressIndicator(progress = { progress }, modifier = Modifier.fillMaxWidth())
            } else {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }
        }
    }
}

@Composable
private fun ExportStatus(
    state: FileBrowserUiState,
    onDismiss: () -> Unit,
) {
    state.exportStatus?.let { status ->
        Column(Modifier.fillMaxWidth().padding(horizontal = OpenCloudDimensions.SpacingMd)) {
            Text(status, style = MaterialTheme.typography.bodySmall)
            if (state.exporting) {
                androidx.compose.material3.LinearProgressIndicator(Modifier.fillMaxWidth())
            } else {
                TextButton(onClick = onDismiss) { Text(stringResource(R.string.browser_dismiss)) }
            }
        }
    }
}

@Composable
@Suppress("LongParameterList")
private fun BrowserNavigationDrawer(
    releaseVersion: String,
    selectedDestination: FileBrowserDestination,
    onRecents: () -> Unit,
    onOffline: () -> Unit,
    onTransfers: () -> Unit,
    onDeletedFiles: () -> Unit,
    onSettings: () -> Unit,
    onShares: () -> Unit,
    personalSpace: eu.opencloud.android.next.core.database.SpaceEntity?,
    onVaults: (() -> Unit)? = null,
) = ModalDrawerSheet(
    modifier =
        Modifier.width(
            (androidx.compose.ui.platform.LocalConfiguration.current.screenWidthDp.dp * 0.75f).coerceAtMost(
                OpenCloudDimensions.DrawerMaxWidth,
            ),
        ),
) {
    val context = LocalContext.current
    eu.opencloud.android.next.core.designsystem.RaiunWordmark(
        Modifier.padding(OpenCloudDimensions.SpacingXl),
    )
    HorizontalDivider()
    NavigationDrawerItem(
        label = { Text(stringResource(R.string.browser_recents)) },
        selected = selectedDestination == FileBrowserDestination.Recents,
        onClick = onRecents,
        icon = { Icon(Icons.Default.History, null) },
        modifier =
            Modifier
                .padding(horizontal = OpenCloudDimensions.SpacingSm)
                .browserDescription(R.string.browser_navigate_to, stringResource(R.string.browser_recents)),
    )
    NavigationDrawerItem(
        label = { Text(stringResource(R.string.browser_offline)) },
        selected = selectedDestination == FileBrowserDestination.Offline,
        onClick = onOffline,
        icon = { Icon(Icons.Default.OfflinePin, null) },
        modifier =
            Modifier
                .padding(horizontal = OpenCloudDimensions.SpacingSm)
                .browserDescription(R.string.browser_navigate_to, stringResource(R.string.browser_offline)),
    )
    NavigationDrawerItem(
        label = { Text(stringResource(R.string.browser_shares)) },
        selected = selectedDestination == FileBrowserDestination.Shares,
        onClick = onShares,
        icon = { Icon(Icons.Default.Share, null) },
        modifier =
            Modifier
                .padding(
                    horizontal = OpenCloudDimensions.SpacingSm,
                ).browserDescription(R.string.browser_navigate_to_shares),
    )
    NavigationDrawerItem(
        label = { Text(stringResource(R.string.browser_uploads)) },
        selected = false,
        onClick = onTransfers,
        icon = { Icon(Icons.Default.CloudSync, contentDescription = null) },
        modifier =
            Modifier
                .padding(horizontal = OpenCloudDimensions.SpacingSm)
                .browserDescription(R.string.browser_navigate_to_uploads),
    )
    NavigationDrawerItem(
        label = { Text(stringResource(R.string.browser_deleted_files)) },
        selected = false,
        onClick = onDeletedFiles,
        icon = { Icon(Icons.Default.Delete, contentDescription = null) },
        modifier =
            Modifier
                .padding(horizontal = OpenCloudDimensions.SpacingSm)
                .browserDescription(R.string.browser_navigate_to_deleted_files),
    )
    onVaults?.let { open ->
        VaultNavigationDrawerItem(open)
    }
    Spacer(Modifier.weight(1f))
    HorizontalDivider()
    NavigationDrawerItem(
        label = { Text(stringResource(R.string.browser_settings)) },
        selected = false,
        onClick = onSettings,
        icon = { Icon(Icons.Default.Settings, contentDescription = null) },
        modifier =
            Modifier
                .padding(OpenCloudDimensions.SpacingSm)
                .browserDescription(R.string.browser_open_settings),
    )
    NavigationDrawerItem(label = {
        Text(stringResource(R.string.browser_community_discussions))
    }, selected = false, onClick = {
        context.startActivity(
            Intent(Intent.ACTION_VIEW, android.net.Uri.parse("https://github.com/orgs/opencloud-eu/discussions")),
        )
    }, icon = {
        Icon(
            Icons.Default.Forum,
            null,
        )
    }, modifier = Modifier.padding(horizontal = OpenCloudDimensions.SpacingSm))
    personalSpace?.let { space ->
        val used = space.quotaUsedBytes
        val total = space.quotaBytes?.takeIf { it > 0 }
        Column(Modifier.padding(OpenCloudDimensions.SpacingMd)) {
            Text(stringResource(R.string.browser_personal_storage), style = MaterialTheme.typography.labelLarge)
            Text(
                browserQuotaSummary(used, total),
            )
            if (used != null &&
                total != null
            ) {
                LinearProgressIndicator(
                    progress = { (used.toFloat() / total).coerceIn(0f, 1f) },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    }
    Text(
        text = stringResource(R.string.browser_version, releaseVersion),
        modifier = Modifier.padding(OpenCloudDimensions.SpacingXl),
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        style = MaterialTheme.typography.bodySmall,
    )
}

@Composable
private fun VaultNavigationDrawerItem(onOpen: () -> Unit) {
    NavigationDrawerItem(
        label = { Text(stringResource(R.string.browser_vaults)) },
        selected = false,
        onClick = onOpen,
        icon = { Icon(Icons.Default.Lock, contentDescription = null) },
        modifier = Modifier.padding(horizontal = OpenCloudDimensions.SpacingSm),
    )
}

private val ACTIVE_TRANSFER_STATES =
    setOf(TransferState.QUEUED.name, TransferState.RUNNING.name, TransferState.RETRY.name)
private val FAILED_TRANSFER_STATES = setOf(TransferState.CONFLICT.name, TransferState.FAILED.name)

@Composable
@OptIn(ExperimentalMaterial3Api::class)
@Suppress("LongParameterList")
private fun BrowserBottomNavigation(
    selectedDestination: FileBrowserDestination,
    onPersonal: () -> Unit,
    onFavorites: () -> Unit,
    onSpaces: () -> Unit,
) = NavigationBar(
    containerColor = MaterialTheme.colorScheme.surfaceContainer,
    modifier = Modifier.personalNavigationCrown(MaterialTheme.colorScheme.surfaceContainer),
) {
    listOf(
        FileBrowserDestination.Favorites,
        FileBrowserDestination.Personal,
        FileBrowserDestination.Spaces,
    ).forEach { destination ->
        // The standard ripple is sized for the smaller Material indicator and would
        // briefly overlap Personal's custom indicator. Its selected state gives feedback.
        val ripple = if (destination == FileBrowserDestination.Personal) null else LocalRippleConfiguration.current
        CompositionLocalProvider(LocalRippleConfiguration provides ripple) {
            NavigationBarItem(
                colors =
                    androidx.compose.material3.NavigationBarItemDefaults.colors(
                        indicatorColor =
                            if (destination ==
                                FileBrowserDestination.Personal
                            ) {
                                OpenCloudColor.Transparent
                            } else {
                                MaterialTheme.colorScheme.secondaryContainer
                            },
                    ),
                selected = destination == selectedDestination,
                onClick =
                    when (destination) {
                        FileBrowserDestination.Favorites -> onFavorites
                        FileBrowserDestination.Spaces -> onSpaces
                        else -> onPersonal
                    },
                icon = {
                    if (destination == FileBrowserDestination.Personal) {
                        PersonalNavigationIcon(destination.icon, destination == selectedDestination)
                    } else {
                        Icon(destination.icon, null)
                    }
                },
                label = {
                    Text(
                        stringResource(destination.labelResource),
                        maxLines = 1,
                        style = MaterialTheme.typography.labelSmall,
                    )
                },
                modifier =
                    Modifier.browserDescription(
                        R.string.browser_navigate_to,
                        stringResource(destination.labelResource),
                    ),
            )
        }
    }
}

@Composable
@Suppress("LongParameterList")
private fun BrowserList(
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
)

@Composable
@Suppress("LongParameterList")
private fun BrowserGrid(
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
) {
    BrowserContent(
        mixedBrowserEntries(resources, encryptedFolders, sortCriterion, sortAscending),
        { it.key },
        layout,
        padding = contentPadding,
        footer = {
            FolderSummary(resources.filterNot { it.matchesEncryptedFolder(encryptedFolders) }, encryptedFolders.size)
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

@OptIn(ExperimentalFoundationApi::class)
@Composable
internal fun SheetAction(
    label: String,
    icon: ImageVector,
    color: Color = MaterialTheme.colorScheme.onSurface,
    onClick: () -> Unit,
) = BrowserAction(label, icon, color = color, onClick = onClick)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Suppress("LongParameterList")
fun ResourceActionSheet(
    resource: ResourceEntity,
    onDismiss: () -> Unit,
    onRename: () -> Unit,
    onMove: () -> Unit,
    onCopy: () -> Unit,
    onDownloadForOffline: () -> Unit,
    onDelete: () -> Unit,
    onToggleFavorite: () -> Unit = {},
    onShare: (() -> Unit)? = null,
    sheetState: androidx.compose.material3.SheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
    onOpenWith: (() -> Unit)? = null,
    onDetails: (() -> Unit)? = null,
    onSend: (() -> Unit)? = null,
    onExport: ((Boolean) -> Unit)? = null,
    onRemoveLocalCopy: () -> Unit = {},
    keptOffline: Boolean = resource.offlinePinned,
) {
    BrowserActionSheet(resource.name, onDismiss, sheetState = sheetState) {
        onOpenWith?.let {
            SheetAction(
                stringResource(R.string.browser_open_with),
                Icons.AutoMirrored.Filled.OpenInNew,
                onClick = it,
            )
        }
        onSend?.let {
            SheetAction(
                stringResource(R.string.browser_send),
                Icons.AutoMirrored.Filled.Send,
                onClick = it,
            )
        }
        onShare?.let { SheetAction(stringResource(R.string.browser_share), Icons.Outlined.People, onClick = it) }
        onDetails?.let { SheetAction(stringResource(R.string.browser_details), Icons.Default.Info, onClick = it) }
        FolderShortcutAction(resource)
        ActionGroupDivider()
        SheetAction(stringResource(R.string.browser_rename), Icons.Default.Edit, onClick = onRename)
        SheetAction(
            stringResource(R.string.browser_move_to),
            Icons.AutoMirrored.Filled.DriveFileMove,
            onClick = onMove,
        )
        SheetAction(stringResource(R.string.browser_copy_to), Icons.Default.ContentCopy, onClick = onCopy)
        SheetAction(
            if (resource.isFavorite) {
                stringResource(
                    R.string.browser_remove_from_favorites,
                )
            } else {
                stringResource(R.string.browser_add_to_favorites)
            },
            Icons.Default.Star,
            onClick = onToggleFavorite,
        )
        ActionGroupDivider()
        if (!keptOffline) {
            SheetAction(
                stringResource(R.string.browser_make_available_offline),
                Icons.Default.OfflinePin,
                onClick = onDownloadForOffline,
            )
        }
        if (resource.hasLocalCopy || keptOffline) {
            SheetAction(
                if (resource.kind ==
                    ResourceKind.FOLDER
                ) {
                    stringResource(R.string.browser_stop_keeping_offline)
                } else {
                    stringResource(R.string.browser_delete_local_copy)
                },
                cleanupIcon(),
                onClick = onRemoveLocalCopy,
            )
        }
        onExport?.let { export ->
            SheetAction(
                stringResource(R.string.browser_copy_to_device),
                Icons.Default.ContentCopy,
                onClick = { export(false) },
            )
        }
        ActionGroupDivider()
        SheetAction(
            stringResource(R.string.browser_delete),
            Icons.Default.Delete,
            MaterialTheme.colorScheme.error,
            onDelete,
        )
    }
}

@Composable
private fun BrowserNotice(
    title: String,
    message: String,
    onDismiss: () -> Unit,
) = AlertDialog(
    onDismissRequest = onDismiss,
    title = { Text(title) },
    text = { Text(message) },
    confirmButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.browser_ok)) } },
)

@Composable
private fun ConflictResolutionDialog(
    conflict: TransferEntity,
    onDecision: (ConflictDecision) -> Unit,
) = AlertDialog(
    onDismissRequest = {},
    title = { Text(stringResource(R.string.browser_upload_conflict)) },
    text = { Text(stringResource(R.string.browser_conflict_message, conflict.displayName)) },
    confirmButton = {
        Column(Modifier.fillMaxWidth()) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
            ) {
                FilledTonalButton(
                    onClick = { onDecision(ConflictDecision.KEEP_BOTH) },
                    modifier = Modifier.weight(1f),
                ) { Text(stringResource(R.string.browser_keep_both), textAlign = TextAlign.Center) }
                FilledTonalButton(
                    onClick = { onDecision(ConflictDecision.REPLACE) },
                    modifier = Modifier.weight(1f),
                ) { Text(stringResource(R.string.browser_replace_remote), textAlign = TextAlign.Center) }
            }
            TextButton(onClick = { onDecision(ConflictDecision.CANCEL) }) {
                Text(stringResource(R.string.browser_cancel_upload))
            }
        }
    },
)

@Composable
@Suppress("LongParameterList")
fun FolderBackupSettingsDialog(
    backups: List<FolderBackupEntity>,
    pickerTrail: List<BackupFolderCrumb>,
    pickerFolders: List<ResourceEntity>,
    onDismiss: () -> Unit,
    onAdd: (BackupDraft) -> Unit,
    onDelete: (String) -> Unit,
    onOpenPicker: () -> Unit,
    onOpenFolder: (ResourceEntity) -> Unit,
    onNavigateUp: () -> Unit,
    onCreateFolder: (String) -> Unit,
    sourceDisplayName: String? = null,
    onChooseSource: () -> Unit = {},
) = AlertDialog(
    onDismissRequest = onDismiss,
    text = {
        FolderBackupSettingsContent(
            backups = backups,
            pickerTrail = pickerTrail,
            pickerFolders = pickerFolders,
            onDismiss = onDismiss,
            onAdd = onAdd,
            onDelete = onDelete,
            onOpenPicker = onOpenPicker,
            onOpenFolder = onOpenFolder,
            onNavigateUp = onNavigateUp,
            onCreateFolder = onCreateFolder,
            sourceDisplayName = sourceDisplayName,
            onChooseSource = onChooseSource,
        )
    },
    confirmButton = {},
)

@Composable
@Suppress("LongParameterList", "CyclomaticComplexMethod", "LongMethod", "UnusedParameter")
fun FolderBackupSettingsContent(
    backups: List<FolderBackupEntity>,
    onDismiss: () -> Unit,
    onAdd: (BackupDraft) -> Unit,
    onDelete: (String) -> Unit,
    modifier: Modifier = Modifier,
    pickerTrail: List<BackupFolderCrumb> = emptyList(),
    pickerFolders: List<ResourceEntity> = emptyList(),
    onOpenPicker: () -> Unit = {},
    onOpenPickerSpace: (SpaceEntity) -> Unit = {},
    onOpenPickerShare: (BackupSharedRoot) -> Unit = {},
    onOpenSharedFolder: (BackupSharedFolder) -> Unit = {},
    onOpenFolder: (ResourceEntity) -> Unit = {},
    onNavigateUp: () -> Unit = {},
    onCreateFolder: (String) -> Unit = {},
    initialBackup: FolderBackupEntity? = null,
    transfers: List<TransferEntity> = emptyList(),
    sourceDisplayName: String? = null,
    onChooseSource: () -> Unit = {},
    pickerState: FileBrowserUiState = FileBrowserUiState(),
    defaultSpaceId: String? = null,
    requireDestinationBinding: Boolean = false,
) {
    var destination by rememberSaveable(initialBackup?.id) {
        mutableStateOf(
            initialBackup?.destinationPath ?: "/Camera Uploads",
        )
    }
    var showDestinationPicker by rememberSaveable { mutableStateOf(false) }
    var destinationSpaceId by rememberSaveable(initialBackup?.id) {
        mutableStateOf(
            initialBackup?.spaceId ?: defaultSpaceId,
        )
    }
    var destinationKind by rememberSaveable(initialBackup?.id) {
        mutableStateOf(
            initialBackup?.destinationKind ?: "SPACE",
        )
    }
    var sharedShareId by rememberSaveable(initialBackup?.id) { mutableStateOf(initialBackup?.sharedShareId) }
    var sharedFolderId by rememberSaveable(initialBackup?.id) { mutableStateOf(initialBackup?.sharedFolderId) }
    var destinationName by rememberSaveable(initialBackup?.id) { mutableStateOf<String?>(null) }
    LaunchedEffect(defaultSpaceId, initialBackup?.id) {
        if (initialBackup == null && destinationSpaceId == null) destinationSpaceId = defaultSpaceId
    }
    var showCreateFolder by rememberSaveable { mutableStateOf(false) }
    var mediaType by rememberSaveable(initialBackup?.id) { mutableStateOf(initialBackup?.mediaType ?: "IMAGE") }
    var wifiOnly by rememberSaveable(initialBackup?.id) { mutableStateOf(initialBackup?.wifiOnly ?: true) }
    var chargingOnly by rememberSaveable(initialBackup?.id) { mutableStateOf(initialBackup?.chargingOnly ?: false) }
    var datedFolders by rememberSaveable(initialBackup?.id) {
        mutableStateOf(initialBackup?.dateOrganization?.let { it != "NONE" } ?: false)
    }
    var datePattern by rememberSaveable(initialBackup?.id) {
        mutableStateOf(initialBackupDatePattern(initialBackup?.dateOrganization))
    }
    var showDatePatternEditor by rememberSaveable(initialBackup?.id) { mutableStateOf(false) }
    var backupEnabled by rememberSaveable(initialBackup?.id) { mutableStateOf(initialBackup?.enabled ?: true) }
    var exclusionPatterns by rememberSaveable(initialBackup?.id) {
        mutableStateOf(initialBackup?.exclusionPatterns.orEmpty())
    }
    var showExclusions by rememberSaveable(initialBackup?.id) { mutableStateOf(false) }
    var exclusionRows by rememberSaveable(initialBackup?.id) { mutableStateOf(arrayListOf("")) }
    var exclusionRowIds by rememberSaveable(initialBackup?.id) { mutableStateOf(arrayListOf(0)) }
    var nextExclusionRowId by rememberSaveable(initialBackup?.id) { mutableIntStateOf(1) }
    var focusExclusionRowId by rememberSaveable(initialBackup?.id) { mutableStateOf<Int?>(null) }
    val exclusionError = BackupExclusions.validate(exclusionPatterns)
    val datePreview = formatBackupDateFolder(datePattern, 1_790_687_999_000L)
    Column(modifier = modifier.fillMaxWidth()) {
        Column(
            modifier =
                Modifier
                    .weight(1f, fill = false)
                    .verticalScroll(rememberScrollState())
                    .padding(OpenCloudDimensions.SpacingMd),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs),
        ) {
            Text(
                stringResource(
                    if (initialBackup ==
                        null
                    ) {
                        R.string.backup_settings_add
                    } else {
                        R.string.backup_settings_manage
                    },
                ),
                style = MaterialTheme.typography.headlineSmall,
            )
            BackupSwitch(stringResource(R.string.backup_pause_option), !backupEnabled) { backupEnabled = !it }
            if (!backupEnabled) {
                Text(
                    stringResource(
                        if (initialBackup?.enabled == false) {
                            R.string.backup_settings_paused
                        } else {
                            R.string.backup_pause_pending
                        },
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            BackupLocationChoice(
                label = stringResource(R.string.backup_settings_source_folder),
                value =
                    initialBackup?.let { it.sourceDisplayName.ifBlank { sourceNameFromTreeUri(it.sourceTreeUri) } }
                        ?: sourceDisplayName ?: stringResource(R.string.backup_settings_source_not_selected),
                action = if (initialBackup == null) stringResource(R.string.browser_choose_source_folder) else null,
                onClick = onChooseSource,
            )
            BackupLocationChoice(
                label = stringResource(R.string.backup_settings_destination_folder),
                value =
                    if (destinationKind == "SHARED_FOLDER") {
                        val name =
                            pickerState.backupPickerSharedRoots.firstOrNull { it.shareId == sharedShareId }?.name
                                ?: sharedShareId?.let(pickerState.backupPickerSharedNames::get)
                        val category = stringResource(R.string.backup_destination_shared_with_me)
                        val label = destinationName ?: if (name == null) category else "$category · $name"
                        "$label · $destination"
                    } else {
                        val space = pickerState.spaces.firstOrNull { it.driveId == destinationSpaceId }
                        val category =
                            stringResource(
                                if (space?.type.equals(
                                        "personal",
                                        true,
                                    )
                                ) {
                                    R.string.backup_destination_personal
                                } else {
                                    R.string.backup_destination_spaces
                                },
                            )
                        val label = destinationName ?: space?.name?.let { "$category · $it" } ?: category
                        "$label · $destination"
                    },
                action = stringResource(R.string.browser_select_folder),
                onClick = {
                    onOpenPicker()
                    showDestinationPicker = true
                },
            )
            HorizontalDivider()
            Text(stringResource(R.string.backup_settings_files_to_back_up), style = MaterialTheme.typography.titleSmall)
            BackupMediaTypeOptions(mediaType) { mediaType = it }
            HorizontalDivider()
            BackupDateOrganizationOptions(
                wifiOnly = wifiOnly,
                onWifiOnlyChange = { wifiOnly = it },
                chargingOnly = chargingOnly,
                onChargingOnlyChange = { chargingOnly = it },
                enabled = datedFolders,
                pattern = datePattern,
                onEditPattern = { showDatePatternEditor = true },
            )
            Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.backup_exclusions_label), modifier = Modifier.weight(1f))
                OutlinedButton(onClick = {
                    val patterns = exclusionPatterns.lines().filter(String::isNotBlank).ifEmpty { listOf("") }
                    exclusionRows = ArrayList(patterns)
                    exclusionRowIds = ArrayList(patterns.indices.map { nextExclusionRowId + it })
                    nextExclusionRowId += patterns.size
                    focusExclusionRowId = null
                    showExclusions = true
                }) {
                    Text(stringResource(R.string.backup_exclusions_button))
                }
            }
            if (backups.isNotEmpty() || initialBackup != null) HorizontalDivider()
            backups.forEach { backup -> BackupConfigurationItem(backup = backup, onDelete = { onDelete(backup.id) }) }
            BackupRemoveButton(initialBackup, onDelete, onDismiss)
        }
        HorizontalDivider()
        Row(
            modifier = Modifier.fillMaxWidth().padding(OpenCloudDimensions.SpacingMd),
            horizontalArrangement = Arrangement.End,
        ) {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.browser_cancel)) }
            TextButton(
                enabled =
                    (initialBackup != null || sourceDisplayName != null) &&
                        (!requireDestinationBinding || destinationSpaceId != null) &&
                        (!datedFolders || datePreview != null) &&
                        exclusionError == null,
                onClick = {
                    onAdd(
                        BackupDraft(
                            destination,
                            mediaType,
                            wifiOnly,
                            chargingOnly,
                            false,
                            if (datedFolders) datePattern else "NONE",
                            destinationSpaceId,
                            destinationKind,
                            sharedShareId,
                            sharedFolderId,
                            exclusionPatterns,
                            backupEnabled,
                        ),
                    )
                },
            ) {
                Text(stringResource(R.string.browser_save))
            }
        }
    }
    if (showDestinationPicker) {
        BackupDestinationPickerDialog(
            state = pickerState,
            onDismiss = { showDestinationPicker = false },
            onOpenSpace = onOpenPickerSpace,
            onOpenShare = onOpenPickerShare,
            onOpenFolder = onOpenFolder,
            onOpenSharedFolder = onOpenSharedFolder,
            onNavigateUp = onNavigateUp,
            onRetry = onOpenPicker,
            onCreateFolder = { showCreateFolder = true },
            onSelect = { selected ->
                destination = selected.path
                destinationSpaceId = selected.spaceId
                destinationKind = selected.destinationKind
                sharedShareId = selected.sharedShareId
                sharedFolderId = selected.sharedFolderId
                destinationName = selected.name
                showDestinationPicker = false
            },
        )
    }
    if (showCreateFolder) {
        NameDialog(
            title = stringResource(R.string.browser_new_destination_folder),
            confirm = stringResource(R.string.browser_create),
            onDismiss = { showCreateFolder = false },
        ) { name ->
            onCreateFolder(name)
            showCreateFolder = false
        }
    }
    if (showExclusions) {
        BackupExclusionsDialog(
            rows = exclusionRows,
            rowIds = exclusionRowIds,
            focusRowId = focusExclusionRowId,
            onRowChange = { index, value ->
                exclusionRows =
                    ArrayList(exclusionRows).apply { this[index] = value.replace("\n", "").replace("\r", "") }
            },
            onAddRow = {
                val id = nextExclusionRowId++
                exclusionRows = ArrayList(exclusionRows).apply { add("") }
                exclusionRowIds = ArrayList(exclusionRowIds).apply { add(id) }
                focusExclusionRowId = id
            },
            onRemoveRow = { index ->
                if (focusExclusionRowId == exclusionRowIds[index]) focusExclusionRowId = null
                exclusionRows = ArrayList(exclusionRows).apply { removeAt(index) }
                exclusionRowIds = ArrayList(exclusionRowIds).apply { removeAt(index) }
            },
            onCancel = {
                focusExclusionRowId = null
                showExclusions = false
            },
            onDone = {
                exclusionPatterns = exclusionRows.filter(String::isNotBlank).joinToString("\n")
                focusExclusionRowId = null
                showExclusions = false
            },
        )
    }
    if (showDatePatternEditor) {
        BackupDatePatternDialog(
            enabled = datedFolders,
            pattern = datePattern,
            destination = destination,
            onCancel = { showDatePatternEditor = false },
            onDone = { selectedEnabled, selectedPattern ->
                datedFolders = selectedEnabled
                datePattern = selectedPattern
                showDatePatternEditor = false
            },
        )
    }
}

@Composable
@Suppress("LongParameterList") // Dialog rows and their editor actions are independent inputs.
private fun BackupExclusionsDialog(
    rows: List<String>,
    rowIds: List<Int>,
    focusRowId: Int?,
    onRowChange: (Int, String) -> Unit,
    onAddRow: () -> Unit,
    onRemoveRow: (Int) -> Unit,
    onCancel: () -> Unit,
    onDone: () -> Unit,
) {
    val error = BackupExclusions.validate(rows.filter(String::isNotBlank).joinToString("\n"))
    val listState = rememberLazyListState()
    LaunchedEffect(focusRowId) {
        val index = rowIds.indexOf(focusRowId)
        if (index >= 0) listState.scrollToItem(index)
    }
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text(stringResource(R.string.backup_exclusions_button)) },
        text = {
            LazyColumn(
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .heightIn(max = OpenCloudDimensions.BackupExclusionsListHeight),
                state = listState,
                verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs),
            ) {
                itemsIndexed(rows, key = { index, _ -> rowIds[index] }) { index, pattern ->
                    val rowId = rowIds[index]
                    val focusRequester = remember { FocusRequester() }
                    LaunchedEffect(focusRowId, rowId) {
                        if (focusRowId == rowId) {
                            focusRequester.requestFocus()
                        }
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        OutlinedTextField(
                            value = pattern,
                            onValueChange = { onRowChange(index, it) },
                            label = { Text(stringResource(R.string.backup_exclusions_pattern, index + 1)) },
                            singleLine = true,
                            modifier =
                                Modifier
                                    .weight(1f)
                                    .focusRequester(focusRequester),
                        )
                        IconButton(onClick = { onRemoveRow(index) }) {
                            Icon(
                                Icons.Default.Remove,
                                contentDescription = stringResource(R.string.backup_exclusions_remove, index + 1),
                            )
                        }
                    }
                }
                item(key = "add") {
                    IconButton(onClick = onAddRow) {
                        Icon(Icons.Default.Add, contentDescription = stringResource(R.string.backup_exclusions_add))
                    }
                }
                item(key = "help") {
                    Text(stringResource(R.string.backup_exclusions_help), style = MaterialTheme.typography.bodySmall)
                }
                if (error != null) {
                    item(key = "error") {
                        Text(
                            stringResource(R.string.backup_exclusions_invalid),
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
                item(key = "effect") {
                    Text(stringResource(R.string.backup_exclusions_effect), style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = onDone,
                enabled = error == null,
            ) { Text(stringResource(R.string.backup_exclusions_done)) }
        },
        dismissButton = { TextButton(onClick = onCancel) { Text(stringResource(R.string.browser_cancel)) } },
    )
}

@Composable
private fun BackupRemoveButton(
    backup: FolderBackupEntity?,
    onDelete: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    backup?.let {
        TextButton(onClick = {
            onDelete(it.id)
            onDismiss()
        }) { Text(stringResource(R.string.browser_remove_backup), color = MaterialTheme.colorScheme.error) }
    }
}

@Composable
@Suppress("LongParameterList") // The option state and callbacks are independent editor controls.
private fun BackupDateOrganizationOptions(
    wifiOnly: Boolean,
    onWifiOnlyChange: (Boolean) -> Unit,
    chargingOnly: Boolean,
    onChargingOnlyChange: (Boolean) -> Unit,
    enabled: Boolean,
    pattern: String,
    onEditPattern: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs)) {
        Text(stringResource(R.string.backup_settings_conditions), style = MaterialTheme.typography.titleSmall)
        BackupSwitch(stringResource(R.string.browser_wifi_only), wifiOnly, onWifiOnlyChange)
        BackupSwitch(stringResource(R.string.browser_charging_only), chargingOnly, onChargingOnlyChange)
        Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.backup_date_pattern), style = MaterialTheme.typography.bodyMedium)
                Text(
                    if (enabled) pattern else stringResource(R.string.backup_date_off),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            OutlinedButton(onClick = onEditPattern) { Text(stringResource(R.string.backup_date_edit)) }
        }
    }
}

@Composable
private fun BackupDatePatternDialog(
    enabled: Boolean,
    pattern: String,
    destination: String,
    onCancel: () -> Unit,
    onDone: (Boolean, String) -> Unit,
) {
    var selectedEnabled by rememberSaveable(enabled) { mutableStateOf(enabled) }
    var input by rememberSaveable(pattern, stateSaver = TextFieldValue.Saver) {
        mutableStateOf(TextFieldValue(pattern, TextRange(pattern.length)))
    }
    val preview = formatBackupDateFolder(input.text, 1_790_687_999_000L)
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text(stringResource(R.string.backup_date_pattern)) },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs),
            ) {
                Text(stringResource(R.string.backup_date_editor_help), style = MaterialTheme.typography.bodySmall)
                BackupSwitch(stringResource(R.string.backup_date_folders), selectedEnabled) { selectedEnabled = it }
                OutlinedTextField(
                    value = input,
                    onValueChange = { input = it },
                    label = { Text(stringResource(R.string.backup_date_pattern)) },
                    singleLine = true,
                    isError = preview == null,
                    modifier = Modifier.fillMaxWidth(),
                )
                Text(stringResource(R.string.backup_date_presets), style = MaterialTheme.typography.labelMedium)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs)) {
                    listOf("[YYYY]/[MM]", "[YYYY]/[MM]/[DD]", "[YYYY]-[MM]-[DD]").forEach { preset ->
                        FilterChip(
                            selected = input.text == preset,
                            onClick = { input = TextFieldValue(preset, TextRange(preset.length)) },
                            label = { Text(preset) },
                        )
                    }
                }
                Text(stringResource(R.string.backup_date_insert_token), style = MaterialTheme.typography.labelMedium)
                listOf(
                    R.string.backup_date_group_year to
                        listOf(
                            Triple("[YYYY]", "2026", R.string.backup_date_token_year),
                            Triple("[YY]", "26", R.string.backup_date_token_short_year),
                        ),
                    R.string.backup_date_group_month to
                        listOf(
                            Triple("[MMMM]", "October", R.string.backup_date_token_month_name),
                            Triple("[MMM]", "Oct", R.string.backup_date_token_short_month_name),
                            Triple("[MM]", "01–12", R.string.backup_date_token_month),
                            Triple("[M]", "1–12", R.string.backup_date_token_short_month),
                        ),
                    R.string.backup_date_group_day to
                        listOf(
                            Triple("[DD]", "01–31", R.string.backup_date_token_day),
                            Triple("[D]", "1–31", R.string.backup_date_token_short_day),
                        ),
                ).forEach { (groupLabel, tokens) ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            stringResource(groupLabel),
                            style = MaterialTheme.typography.labelSmall,
                            modifier = Modifier.weight(1f),
                        )
                        FlowRow(
                            modifier = Modifier.weight(4f),
                            horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs),
                        ) {
                            tokens.forEach { (token, example, description) ->
                                val descriptionText = stringResource(description)
                                AssistChip(
                                    onClick = {
                                        val start = input.selection.min.coerceIn(0, input.text.length)
                                        val end = input.selection.max.coerceIn(start, input.text.length)
                                        val updated = input.text.replaceRange(start, end, token)
                                        input = TextFieldValue(updated, TextRange(start + token.length))
                                    },
                                    label = { Text(example, style = MaterialTheme.typography.labelSmall) },
                                    modifier = Modifier.semantics { contentDescription = descriptionText },
                                )
                            }
                        }
                    }
                }
                Text(
                    if (preview == null) {
                        stringResource(R.string.backup_date_invalid)
                    } else {
                        stringResource(R.string.backup_date_preview, "$destination/$preview")
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color =
                        if (preview ==
                            null
                        ) {
                            MaterialTheme.colorScheme.error
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        },
                )
                Text(stringResource(R.string.backup_date_fallback), style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onDone(selectedEnabled, input.text) },
                enabled = !selectedEnabled || preview != null,
            ) {
                Text(stringResource(R.string.backup_exclusions_done))
            }
        },
        dismissButton = { TextButton(onClick = onCancel) { Text(stringResource(R.string.browser_cancel)) } },
    )
}

@Composable
private fun BackupConfigurationItem(
    backup: FolderBackupEntity,
    onDelete: () -> Unit,
) = ListItem(
    headlineContent = {
        BackupPathLine(
            label = stringResource(R.string.browser_local_path_label),
            value = backup.sourceDisplayName.ifBlank { sourceNameFromTreeUri(backup.sourceTreeUri) },
        )
    },
    supportingContent = {
        Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXxs)) {
            BackupPathLine(label = stringResource(R.string.browser_remote_path_label), value = backup.destinationPath)
            Text(
                backupDetails(backup, LocalContext.current),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodySmall,
            )
        }
    },
    trailingContent = {
        IconButton(onClick = onDelete) { Icon(Icons.Default.Delete, stringResource(R.string.browser_remove_backup)) }
    },
)

@Composable
private fun BackupPathLine(
    label: String,
    value: String,
) {
    Row(horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXxs)) {
        Text(label, fontWeight = FontWeight.SemiBold)
        Text(value)
    }
}

@Composable
private fun BackupLocationChoice(
    label: String,
    value: String,
    action: String?,
    onClick: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXxs)) {
        Text(label, style = MaterialTheme.typography.titleSmall)
        Text(value, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        if (action != null) TextButton(onClick = onClick) { Text(action) }
    }
}

@Composable
private fun BackupMediaTypeOptions(
    selected: String,
    onSelect: (String) -> Unit,
) {
    FlowRow(horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs)) {
        listOf(
            "IMAGE" to R.string.browser_photo_type,
            "VIDEO" to R.string.browser_video_type,
            "ALL" to R.string.browser_all_files_type,
        ).forEach { (value, labelId) ->
            val label = stringResource(labelId)
            FilterChip(selected = selected == value, onClick = { onSelect(value) }, label = { Text(label) })
        }
    }
}

/** Production callers supply Context; pure callers retain the established English fallback. */
internal fun backupDetails(
    backup: FolderBackupEntity,
    context: android.content.Context? = null,
): String {
    fun label(
        id: Int,
        fallback: String,
    ): String = context?.getString(id) ?: fallback
    val fileType =
        when (backup.mediaType) {
            "IMAGE" -> label(R.string.browser_photo_type, "Photos")
            "VIDEO" -> label(R.string.browser_video_type, "Videos")
            else -> label(R.string.browser_all_files_type, "All files")
        }
    val constraints =
        buildList {
            if (backup.wifiOnly) add(label(R.string.browser_wifi_only, "Wi-Fi only"))
            if (backup.chargingOnly) add(label(R.string.browser_charging, "Charging"))
        }.ifEmpty { listOf(label(R.string.browser_no_restrictions, "No restrictions")) }
    val separator = " ${label(R.string.browser_backup_separator, "•")} "
    return context?.getString(R.string.browser_backup_constraints, fileType, constraints.joinToString(separator))
        ?: "$fileType • ${constraints.joinToString(separator)}"
}

@Composable
private fun BackupSwitch(
    label: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(label, modifier = Modifier.weight(1f))
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            modifier = Modifier.semantics { contentDescription = label },
        )
    }
}

@Composable
private fun NameDialog(
    title: String,
    confirm: String,
    onDismiss: () -> Unit,
    initial: String = "",
    onConfirm: (String) -> Unit,
) {
    var name by remember { mutableStateOf(initial) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text(stringResource(R.string.browser_sort_name)) },
                singleLine = true,
            )
        },
        confirmButton = {
            Button(onClick = { onConfirm(name) }, enabled = name.isNotBlank()) { Text(confirm) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.browser_cancel)) } },
    )
}

private sealed interface BrowserDialog {
    data object New : BrowserDialog

    data object CreateFolder : BrowserDialog

    data object CreateSpace : BrowserDialog

    data class Rename(
        val resource: ResourceEntity,
    ) : BrowserDialog
}

data class BackupDraft(
    val destinationPath: String,
    val mediaType: String,
    val wifiOnly: Boolean,
    val chargingOnly: Boolean,
    val deleteAfterUpload: Boolean,
    val dateOrganization: String = "NONE",
    val spaceId: String? = null,
    val destinationKind: String = "SPACE",
    val sharedShareId: String? = null,
    val sharedFolderId: String? = null,
    val exclusionPatterns: String = "",
    val enabled: Boolean = true,
)

internal enum class BrowserSortCriterion(
    @androidx.annotation.StringRes val labelResource: Int,
) {
    Name(R.string.browser_sort_name),
    DateModified(R.string.browser_sort_date_modified),
    DateOpened(R.string.browser_sort_date_created),
    Size(R.string.browser_sort_size),
    Type(R.string.browser_sort_file_type),
    ;

    fun comparator(ascending: Boolean): Comparator<ResourceEntity> {
        val comparator =
            when (this) {
                Name -> compareBy(String.CASE_INSENSITIVE_ORDER) { resource: ResourceEntity -> resource.name }
                DateModified -> compareBy<ResourceEntity> { it.modifiedAtEpochMillis }
                DateOpened -> compareBy<ResourceEntity> { it.createdAtEpochMillis }
                Size -> compareBy<ResourceEntity> { it.sizeBytes }
                Type ->
                    compareBy(String.CASE_INSENSITIVE_ORDER) { resource: ResourceEntity ->
                        resource.name.substringAfterLast('.', "").ifBlank { resource.mimeType.orEmpty() }
                    }
            }
        val ordered = comparator.thenBy(String.CASE_INSENSITIVE_ORDER) { it.name }
        return compareBy<ResourceEntity> { it.kind != ResourceKind.FOLDER }
            .then(if (ascending) ordered else ordered.reversed())
    }
}

private fun BrowserLayout.next(): BrowserLayout =
    when (this) {
        BrowserLayout.DEFAULT_TABLE -> BrowserLayout.CONDENSED_TABLE
        BrowserLayout.CONDENSED_TABLE -> BrowserLayout.TILES
        BrowserLayout.TILES -> BrowserLayout.DEFAULT_TABLE
    }

enum class FileBrowserDestination(
    @androidx.annotation.StringRes val labelResource: Int,
    val icon: ImageVector,
) {
    Personal(R.string.browser_personal, Icons.Default.Folder),
    Favorites(R.string.browser_favorites, Icons.Default.Star),
    Shares(R.string.browser_shares, Icons.Default.Share),
    Spaces(R.string.browser_spaces, Icons.Default.Apps),
    Offline(R.string.browser_offline, Icons.Default.Smartphone),
    Recents(R.string.browser_recents, Icons.Default.History),
}

@Composable
private fun ApplyFolderShortcut(
    resource: ResourceEntity?,
    spaces: List<eu.opencloud.android.next.core.database.SpaceEntity>,
    accountId: String,
    open: (ResourceEntity) -> Unit,
) {
    val currentOpen by rememberUpdatedState(open)
    LaunchedEffect(resource, spaces) {
        resource
            ?.takeIf { it.accountId == accountId && spaces.any { space -> space.driveId == it.spaceId } }
            ?.let(currentOpen)
    }
}

private fun initialBackupDatePattern(organization: String?): String =
    when (organization) {
        null, "NONE", "YEAR_MONTH" -> "[YYYY]/[MM]"
        else -> organization
    }
