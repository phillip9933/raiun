package eu.opencloud.android.next.feature.files

import android.content.Intent
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.DriveFileMove
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.CameraAlt
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Smartphone
import androidx.compose.material.icons.filled.Star
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.material3.rememberDrawerState
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.TransferBrowserOverview
import eu.opencloud.android.next.core.database.TransferDirection
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.database.TransferState
import eu.opencloud.android.next.core.database.typedState
import eu.opencloud.android.next.core.datastore.DEFAULT_PINNED_NAVIGATION_ITEMS
import eu.opencloud.android.next.core.datastore.NavigationItem
import eu.opencloud.android.next.core.datastore.normalizePinnedNavigationItems
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.ui.BrowserPageNavigation
import eu.opencloud.android.next.core.ui.BrowserPageNavigationState
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
    var previewTarget by remember(accountId, state.accountRevision) { mutableStateOf<ResourceEntity?>(null) }
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
    LaunchedEffect(accountId, state.encryptedFolders) { favoritesViewModel.knownRoots(state.encryptedFolders) }
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
            pinnedNavigationItems = openingSettings.pinnedNavigationItems,
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
            onDirectoryPage = viewModel::directoryPage,
            onDirectorySort = viewModel::setDirectorySort,
            onFavoritesDisplay = favoritesViewModel::display,
            onFavoritesPage = favoritesViewModel::page,
            onOfflineDisplay = viewModel::offlineDisplay,
            onOfflinePage = viewModel::offlinePage,
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
                    onOtherLocation =
                        destinations.onOtherLocation?.let { open ->
                            {
                                val sources = state.clipboardItems.ifEmpty { listOfNotNull(state.clipboard) }
                                open(sources, state.moving)
                            }
                        },
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
            onCancelUploadConflicts = viewModel::cancelUploadConflicts,
            onClearMessage = viewModel::clearMessage,
            onSearchQueryChange = viewModel::setSearchQuery,
            onCollectionSearchOnly = viewModel::setCollectionSearchOnly,
            onOpenTransfers = destinations.onOpenTransfers,
            onRemoveFavorite = favoritesViewModel::remove,
            onDismissFavoriteError = favoritesViewModel::dismissError,
            onRefreshFavorites = favoritesViewModel::refresh,
            onOpenDeletedFiles = destinations.onOpenDeletedFiles,
            onOpenSettings = destinations.onOpenSettings,
            onOpenAppUpdates = destinations.onOpenAppUpdates,
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
    val onOtherLocation: ((List<ResourceEntity>, Boolean) -> Unit)? = null,
    val onOpenAppUpdates: () -> Unit = {},
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
    onCancelUploadConflicts: () -> Unit = {},
    onClearMessage: () -> Unit,
    onSearchQueryChange: (String) -> Unit,
    onOpenTransfers: () -> Unit,
    onRemoveFavorite: (ResourceEntity) -> Unit = {},
    onDismissFavoriteError: () -> Unit = {},
    onRefreshFavorites: () -> Unit = {},
    onOpenDeletedFiles: () -> Unit,
    onOpenSettings: () -> Unit,
    onOpenAppUpdates: () -> Unit = {},
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
    onDirectoryPage: (Boolean) -> Unit = {},
    onDirectorySort: (String, Boolean) -> Unit = { _, _ -> },
    onCollectionSearchOnly: (Boolean) -> Unit = {},
    onFavoritesDisplay: (String, String, Boolean, Boolean) -> Unit = { _, _, _, _ -> },
    onFavoritesPage: (Boolean) -> Unit = {},
    onOfflineDisplay: (String, String, Boolean, Boolean, String) -> Unit = { _, _, _, _, _ -> },
    onOfflinePage: (Boolean) -> Unit = {},
    pinnedNavigationItems: List<NavigationItem> = DEFAULT_PINNED_NAVIGATION_ITEMS,
) {
    var dialog by remember(accountId, state.accountRevision) { mutableStateOf<BrowserDialog?>(null) }
    var offlineFilter by rememberSaveable(accountId) { mutableStateOf(OfflineFilter.ALL) }
    var details by remember(accountId, state.accountRevision) { mutableStateOf<ResourceEntity?>(null) }
    var serverWebApp by remember(accountId, state.accountRevision) { mutableStateOf<ResourceEntity?>(null) }
    var expandedAdd by rememberSaveable { mutableStateOf(false) }
    var sortCriterion by rememberSaveable(accountId) { mutableStateOf(BrowserSortCriterion.Name) }
    var sortAscending by rememberSaveable(accountId) { mutableStateOf(true) }
    val currentDirectorySort by rememberUpdatedState(onDirectorySort)
    LaunchedEffect(sortCriterion, sortAscending) { currentDirectorySort(sortCriterion.name, sortAscending) }
    var showSortMenu by remember { mutableStateOf(false) }
    var favoritesQuery by rememberSaveable(accountId) { mutableStateOf("") }
    val currentFavoritesDisplay by rememberUpdatedState(onFavoritesDisplay)
    val currentOfflineDisplay by rememberUpdatedState(onOfflineDisplay)
    LaunchedEffect(favoritesQuery, sortCriterion, sortAscending, state.fileDisplay.showHidden) {
        currentFavoritesDisplay(favoritesQuery, sortCriterion.name, sortAscending, state.fileDisplay.showHidden)
    }
    LaunchedEffect(state.searchQuery, sortCriterion, sortAscending, state.fileDisplay.showHidden, offlineFilter) {
        currentOfflineDisplay(
            state.searchQuery,
            sortCriterion.name,
            sortAscending,
            state.fileDisplay.showHidden,
            offlineFilter.name,
        )
    }
    val visibleOfflinePins = state.offlinePins + favoritesState.keptOffline
    // Keep the in-session tab selection through recomposition, but start a fresh app launch
    // on Personal instead of restoring a previously selected Space.
    var selectedDestination by remember(accountId) { mutableStateOf(initialDestination) }
    val currentCollectionSearchOnly by rememberUpdatedState(onCollectionSearchOnly)
    LaunchedEffect(selectedDestination) {
        currentCollectionSearchOnly(
            selectedDestination != FileBrowserDestination.Personal,
        )
    }
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
    val controlsPage =
        when (selectedDestination) {
            FileBrowserDestination.Personal -> state.directoryPage.takeIf { state.searchQuery.isBlank() }
            FileBrowserDestination.Favorites -> favoritesState.page
            FileBrowserDestination.Offline -> state.offlinePage
            else -> null
        }
    val hasPageControls = controlsPage?.let { it.hasPrevious || it.hasNext } == true
    val transferOverview = state.transferOverview ?: legacyTransferOverview(state.transfers, accountId)
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
        remember(favoritesState.resources, favoritesState.page, favoritesQuery, sortCriterion, sortAscending) {
            if (favoritesState.page != null) {
                favoritesState.resources
            } else {
                favoritesState.resources
                    .filter { resource ->
                        favoritesQuery.isBlank() || resource.name.contains(favoritesQuery, ignoreCase = true)
                    }.sortedWith(sortCriterion.comparator(sortAscending))
            }
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

    val pinnedItems = normalizePinnedNavigationItems(pinnedNavigationItems)
    val onNavigate: (NavigationItem) -> Unit = { item ->
        onClearSelection()
        if (item == NavigationItem.TRANSFERS) {
            onOpenTransfers()
        } else {
            selectedDestination = requireNotNull(item.browserDestination())
            if (item == NavigationItem.PERSONAL) {
                state.spaces.firstOrNull { it.type == "personal" }?.let { onSelectSpace(it.driveId) }
            }
        }
    }

    ModalNavigationDrawer(
        drawerState = drawerState,
        gesturesEnabled = !selectionMode,
        drawerContent = {
            BrowserNavigationDrawer(
                releaseVersion = releaseVersion,
                selectedDestination = selectedDestination,
                pinnedItems = pinnedItems,
                onNavigate = {
                    onNavigate(it)
                    scope.launch { drawerState.close() }
                },
                personalSpace = state.spaces.firstOrNull { it.type == "personal" },
                onDeletedFiles = {
                    scope.launch { drawerState.close() }
                    onOpenDeletedFiles()
                },
                onSettings = {
                    scope.launch { drawerState.close() }
                    onOpenSettings()
                },
                onAppUpdates = {
                    scope.launch { drawerState.close() }
                    onOpenAppUpdates()
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
                                accountId = accountId,
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
                                if ((
                                        state.resources + state.searchResults + state.offlineResources +
                                            state.selectedResources
                                    ).any {
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
                    TransferSummary(listOfNotNull(transferOverview.representative), onOpenTransfers)
                }
            },
            bottomBar = {
                Column {
                    controlsPage?.takeIf { hasPageControls }?.let { page ->
                        DirectoryPagingBar(
                            page,
                            when (selectedDestination) {
                                FileBrowserDestination.Favorites -> onFavoritesPage
                                FileBrowserDestination.Offline -> onOfflinePage
                                else -> onDirectoryPage
                            },
                        )
                    }
                    operationControls()
                    BrowserBottomNavigation(
                        selectedDestination =
                            if (browsingProjectSpace) FileBrowserDestination.Spaces else selectedDestination,
                        pinnedItems = pinnedItems,
                        onNavigate = onNavigate,
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
                            if (state.offlinePage != null) {
                                state.offlineResources
                            } else {
                                state.offlineResources
                                    .filter {
                                        it.name.contains(state.searchQuery, true) &&
                                            offlineFilter.matches(it, visibleOfflinePins)
                                    }.sortedWith(sortCriterion.comparator(sortAscending))
                            }
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
                    val directoryPage =
                        state.directoryPage.takeIf {
                            selectedDestination == FileBrowserDestination.Personal && state.searchQuery.isBlank()
                        }
                    val collectionPage =
                        when (selectedDestination) {
                            FileBrowserDestination.Favorites -> favoritesState.page
                            FileBrowserDestination.Offline -> state.offlinePage
                            else -> null
                        }
                    val displayedPage = directoryPage ?: collectionPage
                    val directoryEntries =
                        displayedPage?.entries?.mapNotNull { item ->
                            item.resource
                                ?.takeUnless { it.matchesEncryptedFolder(encryptedFolders) }
                                ?.let { MixedBrowserEntry(resource = it) }
                                ?: encryptedFolders
                                    .firstOrNull { it.directoryOverlayId == item.overlayId }
                                    ?.let { MixedBrowserEntry(encrypted = it) }
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
                        androidx.compose.runtime.key(
                            displayedPage?.offset,
                            sortCriterion,
                            sortAscending,
                            state.spaceId,
                            state.currentFolderId,
                        ) {
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
                                        offlinePins = visibleOfflinePins,
                                        resources = displayedResources,
                                        directoryEntries = directoryEntries,
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
                                        offlinePins = visibleOfflinePins,
                                        resources = displayedResources,
                                        directoryEntries = directoryEntries,
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
    }

    transferOverview.uploadConflict?.let { conflict ->
        ConflictResolutionDialog(
            conflict = conflict,
            count = transferOverview.uploadConflictCount,
            busy = state.bulkConflictCancelling,
            onDecision = { onResolveConflict(conflict, it) },
            onCancelAll = onCancelUploadConflicts,
        )
    }
    state.message?.let { BrowserNotice(stringResource(R.string.browser_notice), it, onClearMessage) }
    details?.let { resource ->
        ResourceDetailsDialog(
            resource = resource,
            options =
                ResourceDetailsOptions(
                    keptOffline = isKeptOffline(resource, visibleOfflinePins),
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
    serverWebApp?.takeIf { it.accountId == accountId }?.let { resource ->
        ServerWebAppDialog(resource, onDismiss = { serverWebApp = null })
    }
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
            keptOffline = isKeptOffline(resource, visibleOfflinePins),
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
            onOpenOnServer =
                if (resource.kind == ResourceKind.FILE && resource.accountId == accountId) {
                    {
                        onDismissActions()
                        serverWebApp = resource
                    }
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

/** Small preview/test states may still supply explicit rows; production observes the scalar overview. */
internal fun legacyTransferOverview(
    transfers: List<TransferEntity>,
    account: String,
): TransferBrowserOverview {
    val representative = browserTransferRepresentative(transfers)
    val conflicts = bulkUploadConflictTargets(transfers, account)
    return TransferBrowserOverview(representative, conflicts.firstOrNull { it.locationKind != "VAULT" }, conflicts.size)
}

/** Matches the database overview ordering; awaiting authentication has no runnable progress banner. */
internal fun browserTransferRepresentative(transfers: List<TransferEntity>): TransferEntity? =
    transfers
        .filter { it.typedState.isRunnable || it.typedState.requiresAttention }
        .minWithOrNull(
            compareBy<TransferEntity> {
                when (it.typedState) {
                    TransferState.RUNNING -> 0
                    TransferState.QUEUED, TransferState.RETRY -> 1
                    else -> 2
                }
            }.thenByDescending { it.createdAtEpochMillis }.thenByDescending { it.id },
        )

internal fun bulkUploadConflictTargets(
    transfers: List<TransferEntity>,
    accountId: String,
): List<TransferEntity> =
    transfers.filter {
        it.accountId == accountId &&
            it.direction == TransferDirection.UPLOAD.name &&
            it.state == TransferState.CONFLICT.name
    }

private sealed interface BrowserDialog {
    data object New : BrowserDialog

    data object CreateFolder : BrowserDialog

    data object CreateSpace : BrowserDialog

    data class Rename(
        val resource: ResourceEntity,
    ) : BrowserDialog
}

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

@Composable
private fun DirectoryPagingBar(
    page: eu.opencloud.android.next.core.database.ResourceDirectoryPage,
    onPage: (Boolean) -> Unit,
) {
    BrowserPageNavigation(
        BrowserPageNavigationState(
            if (page.total == 0) 0 else page.offset.toLong() + 1,
            page.offset.toLong() + page.entries.size,
            page.total.toLong(),
            page.hasPrevious,
            page.hasNext,
        ),
        onPage,
    )
}
