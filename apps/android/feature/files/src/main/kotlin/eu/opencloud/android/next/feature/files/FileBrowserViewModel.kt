package eu.opencloud.android.next.feature.files

import android.app.Application
import android.net.Uri
import android.provider.DocumentsContract
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.viewModelScope
import androidx.work.WorkInfo
import androidx.work.WorkManager
import eu.opencloud.android.next.core.database.DirectoryOverlay
import eu.opencloud.android.next.core.database.DirectorySort
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.FolderBackupEntity
import eu.opencloud.android.next.core.database.IncomingShareStore
import eu.opencloud.android.next.core.database.RESOURCE_DIRECTORY_PAGE_SIZE
import eu.opencloud.android.next.core.database.ResourceCollection
import eu.opencloud.android.next.core.database.ResourceCollectionOptions
import eu.opencloud.android.next.core.database.ResourceCollectionPaging
import eu.opencloud.android.next.core.database.ResourceCollectionRoot
import eu.opencloud.android.next.core.database.ResourceDirectoryPage
import eu.opencloud.android.next.core.database.ResourceDirectoryPaging
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.ResourceOfflineFilter
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.database.TransferBrowserOverview
import eu.opencloud.android.next.core.database.TransferDirection
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.database.TransferState
import eu.opencloud.android.next.core.datastore.FileDisplayOptions
import eu.opencloud.android.next.core.datastore.SettingsBrowserLayout
import eu.opencloud.android.next.core.datastore.SettingsRepository
import eu.opencloud.android.next.core.designsystem.localizedString
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.sync.DISCOVERY_ERROR
import eu.opencloud.android.next.core.sync.FileOperationNameConflictException
import eu.opencloud.android.next.core.sync.SearchRepositoryResult
import eu.opencloud.android.next.core.sync.SharedFolderBrowser
import eu.opencloud.android.next.core.sync.SharedFolderPage
import eu.opencloud.android.next.core.sync.SharedFolderPageCursorSnapshot
import eu.opencloud.android.next.core.sync.SharedFolderRequest
import eu.opencloud.android.next.core.sync.SharedRootDiscovery
import eu.opencloud.android.next.core.sync.SharedUploadDestinationResolver
import eu.opencloud.android.next.core.sync.SpaceCreationResult
import eu.opencloud.android.next.core.sync.TransferManager
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultRepository
import eu.opencloud.android.next.core.sync.createSearchRepository
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.mapLatest
import kotlinx.coroutines.flow.onStart
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID

@OptIn(ExperimentalCoroutinesApi::class)
// Existing browser orchestration; encrypted discovery is isolated in EncryptedFolderDiscovery.
// Picker guards reject stale account and location transitions.
@Suppress("LargeClass", "ComplexCondition", "ReturnCount")
class FileBrowserViewModel(
    application: Application,
    private val savedState: SavedStateHandle,
) : AndroidViewModel(application) {
    private val restoredAccount: String? = savedState["browser.account"]
    private val restoredSpace: String? = savedState["browser.space"]
    private val restoredFolder: String? = savedState["browser.folder"]
    private val store = FileBrowserStore(FileBrowserDatabase.create(application))
    private val directoryPaging = ResourceDirectoryPaging(FileBrowserDatabase.create(application))
    private val collectionPaging = ResourceCollectionPaging(FileBrowserDatabase.create(application))
    private val offlinePager =
        CachedCollectionPager(
            viewModelScope,
            collectionPaging::invalidations,
            { collectionPaging.load(it.account, ResourceCollection.Offline, it.options) },
            { request ->
                collectionPaging.offlineBytes(request.account, request.options.roots) { resource ->
                    eu.opencloud.android.next.core.model
                        .validatedCachedFile(
                            eu.opencloud.android.next.core.model.resourceCacheDirectory(
                                application.filesDir,
                                resource.accountId,
                                resource.spaceId,
                            ),
                            resource.localPath,
                            resource.sizeBytes,
                        )?.let { it.path to it.length() }
                }
            },
        )
    private var accountJob: Job? = null
    private val directoryOptions = MutableStateFlow(DirectoryPageOptions())
    private val transfers = TransferManager(application, store)
    private val operations =
        eu.opencloud.android.next.core.sync
            .FileOperationManager(application)
    private val searchRepository = createSearchRepository(application, store)
    private val workManager = WorkManager.getInstance(application)
    private val settings = SettingsRepository.create(application)
    private val recentFiles =
        eu.opencloud.android.next.core.datastore
            .RecentFiles(application)
    private val mutableState = MutableStateFlow(FileBrowserUiState())
    private var placementInFlight = false
    private var placementTarget: FileOperationPlacementTarget? = null
    private val activeLocation = MutableStateFlow<BrowserLocation?>(null)
    private val backupPickerLocation = MutableStateFlow<BrowserLocation?>(null)
    private val backupPickerOffset = MutableStateFlow(0)
    private var backupPickerRevision = 0
    private var backupPickerVaultRevision = 0
    private var backupPickerSharedSnapshot: SharedBackupPickerSnapshot? = null
    private val backupPickerVaults = VaultRepository(application, store)
    private val sharedRoots = SharedRootDiscovery.create(application)
    private val sharedInventory = IncomingShareStore(FileBrowserDatabase.create(application))
    private val sharedBrowser = SharedFolderBrowser.create(application)
    private val sharedDestinationResolver = SharedUploadDestinationResolver.create(application)
    private val searchQuery = MutableStateFlow("")
    private val collectionSearchOnly = MutableStateFlow(false)
    val state: StateFlow<FileBrowserUiState> = mutableState.asStateFlow()

    private var accountId: String? = null
    private var latestDiscovery: UUID? = null
    private var creatingSpace = false
    private val encryptedFolders =
        EncryptedFolderDiscovery(application, store, viewModelScope) { entries, error ->
            reduce { withEncryptedFolders(entries, error) }
            offlinePager.roots(
                entries
                    .filter {
                        it.accountId == accountId
                    }.map { ResourceCollectionRoot(it.driveId, it.remoteVaultId, it.vaultPath) },
            )
            directoryOptions.update {
                it.copy(
                    overlays =
                        entries.map { root ->
                            DirectoryOverlay(root.directoryOverlayId, root.title, root.remoteVaultId, root.vaultPath)
                        },
                )
            }
        }
    private val encryptedCreation =
        EncryptedLocationCreation(
            application,
            store,
            viewModelScope,
            onBusy = { busy -> reduce { copy(encryptedCreationBusy = busy) } },
            onCreated = { created, parent ->
                if (accountId == created.accountId) {
                    if (parent == null) {
                        observeDiscovery(transfers.refreshAccount(created.accountId))
                        reduce { copy(encryptedSpaceCreationRevision = encryptedSpaceCreationRevision + 1) }
                    } else if (activeLocation.value ==
                        BrowserLocation(parent.accountId, parent.driveId, parent.folderId)
                    ) {
                        observeDiscovery(transfers.refreshFolder(parent.accountId, parent.driveId, parent.folderId))
                        encryptedFolders.refresh(parent.accountId, parent.driveId, parent.folderId)
                    }
                }
            },
            onUncertain = { account ->
                if (accountId == account) {
                    reduce {
                        copy(
                            error =
                                getApplication<Application>().localizedString(
                                    R.string.browser_encrypt_create_uncertain,
                                ),
                        )
                    }
                }
            },
        )

    init {
        transfers.scheduleCleanup()
        viewModelScope.launch(Dispatchers.IO) {
            offlinePager.state.collectLatest { cached ->
                if (cached.request?.account == accountId) {
                    reduce {
                        copy(
                            offlineResources =
                                cached.result
                                    ?.page
                                    ?.entries
                                    ?.mapNotNull { it.resource }
                                    .orEmpty(),
                            offlinePage = cached.result?.page,
                            offlineBytes = cached.bytes,
                            error = cached.error?.toOpenCloudError()?.safeMessage(getApplication()) ?: error,
                        )
                    }
                }
            }
        }
        viewModelScope.launch(Dispatchers.IO) {
            settings.settings.collectLatest { settings ->
                directoryOptions.update { it.copy(showHidden = settings.fileDisplay.showHidden) }
                reduce {
                    copy(
                        layout = settings.browserLayout.toBrowserLayout(),
                        fileDisplay = settings.fileDisplay,
                        temporaryCopyRetentionHours = settings.temporaryCopyRetentionHours,
                    )
                }
            }
        }
        viewModelScope.launch(Dispatchers.IO) {
            combine(activeLocation, directoryOptions) { location, options -> location to options }
                .flatMapLatest { (location, options) ->
                    if (location == null) {
                        flowOf(null)
                    } else {
                        directoryPaging.invalidations(location.accountId, location.spaceId, location.folderId).map {
                            loadDirectoryPage(location, options)
                        }
                    }
                }.collectLatest { result ->
                    if (result != null &&
                        activeLocation.value == result.first &&
                        directoryOptions.value == result.second
                    ) {
                        reduce {
                            copy(
                                resources = result.third.entries.mapNotNull { it.resource },
                                directoryPage = result.third,
                                selectedIds = if (result.third.accessible) selectedIds else emptySet(),
                            )
                        }
                    }
                }
        }
        viewModelScope.launch(Dispatchers.IO) {
            searchQuery
                .combine(collectionSearchOnly) { query, cachedOnly -> query to cachedOnly }
                .flatMapLatest { (query, cachedOnly) ->
                    val account = accountId
                    if (cachedOnly || account == null || query.isBlank()) {
                        flowOf(SearchRepositoryResult(emptyList(), remoteSupported = false))
                    } else {
                        searchRepository.search(account, query)
                    }
                }.onStart { emit(SearchRepositoryResult(emptyList(), remoteSupported = false)) }
                .collectLatest { result ->
                    reduce {
                        copy(
                            searchResults = result.resources,
                            remoteSearchSupported = result.remoteSupported,
                            isRemoteSearchLoading = result.remoteLoading,
                            remoteSearchError = result.remoteError,
                        )
                    }
                }
        }
        viewModelScope.launch(Dispatchers.IO) {
            backupPickerLocation
                .filterNotNull()
                .flatMapLatest { location ->
                    directoryPaging
                        .invalidations(location.accountId, location.spaceId, location.folderId)
                        .mapLatest {
                            loadBackupPickerOverlays(location)
                        }.combine(backupPickerOffset) { overlays, offset ->
                            BackupPickerQuery(location, overlays, offset)
                        }
                }.collectLatest { (location, overlays, offset) ->
                    val pickerRevision = backupPickerRevision
                    if (!isCurrentBackupPickerLocation(location, pickerRevision)) return@collectLatest
                    if (overlays == null) {
                        backupPickerVaultRevision++
                        return@collectLatest
                    }
                    val revision = ++backupPickerVaultRevision
                    reduce {
                        copy(
                            backupPickerLoading = true,
                            backupPickerCanSelect = false,
                            backupPickerError = null,
                        )
                    }
                    loadBackupPickerResourcePage(location, overlays, offset, revision, pickerRevision)
                }
        }
    }

    fun load(accountId: String) {
        if (this.accountId == accountId) return
        accountJob?.cancel()
        this.accountId = accountId
        offlinePager.account(accountId)
        searchQuery.value = ""
        activeLocation.value = null
        directoryOptions.value = DirectoryPageOptions(showHidden = state.value.fileDisplay.showHidden)
        reduce {
            copy(
                transfers = emptyList(),
                transferOverview = TransferBrowserOverview(),
                bulkConflictCancelling = false,
                selectedIds = emptySet(),
                resources = emptyList(),
                directoryPage = null,
                offlineResources = emptyList(),
                offlinePage = null,
                offlineBytes = 0,
                offlinePins = emptyList(),
                recentResources = emptyList(),
                searchResults = emptyList(),
                searchQuery = "",
                actionResource = null,
            )
        }
        backupPickerRevision++
        backupPickerLocation.value = null
        reduce {
            copy(
                backupPickerDestination = null,
                backupPickerSharedRoots = emptyList(),
                backupPickerSharedNames = emptyMap(),
                backupPickerSharedFolders = emptyList(),
                backupPickerResources = emptyList(),
                backupPickerTrail = emptyList(),
            )
        }
        accountJob =
            viewModelScope.launch(Dispatchers.IO) {
                launch {
                    sharedInventory.observe(accountId).collectLatest { shares ->
                        if (this@FileBrowserViewModel.accountId == accountId) {
                            reduce {
                                copy(
                                    backupPickerSharedNames =
                                        shares.filter { it.isFolder }.associate {
                                            it.id to
                                                it.name
                                        },
                                )
                            }
                        }
                    }
                }
                launch {
                    recentFiles
                        .observe(accountId)
                        .flatMapLatest { references ->
                            store.observeRecent(accountId, references.map { it.resourceId }).map { resources ->
                                references.mapNotNull { ref ->
                                    resources.firstOrNull {
                                        it.remoteId == ref.resourceId &&
                                            it.spaceId == ref.spaceId
                                    }
                                }
                            }
                        }.collectLatest { values -> reduce { copy(recentResources = values) } }
                }
                launch {
                    store.transferInventory().invalidations(accountId).collectLatest {
                        refreshTransferOverview(accountId)
                    }
                }
                launch {
                    store.observeBackups(accountId).collectLatest { backups ->
                        reduce { copy(backups = backups) }
                    }
                }
                launch {
                    mutableState
                        .map { it.pinCandidates() }
                        .distinctUntilChanged()
                        .combine(collectionPaging.invalidations(accountId)) { resources, _ -> resources }
                        .collectLatest { resources ->
                            val pins = collectionPaging.keptOffline(resources)
                            if (this@FileBrowserViewModel.accountId == accountId) reduce { copy(offlinePins = pins) }
                        }
                }
                launch { transfers.reconcile() }
                launch { operations.reconcile() }
                launch {
                    operations.observe(accountId).collectLatest { values ->
                        reduce { copy(operations = values) }
                    }
                }
                observeDiscovery(transfers.refreshAccount(accountId))
                store.observeSpaces(accountId).collectLatest { spaces ->
                    val selectedSpace =
                        mutableState.value.spaceId
                            ?.let { selectedId -> spaces.find { it.driveId == selectedId } }
                            ?: preferredInitialBrowserSpace(spaces)
                    reduce {
                        copy(
                            spaces = spaces,
                            spaceId = spaceId ?: selectedSpace?.driveId,
                        )
                    }
                    if (activeLocation.value == null && selectedSpace != null) {
                        restoreLocation(selectedSpace.driveId)
                    }
                }
            }
    }

    fun selectSpace(spaceId: String) {
        reduce { copy(spaceId = spaceId, currentFolderId = null, folderTrail = emptyList(), selectedIds = emptySet()) }
        setActiveLocation(spaceId, null)
        accountId?.let { observeDiscovery(transfers.refreshFolder(it, spaceId, null)) }
    }

    fun recordOpened(resource: ResourceEntity) =
        recentFiles.record(resource.accountId, resource.spaceId, resource.remoteId)

    suspend fun prepareExternalFile(resource: ResourceEntity): ResourceEntity =
        eu.opencloud.android.next.core.sync
            .prepareLocalResource(getApplication(), resource)

    fun exportFile(
        spaceId: String,
        resourceId: String,
        destination: Uri,
        removeLocal: Boolean,
    ) {
        val account = accountId ?: return
        if (state.value.exporting) return
        reduce { copy(exporting = true, exportStatus = "Preparing export…") }
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val resource = requireNotNull(store.resource(account, spaceId, resourceId))
                val ready = prepareExternalFile(resource)
                reduce { copy(exportStatus = "Exporting ${ready.name}…") }
                eu.opencloud.android.next.core.sync
                    .exportCachedFile(getApplication(), ready, destination)
                if (removeLocal) transfers.removeLocalCopy(ready, requireSameCopy = true)
                reduce {
                    copy(
                        exportStatus =
                            if (removeLocal) {
                                "Exported; app's local copy removed. Cloud file kept."
                            } else {
                                "Saved to the selected location."
                            },
                    )
                }
            } catch (cancelled: kotlinx.coroutines.CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                reduce {
                    copy(
                        exportStatus =
                            "Export did not finish. Your cloud file is unchanged. " +
                                "Check the destination before retrying.",
                    )
                }
            } finally {
                reduce { copy(exporting = false) }
            }
        }
    }

    fun dismissExportStatus() = reduce { copy(exportStatus = null) }

    fun refresh() {
        val location = activeLocation.value ?: return
        observeDiscovery(transfers.refreshFolder(location.accountId, location.spaceId, location.folderId))
        encryptedFolders.refresh(location.accountId, location.spaceId, location.folderId)
    }

    fun open(resource: ResourceEntity) {
        if (resource.kind != ResourceKind.FOLDER) return
        reduce {
            copy(
                currentFolderId = resource.remoteId,
                folderTrail =
                    folderTrail + FolderCrumb(resource.remoteId, resource.name),
                selectedIds = emptySet(),
            )
        }
        setActiveLocation(resource.spaceId, resource.remoteId)
        accountId?.let { observeDiscovery(transfers.refreshFolder(it, resource.spaceId, resource.remoteId)) }
    }

    fun browseSharedResource(resource: ResourceEntity) {
        val account = accountId ?: return
        if (resource.accountId != account) return
        viewModelScope.launch(Dispatchers.IO) {
            val trail = mutableListOf<FolderCrumb>()
            val visited = mutableSetOf<String>()
            var pendingId = if (resource.kind == ResourceKind.FOLDER) resource.remoteId else resource.parentId
            var folder = pendingId?.let { store.resource(account, resource.spaceId, it) }
            while (folder?.kind == ResourceKind.FOLDER && visited.size < 256) {
                if (!visited.add(folder.remoteId)) break
                trail.add(FolderCrumb(folder.remoteId, folder.name))
                pendingId = folder.parentId
                folder = pendingId?.let { store.resource(account, resource.spaceId, it) }
            }
            if (pendingId != null) {
                reportOpenError("The folder location is incomplete. Refresh its Space and try again.")
                return@launch
            }
            val folderId = trail.firstOrNull()?.id
            reduce {
                copy(
                    spaceId = resource.spaceId,
                    currentFolderId = folderId,
                    folderTrail = trail.asReversed(),
                    selectedIds = emptySet(),
                    searchQuery = "",
                    searchResults = emptyList(),
                )
            }
            setActiveLocation(resource.spaceId, folderId)
            observeDiscovery(transfers.refreshFolder(account, resource.spaceId, folderId))
        }
    }

    fun navigateUp() {
        val trail = state.value.folderTrail
        if (trail.isEmpty()) return
        val nextTrail = trail.dropLast(1)
        reduce { copy(currentFolderId = nextTrail.lastOrNull()?.id, folderTrail = nextTrail, selectedIds = emptySet()) }
        state.value.spaceId?.let { spaceId -> setActiveLocation(spaceId, nextTrail.lastOrNull()?.id) }
        state.value.spaceId?.let { spaceId ->
            accountId?.let { observeDiscovery(transfers.refreshFolder(it, spaceId, nextTrail.lastOrNull()?.id)) }
        }
    }

    fun setLayout(layout: BrowserLayout) {
        reduce { copy(layout = layout) }
        viewModelScope.launch(Dispatchers.IO) { settings.setBrowserLayout(layout.toSettingsLayout()) }
    }

    @Suppress("TooGenericExceptionCaught") // Keep the verified overview and future invalidations after a read failure.
    private suspend fun refreshTransferOverview(account: String) {
        try {
            val overview = store.transferInventory().overview(account)
            currentCoroutineContext().ensureActive()
            if (accountId == account) reduce { copy(transferOverview = overview) }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            if (accountId == account) reduce { copy(error = failure.toOpenCloudError().safeMessage(getApplication())) }
        }
    }

    @Suppress("TooGenericExceptionCaught") // UI boundary preserves cancellation and keeps future invalidations alive.
    private suspend fun loadDirectoryPage(
        location: BrowserLocation,
        options: DirectoryPageOptions,
    ): Triple<BrowserLocation, DirectoryPageOptions, ResourceDirectoryPage>? =
        try {
            val page =
                directoryPaging.load(
                    location.accountId,
                    location.spaceId,
                    location.folderId,
                    options.offset,
                    options.sort,
                    options.ascending,
                    options.showHidden,
                    options.overlays,
                )
            Triple(location, options, page)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            if (activeLocation.value == location && directoryOptions.value == options) {
                reduce { copy(error = failure.toOpenCloudError().safeMessage(getApplication())) }
            }
            null
        }

    fun setDirectorySort(
        criterion: String,
        ascending: Boolean,
    ) {
        val sort = DirectorySort.entries.firstOrNull { it.name == criterion } ?: return
        directoryOptions.update {
            if (it.sort == sort &&
                it.ascending == ascending
            ) {
                it
            } else {
                it.copy(sort = sort, ascending = ascending, offset = 0)
            }
        }
    }

    fun offlineDisplay(
        query: String,
        sort: String,
        ascending: Boolean,
        showHidden: Boolean,
        filter: String,
    ) {
        val criterion = DirectorySort.entries.firstOrNull { it.name == sort } ?: return
        val offlineFilter = ResourceOfflineFilter.entries.firstOrNull { it.name.equals(filter, true) } ?: return
        offlinePager.options(
            ResourceCollectionOptions(
                query = query,
                sort = criterion,
                ascending = ascending,
                showHidden = showHidden,
                offlineFilter = offlineFilter,
            ),
        )
    }

    fun offlinePage(previous: Boolean) = offlinePager.page(previous)

    fun directoryPage(previous: Boolean) {
        val page = state.value.directoryPage ?: return
        if (previous && !page.hasPrevious || !previous && !page.hasNext) return
        directoryOptions.update {
            it.copy(
                offset =
                    (
                        page.offset +
                            if (previous) -RESOURCE_DIRECTORY_PAGE_SIZE else RESOURCE_DIRECTORY_PAGE_SIZE
                    ).coerceAtLeast(0),
            )
        }
    }

    fun toggleSelection(resourceId: String) {
        val next = state.value.selectedIds.toMutableSet()
        if (!next.add(resourceId)) next.remove(resourceId)
        reduce { copy(selectedIds = next) }
    }

    fun reportOpenError(message: String) = reduce { copy(error = message) }

    fun clearSelection() = reduce { copy(selectedIds = emptySet()) }

    fun downloadSelection() =
        batchAction { resource ->
            transfers.makeAvailableOffline(resource)
        }

    fun deleteSelected() =
        batchAction { resource ->
            transfers.delete(resource)
        }

    fun removeSelectedLocalCopies() =
        batchAction { resource ->
            if (resource.hasLocalCopy && resource.kind == ResourceKind.FILE) transfers.removeLocalCopy(resource)
        }

    fun showActions(resource: ResourceEntity?) = reduce { copy(actionResource = resource) }

    fun dismissActions() = reduce { copy(actionResource = null) }

    fun createFolder(name: String) =
        mutate { account, space, parent -> transfers.createFolder(account, space, parent, name) }

    fun createEncryptedFolder(
        name: String,
        password: CharArray,
    ) {
        val location = activeLocation.value
        if (location == null || location.accountId != accountId) {
            password.fill('\u0000')
            return
        }
        encryptedCreation.folder(location.accountId, location.spaceId, location.folderId, name, password)
    }

    fun createEncryptedSpace(
        name: String,
        password: CharArray,
    ) {
        val account = accountId
        if (account == null) {
            password.fill('\u0000')
            return
        }
        encryptedCreation.space(account, name, password)
    }

    fun createSpace(name: String) {
        val account = accountId ?: return
        if (creatingSpace) return
        creatingSpace = true
        viewModelScope.launch {
            try {
                runCatching { createProjectSpace(getApplication(), store, account, name) }
                    .onSuccess { result ->
                        if (accountId == account && result is SpaceCreationResult.AwaitingDiscovery) {
                            reduce { copy(message = result.message(getApplication())) }
                        }
                    }.onFailure {
                        val message = it.toOpenCloudError().safeMessage(getApplication())
                        if (accountId == account) reduce { copy(error = message) }
                    }
            } finally {
                creatingSpace = false
            }
        }
    }

    fun rename(
        resource: ResourceEntity,
        name: String,
    ) = mutate { _, _, _ ->
        if (name != resource.name) {
            try {
                operations.enqueue(resource, resource.spaceId, resource.parentId, name, true)
            } catch (_: FileOperationNameConflictException) {
                throw OpenCloudException(OpenCloudError.Conflict)
            }
        }
    }

    fun move(resource: ResourceEntity) =
        reduce {
            copy(clipboard = resource, clipboardItems = emptyList(), moving = true, actionResource = null)
        }

    fun copy(resource: ResourceEntity) =
        reduce {
            copy(clipboard = resource, clipboardItems = emptyList(), moving = false, actionResource = null)
        }

    fun moveSelection() = prepareSelection(true)

    fun copySelection() = prepareSelection(false)

    fun favoriteSelection() = batchAction { transfers.setFavorite(it, true) }

    private fun prepareSelection(move: Boolean) {
        val captured = selectedResources()
        if (captured.isEmpty()) return
        val location = activeLocation.value
        val owner = accountId ?: return
        val selection = state.value.selectedIds
        viewModelScope.launch {
            runCatching {
                val sources =
                    withContext(Dispatchers.IO) {
                        captured.map { resource ->
                            ensureSelectionContext(location, selection, owner)
                            store.requireCurrentMutableResource(resource)
                        }
                    }
                ensureSelectionContext(location, selection, owner)
                reduce {
                    copy(
                        clipboard = sources.firstOrNull(),
                        clipboardItems = sources,
                        moving = move,
                        selectedIds = emptySet(),
                    )
                }
            }.onFailure { reduce { copy(error = it.toOpenCloudError().safeMessage(getApplication())) } }
        }
    }

    fun cancelPlacement() = reduce { copy(clipboard = null, clipboardItems = emptyList(), placementConflict = null) }

    // Cancellation is rethrown; preserve explicit batch and stale-context exits.
    @Suppress("TooGenericExceptionCaught", "CyclomaticComplexMethod", "ReturnCount")
    fun place() {
        val current = state.value
        val account = accountId ?: return
        val space = current.spaceId ?: return
        val parent = current.currentFolderId
        val sources = current.clipboardItems.ifEmpty { listOfNotNull(current.clipboard) }
        if (sources.isEmpty() || placementInFlight) return
        if (sources.any { it.accountId != account }) {
            cancelPlacement()
            return
        }
        placementInFlight = true
        placementTarget = FileOperationPlacementTarget(account, space, parent)
        reduce { copy(placementBusy = true) }
        viewModelScope.launch {
            try {
                for (source in sources) {
                    if (!isPlacementContextCurrent(account, space, parent)) return@launch
                    val failure =
                        try {
                            withContext(Dispatchers.IO) {
                                operations.enqueue(source, space, parent, source.name, current.moving)
                            }
                            null
                        } catch (cancelled: CancellationException) {
                            throw cancelled
                        } catch (error: Exception) {
                            error
                        }
                    if (!isPlacementContextCurrent(account, space, parent)) return@launch
                    if (failure is FileOperationNameConflictException) {
                        reduce {
                            copy(
                                placementConflict =
                                    FileOperationPlacementConflict(
                                        source,
                                        space,
                                        parent,
                                        current.moving,
                                        failure.suggestedName,
                                    ),
                            )
                        }
                        return@launch
                    }
                    if (failure != null) {
                        reduce { copy(error = failure.toOpenCloudError().safeMessage(getApplication())) }
                        return@launch
                    }
                    removePlacementSource(source)
                }
                if (isPlacementContextCurrent(account, space, parent)) {
                    reduce { copy(selectedIds = emptySet(), actionResource = null) }
                }
            } finally {
                placementInFlight = false
                if (isPlacementContextCurrent(account, space, parent)) {
                    if (placementTarget == FileOperationPlacementTarget(account, space, parent)) {
                        placementTarget = null
                    }
                    reduce { copy(placementBusy = false) }
                }
            }
        }
    }

    // Cancellation is rethrown; preserve explicit retry and stale-context exits.
    @Suppress("TooGenericExceptionCaught", "ReturnCount")
    fun keepBothPlacementConflict() {
        val conflict = state.value.placementConflict ?: return
        val account = accountId
        val current = state.value
        if (placementInFlight) return
        if (account != conflict.source.accountId ||
            current.spaceId != conflict.destinationSpaceId ||
            current.currentFolderId != conflict.parentId
        ) {
            cancelPlacement()
            return
        }
        val target =
            FileOperationPlacementTarget(conflict.source.accountId, conflict.destinationSpaceId, conflict.parentId)
        placementInFlight = true
        placementTarget = target
        reduce { copy(placementBusy = true) }
        viewModelScope.launch {
            try {
                val failure =
                    try {
                        withContext(Dispatchers.IO) {
                            operations.enqueue(
                                conflict.source,
                                conflict.destinationSpaceId,
                                conflict.parentId,
                                conflict.suggestedName,
                                conflict.moving,
                                namingBase = conflict.source.name,
                            )
                        }
                        null
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (error: Exception) {
                        error
                    }
                if (!isPlacementContextCurrent(target.accountId, target.spaceId, target.parentId)) return@launch
                when (failure) {
                    is FileOperationNameConflictException ->
                        reduce { copy(placementConflict = conflict.copy(suggestedName = failure.suggestedName)) }
                    null -> {
                        reduce { copy(placementConflict = null) }
                        removePlacementSource(conflict.source)
                    }
                    else -> {
                        reduce {
                            copy(
                                placementConflict = null,
                                error = failure.toOpenCloudError().safeMessage(getApplication()),
                            )
                        }
                    }
                }
            } finally {
                placementInFlight = false
                if (isPlacementContextCurrent(target.accountId, target.spaceId, target.parentId)) {
                    if (placementTarget == target) placementTarget = null
                    reduce { copy(placementBusy = false) }
                }
            }
        }
    }

    private fun isPlacementContextCurrent(
        account: String,
        space: String,
        parent: String?,
    ): Boolean = accountId == account && state.value.spaceId == space && state.value.currentFolderId == parent

    private fun clearPlacementBusyWhenContextChanges(
        account: String,
        space: String,
        parent: String?,
    ) {
        val target = placementTarget ?: return
        if (target != FileOperationPlacementTarget(account, space, parent)) {
            reduce { copy(placementBusy = false, placementConflict = null) }
        }
    }

    private fun removePlacementSource(source: ResourceEntity) =
        reduce {
            val remaining =
                (clipboardItems.ifEmpty { listOfNotNull(clipboard) }).filterNot {
                    it.remoteId == source.remoteId && it.spaceId == source.spaceId
                }
            copy(clipboard = remaining.firstOrNull(), clipboardItems = remaining, placementConflict = null)
        }

    fun retryOperation(id: String) =
        mutate { account, _, _ ->
            operations.retry(id, account)
        }

    fun dismissOperation(id: String) = mutate { account, _, _ -> operations.dismiss(id, account) }

    fun delete(resource: ResourceEntity) = mutate { _, _, _ -> transfers.delete(resource) }

    fun upload(uri: Uri) {
        val account = accountId ?: return
        val space = state.value.spaceId ?: return
        val parentPath =
            state.value.folderTrail
                .joinToString(separator = "/", prefix = "/") { it.name }
                .takeIf { state.value.folderTrail.isNotEmpty() }
        viewModelScope.launch {
            runCatching { withContext(Dispatchers.IO) { transfers.enqueueUpload(account, space, parentPath, uri) } }
                .onFailure { reduce { copy(error = it.toOpenCloudError().safeMessage(getApplication())) } }
        }
    }

    fun removeLocalCopy(resource: ResourceEntity) = mutate { _, _, _ -> transfers.removeLocalCopy(resource) }

    fun downloadForOffline(resource: ResourceEntity) {
        viewModelScope.launch {
            runCatching { withContext(Dispatchers.IO) { transfers.makeAvailableOffline(resource) } }
                .onSuccess { reduce { copy(actionResource = null) } }
                .onFailure { reduce { copy(error = it.toOpenCloudError().safeMessage(getApplication())) } }
        }
    }

    fun toggleFavorite(resource: ResourceEntity) {
        viewModelScope.launch {
            runCatching { withContext(Dispatchers.IO) { transfers.setFavorite(resource, !resource.isFavorite) } }
                .onSuccess {
                    reduce {
                        copy(
                            actionResource = null,
                            message = null,
                        )
                    }
                }.onFailure { reduce { copy(error = it.toOpenCloudError().safeMessage(getApplication())) } }
        }
    }

    fun setCollectionSearchOnly(cachedOnly: Boolean) {
        collectionSearchOnly.value = cachedOnly
    }

    fun setSearchQuery(query: String) {
        reduce { copy(searchQuery = query, remoteSearchError = null) }
        searchQuery.value = query
    }

    @Suppress("LongParameterList")
    fun saveBackup(
        sourceTreeUri: Uri,
        draft: BackupDraft,
    ) {
        val account = accountId ?: return
        val space = draft.spaceId ?: return
        viewModelScope.launch {
            val backup =
                FolderBackupEntity(
                    UUID.randomUUID().toString(),
                    account,
                    space,
                    sourceTreeUri.toString(),
                    getApplication<Application>().sourceDirectoryName(sourceTreeUri),
                    draft.destinationPath
                        .ifBlank {
                            "/Camera Uploads"
                        },
                    draft.mediaType,
                    draft.wifiOnly,
                    draft.chargingOnly,
                    draft.deleteAfterUpload,
                    dateOrganization = draft.dateOrganization,
                    destinationKind = draft.destinationKind,
                    sharedShareId = draft.sharedShareId,
                    sharedFolderId = draft.sharedFolderId,
                    exclusionPatterns = draft.exclusionPatterns,
                    enabled = draft.enabled,
                )
            runCatching { withContext(Dispatchers.IO) { transfers.saveBackup(backup) } }
                .onSuccess {
                    reduce {
                        copy(
                            message =
                                getApplication<Application>().localizedString(R.string.browser_backup_configured),
                        )
                    }
                }.onFailure { reduce { copy(error = it.toOpenCloudError().safeMessage(getApplication())) } }
        }
    }

    fun scanBackupsNow() = transfers.scanBackupsNow()

    fun deleteBackup(id: String) {
        val backup = state.value.backups.firstOrNull { it.id == id }
        viewModelScope.launch(Dispatchers.IO) {
            store.deleteBackup(id)
            backup?.let {
                eu.opencloud.android.next.core.sync
                    .BackupScanDiagnostics(getApplication())
                    .forget(it)
            }
        }
    }

    fun completeBackupSourceSelection(
        expectedAccountId: String?,
        expectedBackupId: String?,
        expectedFingerprint: String?,
        draft: BackupDraft,
        selectedSource: Uri,
    ) {
        if (accountId != expectedAccountId || expectedAccountId == null) return
        if (expectedBackupId == null) {
            saveBackup(selectedSource, draft)
        } else {
            val current =
                state.value.backups.firstOrNull {
                    it.id == expectedBackupId &&
                        it.accountId == expectedAccountId
                }
            if (current != null && backupSourceSelectionFingerprint(current) == expectedFingerprint) {
                updateBackup(current, draft, selectedSource)
            }
        }
    }

    fun updateBackup(
        backup: FolderBackupEntity,
        draft: BackupDraft,
        selectedSource: Uri? = null,
    ) {
        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    transfers.saveBackup(
                        backupSourceSelection(
                            backup,
                            selectedSource?.toString(),
                            selectedSource?.let { getApplication<Application>().sourceDirectoryName(it) },
                        ).copy(
                            destinationPath = draft.destinationPath,
                            spaceId = draft.spaceId ?: backup.spaceId,
                            destinationKind = draft.destinationKind,
                            sharedShareId = draft.sharedShareId,
                            sharedFolderId = draft.sharedFolderId,
                            mediaType = draft.mediaType,
                            wifiOnly = draft.wifiOnly,
                            chargingOnly = draft.chargingOnly,
                            deleteAfterUpload = false,
                            lastSafeScanEpochMillis = 0,
                            dateOrganization = draft.dateOrganization,
                            exclusionPatterns = draft.exclusionPatterns,
                            enabled = draft.enabled,
                        ),
                    )
                }
            }.onFailure { reduce { copy(error = it.toOpenCloudError().safeMessage(getApplication())) } }
        }
    }

    @Suppress("TooGenericExceptionCaught") // UI boundary converts discovery errors and rethrows cancellation.
    private suspend fun loadBackupPickerOverlays(location: BrowserLocation): List<DirectoryOverlay>? =
        try {
            val path =
                state.value.backupPickerTrail
                    .lastOrNull()
                    ?.path
                    ?.trim('/') ?: ""
            backupPickerVaults.encryptedFolders(location.accountId, location.spaceId, path).map { root ->
                DirectoryOverlay(root.directoryOverlayId, root.title, root.remoteVaultId, root.vaultPath)
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            if (accountId == location.accountId && backupPickerLocation.value == location) {
                reduce {
                    copy(
                        backupPickerResources = emptyList(),
                        backupPickerLoading = false,
                        backupPickerCanSelect = false,
                        backupPickerError = failure.toOpenCloudError().safeMessage(getApplication()),
                    )
                }
            }
            null
        }

    private fun isCurrentBackupPickerLocation(
        location: BrowserLocation,
        pickerRevision: Int,
    ): Boolean =
        pickerRevision == backupPickerRevision &&
            accountId == location.accountId &&
            backupPickerLocation.value == location &&
            state.value.backupPickerDestination?.let {
                it.destinationKind == "SPACE" && it.spaceId == location.spaceId
            } == true &&
            state.value.backupPickerTrail
                .lastOrNull()
                ?.id == location.folderId

    @Suppress("TooGenericExceptionCaught") // Convert bounded page failures at this UI boundary; propagate cancellation.
    private suspend fun loadBackupPickerResourcePage(
        location: BrowserLocation,
        overlays: List<DirectoryOverlay>,
        offset: Int,
        pageRevision: Int,
        pickerRevision: Int,
    ) {
        try {
            val page =
                directoryPaging.load(
                    location.accountId,
                    location.spaceId,
                    location.folderId,
                    offset,
                    DirectorySort.Name,
                    true,
                    true,
                    overlays,
                    onlyFolders = true,
                    includeOverlays = false,
                )
            if (pageRevision == backupPickerVaultRevision && isCurrentBackupPickerLocation(location, pickerRevision)) {
                reduce {
                    copy(
                        backupPickerResources = page.entries.mapNotNull { it.resource },
                        backupPickerPage = BackupPickerPageState(page.offset, page.total, RESOURCE_DIRECTORY_PAGE_SIZE),
                        backupPickerLoading = false,
                        backupPickerCanSelect = page.accessible,
                        backupPickerError = null,
                    )
                }
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            if (pageRevision == backupPickerVaultRevision && isCurrentBackupPickerLocation(location, pickerRevision)) {
                reduce {
                    copy(
                        backupPickerResources = emptyList(),
                        backupPickerLoading = false,
                        backupPickerCanSelect = false,
                        backupPickerError = failure.toOpenCloudError().safeMessage(getApplication()),
                    )
                }
            }
        }
    }

    fun openBackupPicker() {
        val account = accountId ?: return
        backupPickerRevision++
        backupPickerSharedSnapshot = null
        backupPickerOffset.value = 0
        backupPickerLocation.value = null
        reduce {
            copy(
                backupPickerDestination = null,
                backupPickerTrail = emptyList(),
                backupPickerResources = emptyList(),
                backupPickerSharedFolders = emptyList(),
                backupPickerPage = null,
                backupPickerSharedRoots = emptyList(),
                backupPickerLoading = true,
                backupPickerCanSelect = false,
                backupPickerError = null,
            )
        }
        val revision = backupPickerRevision
        viewModelScope.launch {
            runCatching { withContext(Dispatchers.IO) { sharedRoots.discover(account) } }
                .onSuccess { catalog ->
                    if (accountId == account &&
                        revision == backupPickerRevision
                    ) {
                        reduce {
                            copy(
                                backupPickerSharedRoots =
                                    catalog.roots.map {
                                        BackupSharedRoot(it.name, it.shareId, it.scopeId, it.rootItemId)
                                    },
                                backupPickerLoading = false,
                            )
                        }
                    }
                }.onFailure {
                    if (accountId == account &&
                        revision == backupPickerRevision
                    ) {
                        reduce {
                            copy(
                                backupPickerLoading = false,
                                backupPickerError = it.toOpenCloudError().safeMessage(getApplication()),
                            )
                        }
                    }
                }
        }
    }

    fun openBackupPickerSpace(space: SpaceEntity) {
        val account = accountId ?: return
        if (space.accountId != account ||
            space.isDisabled ||
            space.isDeleted ||
            space.type.contains("encrypted", true)
        ) {
            return
        }
        backupPickerRevision++
        backupPickerSharedSnapshot = null
        backupPickerOffset.value = 0
        val category =
            if (space.type.equals(
                    "personal",
                    true,
                )
            ) {
                R.string.backup_destination_personal
            } else {
                R.string.backup_destination_spaces
            }
        val label = "${getApplication<Application>().localizedString(category)} · ${space.name}"
        reduce {
            copy(
                backupPickerDestination = BackupDestination(space.driveId, "/", "SPACE", null, null, label),
                backupPickerTrail = emptyList(),
                backupPickerResources = emptyList(),
                backupPickerSharedFolders = emptyList(),
                backupPickerPage = null,
                backupPickerLoading = true,
                backupPickerCanSelect = false,
                backupPickerError = null,
            )
        }
        backupPickerLocation.value = null
        backupPickerLocation.value = BrowserLocation(account, space.driveId, null)
        observeDiscovery(transfers.refreshFolder(account, space.driveId, null))
    }

    fun openBackupPickerShare(root: BackupSharedRoot) {
        val account = accountId ?: return
        backupPickerOffset.value = 0
        backupPickerLocation.value = null
        val label = "${getApplication<Application>().localizedString(
            R.string.backup_destination_shared_with_me,
        )} · ${root.name}"
        val destination = BackupDestination(root.scopeId, "/", "SHARED_FOLDER", root.shareId, root.rootItemId, label)
        loadSharedBackupFolder(account, destination, emptyList())
    }

    private fun loadSharedBackupFolder(
        account: String,
        destination: BackupDestination,
        trail: List<BackupFolderCrumb>,
    ) {
        val revision = ++backupPickerRevision
        backupPickerSharedSnapshot = null
        reduce {
            copy(
                backupPickerDestination = destination,
                backupPickerTrail = trail,
                backupPickerResources = emptyList(),
                backupPickerSharedFolders = emptyList(),
                backupPickerPage = null,
                backupPickerLoading = true,
                backupPickerError = null,
                backupPickerCanSelect = false,
            )
        }
        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    val request =
                        SharedFolderRequest(
                            account,
                            requireNotNull(destination.sharedShareId),
                            destination.spaceId,
                            requireNotNull(destination.sharedFolderId),
                            destination.path,
                        )
                    val page = sharedBrowser.openFolderMetadata(request)
                    val selectable =
                        try {
                            sharedDestinationResolver.prepare(request, page)
                            true
                        } catch (cancelled: CancellationException) {
                            throw cancelled
                        } catch (_: Exception) {
                            false
                        }
                    val snapshot = sharedBrowser.captureDisplaySnapshot(page)
                    val entries = sharedBrowser.displayPage(page, 0, snapshot.revision)
                    Pair(
                        SharedBackupPickerSnapshot(request, page, snapshot, selectable),
                        entries.filter { it.isFolder }.map { BackupSharedFolder(it.remoteId, it.name, it.path) },
                    )
                }
            }.onSuccess { (snapshot, folders) ->
                if (accountId == account &&
                    revision == backupPickerRevision
                ) {
                    backupPickerSharedSnapshot = snapshot
                    reduce {
                        copy(
                            backupPickerSharedFolders = folders,
                            backupPickerPage = BackupPickerPageState(0, snapshot.cursor.total, 256),
                            backupPickerCanSelect = snapshot.canSelect,
                            backupPickerLoading = false,
                        )
                    }
                }
            }.onFailure {
                if (accountId == account &&
                    revision == backupPickerRevision
                ) {
                    reduce {
                        copy(
                            backupPickerLoading = false,
                            backupPickerError = it.toOpenCloudError().safeMessage(getApplication()),
                        )
                    }
                }
            }
        }
    }

    fun pageBackupPicker(previous: Boolean) {
        val page = state.value.backupPickerPage ?: return
        if (previous && !page.hasPrevious) return
        if (!previous && !page.hasNext) return
        val offset = (page.offset + if (previous) -page.pageSize else page.pageSize).coerceAtLeast(0)
        val destination = state.value.backupPickerDestination ?: return
        if (destination.destinationKind == "SPACE") {
            backupPickerOffset.value = offset
            return
        }
        val snapshot = backupPickerSharedSnapshot ?: return
        val account = accountId ?: return
        requestSharedBackupPickerPage(account, destination, snapshot, page, offset)
    }

    @Suppress("TooGenericExceptionCaught") // Convert revision-pinned paging errors at this UI boundary.
    private fun requestSharedBackupPickerPage(
        account: String,
        destination: BackupDestination,
        snapshot: SharedBackupPickerSnapshot,
        page: BackupPickerPageState,
        offset: Int,
    ) {
        val shareId = destination.sharedShareId ?: return
        val folderId = destination.sharedFolderId ?: return
        val expectedRequest = SharedFolderRequest(account, shareId, destination.spaceId, folderId, destination.path)
        if (snapshot.request != expectedRequest) return
        val revision = ++backupPickerRevision
        reduce { copy(backupPickerLoading = true, backupPickerError = null) }
        viewModelScope.launch {
            try {
                val folders =
                    withContext(Dispatchers.IO) {
                        sharedBrowser
                            .displayPage(snapshot.page, offset, snapshot.cursor.revision)
                            .filter { it.isFolder }
                            .map { BackupSharedFolder(it.remoteId, it.name, it.path) }
                    }
                if (isCurrentSharedBackupPicker(account, revision, destination, snapshot)) {
                    reduce {
                        copy(
                            backupPickerSharedFolders = folders,
                            backupPickerPage = page.copy(offset = offset),
                            backupPickerLoading = false,
                            backupPickerCanSelect = snapshot.canSelect,
                        )
                    }
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Exception) {
                if (accountId == account && revision == backupPickerRevision) {
                    backupPickerSharedSnapshot = null
                    reduce {
                        copy(
                            backupPickerLoading = false,
                            backupPickerCanSelect = false,
                            backupPickerError = failure.toOpenCloudError().safeMessage(getApplication()),
                        )
                    }
                }
            }
        }
    }

    private fun isCurrentSharedBackupPicker(
        account: String,
        revision: Int,
        destination: BackupDestination,
        snapshot: SharedBackupPickerSnapshot,
    ): Boolean =
        accountId == account &&
            revision == backupPickerRevision &&
            state.value.backupPickerDestination == destination &&
            backupPickerSharedSnapshot === snapshot

    fun openBackupPickerSharedFolder(folder: BackupSharedFolder) {
        val account = accountId ?: return
        val current = state.value.backupPickerDestination ?: return
        if (current.destinationKind != "SHARED_FOLDER") return
        loadSharedBackupFolder(
            account,
            current.copy(path = folder.path, sharedFolderId = folder.id),
            state.value.backupPickerTrail + BackupFolderCrumb(folder.id, folder.name, folder.path),
        )
    }

    fun openBackupPickerFolder(folder: ResourceEntity) {
        if (folder.kind != ResourceKind.FOLDER) return
        val account = accountId ?: return
        val current = state.value.backupPickerDestination ?: return
        if (current.destinationKind != "SPACE" || folder.spaceId != current.spaceId) return
        backupPickerOffset.value = 0
        reduce { copy(backupPickerPage = null) }
        reduce {
            copy(
                backupPickerDestination = current.copy(path = folder.path),
                backupPickerTrail = backupPickerTrail + BackupFolderCrumb(folder.remoteId, folder.name, folder.path),
                backupPickerResources = emptyList(),
                backupPickerLoading = true,
                backupPickerCanSelect = false,
                backupPickerError = null,
            )
        }
        backupPickerLocation.value = null
        backupPickerLocation.value = BrowserLocation(account, folder.spaceId, folder.remoteId)
        observeDiscovery(transfers.refreshFolder(account, folder.spaceId, folder.remoteId))
    }

    fun navigateBackupPickerUp() {
        val account = accountId ?: return
        val current = state.value.backupPickerDestination ?: return
        val nextTrail = state.value.backupPickerTrail.dropLast(1)
        if (current.destinationKind == "SHARED_FOLDER") {
            val root = state.value.backupPickerSharedRoots.firstOrNull { it.shareId == current.sharedShareId } ?: return
            val last = nextTrail.lastOrNull()
            loadSharedBackupFolder(
                account,
                current.copy(
                    path = last?.path ?: "/",
                    sharedFolderId =
                        last?.id ?: root.rootItemId,
                ),
                nextTrail,
            )
        } else {
            backupPickerOffset.value = 0
            reduce { copy(backupPickerPage = null) }
            reduce {
                copy(
                    backupPickerDestination = current.copy(path = nextTrail.lastOrNull()?.path ?: "/"),
                    backupPickerTrail = nextTrail,
                    backupPickerResources = emptyList(),
                    backupPickerLoading = true,
                    backupPickerCanSelect = false,
                    backupPickerError = null,
                )
            }
            backupPickerLocation.value = null
            backupPickerLocation.value = BrowserLocation(account, current.spaceId, nextTrail.lastOrNull()?.id)
            observeDiscovery(transfers.refreshFolder(account, current.spaceId, nextTrail.lastOrNull()?.id))
        }
    }

    fun createBackupPickerFolder(name: String) {
        val account = accountId ?: return
        val space =
            state.value.backupPickerDestination
                ?.takeIf { it.destinationKind == "SPACE" }
                ?.spaceId ?: return
        val parentId =
            state.value.backupPickerTrail
                .lastOrNull()
                ?.id
        viewModelScope.launch {
            runCatching { withContext(Dispatchers.IO) { transfers.createFolder(account, space, parentId, name) } }
                .onFailure { reduce { copy(error = it.toOpenCloudError().safeMessage(getApplication())) } }
        }
    }

    fun resolveConflict(
        transfer: TransferEntity,
        decision: ConflictDecision,
    ) {
        if (transfer.accountId != accountId || state.value.bulkConflictCancelling) return
        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    when (decision) {
                        ConflictDecision.REPLACE -> transfers.retryConflict(transfer, overwrite = true)
                        ConflictDecision.KEEP_BOTH ->
                            transfers.retryConflict(
                                transfer,
                                overwrite = false,
                                keepBoth = true,
                            )
                        ConflictDecision.CANCEL -> transfers.cancelConflict(transfer)
                    }
                }
            }.onFailure { reduce { copy(error = it.toOpenCloudError().safeMessage(getApplication())) } }
        }
    }

    fun cancelUploadConflicts() {
        val account = accountId ?: return
        if (account.isBlank()) return
        val hasConflicts =
            state.value.transfers.any {
                it.accountId == account &&
                    it.direction == TransferDirection.UPLOAD.name &&
                    it.state == TransferState.CONFLICT.name
            }
        if (state.value.bulkConflictCancelling || !hasConflicts) return
        reduce { copy(bulkConflictCancelling = true, error = null) }
        viewModelScope.launch {
            runCatching { withContext(Dispatchers.IO) { transfers.cancelUploadConflicts(account) } }
                .onFailure { failure ->
                    if (accountId == account) {
                        reduce {
                            copy(
                                bulkConflictCancelling = false,
                                error = failure.toOpenCloudError().safeMessage(getApplication()),
                            )
                        }
                    }
                }.onSuccess {
                    if (accountId == account) reduce { copy(bulkConflictCancelling = false) }
                }
        }
    }

    fun showGlobalActionUnavailable() =
        reduce {
            copy(
                message =
                    getApplication<Application>().localizedString(R.string.browser_preview_navigation_unavailable),
            )
        }

    fun clearMessage() = reduce { copy(message = null, error = null) }

    private fun observeDiscovery(workId: UUID) {
        latestDiscovery = workId
        reduce { copy(discoveryError = null) }
        viewModelScope.launch {
            workManager.getWorkInfoByIdFlow(workId).collectLatest { workInfo ->
                if (latestDiscovery == workId) reduce { copy(refreshing = workInfo?.state == WorkInfo.State.RUNNING) }
                if (latestDiscovery == workId && workInfo?.state == WorkInfo.State.FAILED) {
                    val message = workInfo.outputData.getString(DISCOVERY_ERROR)
                    reduce { copy(discoveryError = message ?: "Remote discovery failed.") }
                }
            }
        }
    }

    private fun setActiveLocation(
        spaceId: String,
        folderId: String?,
    ) {
        accountId?.let { accountId ->
            clearPlacementBusyWhenContextChanges(accountId, spaceId, folderId)
            val next = BrowserLocation(accountId, spaceId, folderId)
            if (activeLocation.value != next) {
                directoryOptions.update { it.copy(offset = 0, overlays = emptyList()) }
                reduce { copy(resources = emptyList(), directoryPage = null, selectedIds = emptySet()) }
            }
            activeLocation.value = next
            encryptedFolders.refresh(accountId, spaceId, folderId)
            viewModelScope.launch(Dispatchers.Main.immediate) {
                savedState["browser.account"] = accountId
                savedState["browser.space"] = spaceId
                savedState["browser.folder"] = folderId
            }
        }
    }

    private suspend fun restoreLocation(spaceId: String) {
        val account = requireNotNull(accountId)
        val folderId = restoredFolder.takeIf { restoredAccount == account && restoredSpace == spaceId }
        val trail = mutableListOf<FolderCrumb>()
        val visited = mutableSetOf<String>()
        var current = folderId?.let { store.resource(account, spaceId, it) }
        while (current?.kind == ResourceKind.FOLDER && visited.size < 256) {
            if (!visited.add(current.remoteId)) break
            trail.add(FolderCrumb(current.remoteId, current.name))
            current = current.parentId?.let { store.resource(account, spaceId, it) }
        }
        val restored = trail.asReversed().takeIf { current == null }.orEmpty()
        if (activeLocation.value != null) return // A shortcut or user navigation superseded saved-location loading.
        reduce { copy(currentFolderId = restored.lastOrNull()?.id, folderTrail = restored) }
        setActiveLocation(spaceId, restored.lastOrNull()?.id)
    }

    private fun mutate(action: suspend (String, String, String?) -> Unit) {
        val account = accountId ?: return
        val space = state.value.spaceId ?: return
        val parent = state.value.currentFolderId
        viewModelScope.launch {
            runCatching { withContext(Dispatchers.IO) { action(account, space, parent) } }
                .onSuccess { reduce { copy(selectedIds = emptySet(), actionResource = null) } }
                .onFailure {
                    reduce {
                        copy(
                            error = it.toOpenCloudError().safeMessage(getApplication()),
                        )
                    }
                }
        }
    }

    private fun selectedResources(): List<ResourceEntity> =
        (
            state.value.resources + state.value.searchResults + state.value.offlineResources +
                state.value.selectedResources
        ).distinctBy { it.selectionKey }
            .filter {
                it.selectionKey in state.value.selectedIds &&
                    !it.matchesEncryptedFolder(state.value.encryptedFolders)
            }

    @Suppress("TooGenericExceptionCaught") // Map failures at the UI boundary; the mapper rethrows cancellation.
    private fun batchAction(action: suspend (ResourceEntity) -> Unit) {
        val selected = selectedResources()
        if (selected.isEmpty()) return
        val location = activeLocation.value
        val owner = accountId ?: return
        val selection = state.value.selectedIds
        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    // Resolve every explicitly selected snapshot before starting a batch, including off-page rows.
                    val current =
                        selected.map { resource ->
                            ensureSelectionContext(location, selection, owner)
                            store.requireCurrentMutableResource(resource)
                        }
                    current.forEach { resource ->
                        ensureSelectionContext(location, selection, owner)
                        action(store.requireCurrentMutableResource(resource))
                    }
                }
                ensureSelectionContext(location, selection, owner)
            }.onSuccess { reduce { copy(selectedIds = emptySet()) } }
                .onFailure { reduce { copy(error = it.toOpenCloudError().safeMessage(getApplication())) } }
        }
    }

    private fun ensureSelectionContext(
        location: BrowserLocation?,
        selection: Set<String>,
        owner: String,
    ) {
        if (activeLocation.value != location ||
            state.value.selectedIds != selection ||
            owner != accountId
        ) {
            throw CancellationException("Selection is no longer current")
        }
    }

    private fun reduce(transform: FileBrowserUiState.() -> FileBrowserUiState) {
        mutableState.update { previous ->
            val next = previous.transform()
            next.withRetainedSelection(previous.selectedResources)
        }
    }
}

internal fun preferredInitialBrowserSpace(spaces: List<SpaceEntity>): SpaceEntity? =
    spaces.firstOrNull { it.type.equals("personal", ignoreCase = true) }

private fun Application.sourceDirectoryName(treeUri: Uri): String {
    val displayName =
        runCatching {
            val documentUri =
                DocumentsContract.buildDocumentUriUsingTree(
                    treeUri,
                    DocumentsContract.getTreeDocumentId(treeUri),
                )
            contentResolver
                .query(
                    documentUri,
                    arrayOf(DocumentsContract.Document.COLUMN_DISPLAY_NAME),
                    null,
                    null,
                    null,
                )?.use { cursor -> if (cursor.moveToFirst()) cursor.getString(0) else null }
        }.getOrNull()
    return displayName?.takeIf(String::isNotBlank) ?: sourceNameFromTreeUri(treeUri.toString())
}

internal fun sourceNameFromTreeUri(sourceTreeUri: String): String =
    Uri
        .decode(Uri.parse(sourceTreeUri).lastPathSegment.orEmpty())
        .substringAfterLast(':')
        .substringAfterLast('/')
        .ifBlank { "Folder" }

data class FileBrowserUiState(
    val fileDisplay: FileDisplayOptions = FileDisplayOptions(),
    val temporaryCopyRetentionHours: Int = 0,
    val exporting: Boolean = false,
    val exportStatus: String? = null,
    val clipboard: ResourceEntity? = null,
    val clipboardItems: List<ResourceEntity> = emptyList(),
    val moving: Boolean = false,
    val placementConflict: FileOperationPlacementConflict? = null,
    val placementBusy: Boolean = false,
    val operations: List<eu.opencloud.android.next.core.database.FileOperationEntity> = emptyList(),
    val spaces: List<SpaceEntity> = emptyList(),
    val spaceId: String? = null,
    val currentFolderId: String? = null,
    val folderTrail: List<FolderCrumb> = emptyList(),
    val resources: List<ResourceEntity> = emptyList(),
    val directoryPage: ResourceDirectoryPage? = null,
    val selectedResources: List<ResourceEntity> = emptyList(),
    val encryptedFolders: List<VaultLocation> = emptyList(),
    val encryptedFoldersError: String? = null,
    val encryptedCreationBusy: Boolean = false,
    val encryptedSpaceCreationRevision: Int = 0,
    val offlineResources: List<ResourceEntity> = emptyList(),
    val offlinePage: ResourceDirectoryPage? = null,
    val offlinePins: List<ResourceEntity> = emptyList(),
    val offlineBytes: Long = 0,
    val recentResources: List<ResourceEntity> = emptyList(),
    val transfers: List<TransferEntity> = emptyList(),
    val transferOverview: TransferBrowserOverview? = null,
    val bulkConflictCancelling: Boolean = false,
    val backups: List<FolderBackupEntity> = emptyList(),
    val backupPickerTrail: List<BackupFolderCrumb> = emptyList(),
    val backupPickerResources: List<ResourceEntity> = emptyList(),
    val backupPickerDestination: BackupDestination? = null,
    val backupPickerSharedRoots: List<BackupSharedRoot> = emptyList(),
    val backupPickerSharedNames: Map<String, String> = emptyMap(),
    val backupPickerSharedFolders: List<BackupSharedFolder> = emptyList(),
    val backupPickerPage: BackupPickerPageState? = null,
    val backupPickerLoading: Boolean = false,
    val backupPickerCanSelect: Boolean = false,
    val backupPickerError: String? = null,
    val layout: BrowserLayout = BrowserLayout.DEFAULT_TABLE,
    val selectedIds: Set<String> = emptySet(),
    val searchQuery: String = "",
    val searchResults: List<ResourceEntity> = emptyList(),
    val remoteSearchSupported: Boolean = false,
    val isRemoteSearchLoading: Boolean = false,
    val remoteSearchError: String? = null,
    val actionResource: ResourceEntity? = null,
    val message: String? = null,
    val error: String? = null,
    val refreshing: Boolean = false,
    val discoveryError: String? = null,
)

data class FileOperationPlacementConflict(
    val source: ResourceEntity,
    val destinationSpaceId: String,
    val parentId: String?,
    val moving: Boolean,
    val suggestedName: String,
)

private data class FileOperationPlacementTarget(
    val accountId: String,
    val spaceId: String,
    val parentId: String?,
)

data class FolderCrumb(
    val id: String,
    val name: String,
)

data class BackupFolderCrumb(
    val id: String,
    val name: String,
    val path: String,
)

private data class BrowserLocation(
    val accountId: String,
    val spaceId: String,
    val folderId: String?,
)

enum class BrowserLayout {
    DEFAULT_TABLE,
    CONDENSED_TABLE,
    TILES,
}

enum class ConflictDecision { REPLACE, KEEP_BOTH, CANCEL }

private fun SettingsBrowserLayout.toBrowserLayout() =
    when (this) {
        SettingsBrowserLayout.DEFAULT_TABLE -> BrowserLayout.DEFAULT_TABLE
        SettingsBrowserLayout.CONDENSED_TABLE -> BrowserLayout.CONDENSED_TABLE
        SettingsBrowserLayout.TILES -> BrowserLayout.TILES
    }

private fun BrowserLayout.toSettingsLayout() =
    when (this) {
        BrowserLayout.DEFAULT_TABLE -> SettingsBrowserLayout.DEFAULT_TABLE
        BrowserLayout.CONDENSED_TABLE -> SettingsBrowserLayout.CONDENSED_TABLE
        BrowserLayout.TILES -> SettingsBrowserLayout.TILES
    }

private data class DirectoryPageOptions(
    val sort: DirectorySort = DirectorySort.Name,
    val ascending: Boolean = true,
    val offset: Int = 0,
    val showHidden: Boolean = false,
    val overlays: List<DirectoryOverlay> = emptyList(),
)

private data class BackupPickerQuery(
    val location: BrowserLocation,
    val overlays: List<DirectoryOverlay>?,
    val offset: Int,
)

data class BackupPickerPageState(
    val offset: Int,
    val total: Int,
    val pageSize: Int,
) {
    val hasPrevious: Boolean get() = offset > 0
    val hasNext: Boolean get() = offset.toLong() + pageSize < total
}

private data class SharedBackupPickerSnapshot(
    val request: SharedFolderRequest,
    val page: SharedFolderPage,
    val cursor: SharedFolderPageCursorSnapshot,
    val canSelect: Boolean,
)

internal val VaultLocation.directoryOverlayId: String get() = "$driveId\u0000$remoteVaultId\u0000$vaultPath"

/** Retain only explicitly selected snapshots across bounded pages; current rows refresh those snapshots. */
internal fun FileBrowserUiState.withRetainedSelection(previous: List<ResourceEntity>): FileBrowserUiState {
    val selected =
        (resources + searchResults + offlineResources + previous)
            .distinctBy { it.selectionKey }
            .filter { it.selectionKey in selectedIds && !it.matchesEncryptedFolder(encryptedFolders) }
    return copy(selectedResources = selected)
}

/** All sources are already bounded windows or explicit selections; pin rows outside them are not retained. */
private fun FileBrowserUiState.pinCandidates(): List<ResourceEntity> =
    (resources + offlineResources + recentResources + searchResults + selectedResources + listOfNotNull(actionResource))
        .distinctBy { Triple(it.accountId, it.spaceId, it.remoteId) }
