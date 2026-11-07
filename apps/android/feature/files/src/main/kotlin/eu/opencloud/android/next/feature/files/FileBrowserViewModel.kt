package eu.opencloud.android.next.feature.files

import android.app.Application
import android.net.Uri
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
import eu.opencloud.android.next.core.database.TransferEntity
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
import eu.opencloud.android.next.core.sync.SpaceCreationResult
import eu.opencloud.android.next.core.sync.TransferManager
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.createSearchRepository
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.map
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
    private val accountContext = BrowserAccountContext()
    private val accountBindings = MutableStateFlow<BrowserAccountBinding?>(null)
    private val offlineBindings = MutableStateFlow<Pair<BrowserAccountBinding, Long>?>(null)
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
    private val activeLocation = MutableStateFlow<BrowserLocation?>(null)
    private val sharedInventory = IncomingShareStore(FileBrowserDatabase.create(application))
    private val searchQuery = MutableStateFlow("")
    private val collectionSearchOnly = MutableStateFlow(false)
    val state: StateFlow<FileBrowserUiState> = mutableState.asStateFlow()

    private var accountId: String? = null
    private var latestDiscovery: UUID? = null
    private var creatingSpace = false
    private val locationLoader =
        BrowserLocationLoader(
            context = accountContext,
            read = store::resource,
            publish = { request, trail ->
                val folder = trail.lastOrNull()?.id
                reduce {
                    if (request.restoring) {
                        copy(spaceId = request.spaceId, currentFolderId = folder, folderTrail = trail)
                    } else {
                        copy(
                            spaceId = request.spaceId,
                            currentFolderId = folder,
                            folderTrail = trail,
                            selectedIds = emptySet(),
                            searchQuery = "",
                            searchResults = emptyList(),
                        )
                    }
                }
                setActiveLocation(request.spaceId, folder)
                if (!request.restoring) {
                    observeDiscovery(transfers.refreshFolder(request.binding.accountId, request.spaceId, folder))
                }
            },
            incomplete = { request ->
                reportOpenError("The folder location is incomplete. Refresh its Space and try again.")
                if (activeLocation.value == null) {
                    val space = admittedBrowserSpace(state.value.spaces, null, state.value.spaceId)
                    if (space != null) {
                        reduce { copy(spaceId = space.driveId, currentFolderId = null, folderTrail = emptyList()) }
                        setActiveLocation(space.driveId, null)
                        observeDiscovery(transfers.refreshFolder(request.binding.accountId, space.driveId, null))
                    }
                }
            },
        )
    private val exports =
        OrdinaryExportOwner(
            scope = viewModelScope,
            accountContext = accountContext,
            files = AndroidOrdinaryExportFiles(application, store, transfers),
            reduce = ::reduce,
        )
    private val backupCommands =
        BrowserBackupCommands(
            scope = viewModelScope,
            accountContext = accountContext,
            state = state,
            backend = AndroidBrowserBackupBackend(application, store, transfers),
            reduce = ::reduce,
            failureMessage = { it.toOpenCloudError().safeMessage(getApplication()) },
            configuredMessage = { application.localizedString(R.string.browser_backup_configured) },
        )
    private val transferCommands =
        BrowserTransferCommands(
            scope = viewModelScope,
            accountContext = accountContext,
            state = state,
            backend = AndroidBrowserTransferBackend(transfers),
            reduce = ::reduce,
            failureMessage = { it.toOpenCloudError().safeMessage(getApplication()) },
        )
    private val placement =
        OrdinaryPlacementOwner(
            scope = viewModelScope,
            state = state,
            currentAccount = { accountId },
            reduce = ::reduce,
            failureMessage = { it.toOpenCloudError().safeMessage(getApplication()) },
            enqueue = { source, space, parent, name, move, namingBase ->
                operations.enqueue(source, space, parent, name, move, namingBase)
            },
        )
    private val backupPicker =
        BackupDestinationPickerOwner(
            application = application,
            scope = viewModelScope,
            directoryPaging = directoryPaging,
            store = store,
            refreshFolder = transfers::refreshFolder,
            createFolder = { account, space, parent, name ->
                transfers.createFolder(account, space, parent, name)
            },
            state = state,
            currentAccount = { accountId },
            reduce = ::reduce,
            observeDiscovery = ::observeDiscovery,
        )
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
            onCreated = { binding, created, parent ->
                if (accountContext.binding == binding) {
                    if (parent == null) {
                        observeDiscovery(transfers.refreshAccount(created.accountId))
                        reduce { copy(encryptedSpaceCreationRevision = encryptedSpaceCreationRevision + 1) }
                    } else if (activeLocation.value?.let {
                            it.accountId == parent.accountId &&
                                it.spaceId == parent.driveId &&
                                it.folderId == parent.folderId
                        } == true
                    ) {
                        observeDiscovery(transfers.refreshFolder(parent.accountId, parent.driveId, parent.folderId))
                        encryptedFolders.refresh(parent.accountId, parent.driveId, parent.folderId)
                    }
                }
            },
            onUncertain = { binding ->
                if (accountContext.binding == binding) {
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
        observeOfflineContent()
        viewModelScope.launch(Dispatchers.IO) {
            settings.settings.collectLatest { settings ->
                withContext(Dispatchers.Main.immediate) {
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
        }
        observeDirectoryContent()
        observeSearchContent()
        backupPicker.start()
    }

    private fun observeOfflineContent() {
        viewModelScope.launch(Dispatchers.IO) {
            offlineBindings
                .flatMapLatest { owner ->
                    offlinePager.state.map { cached -> Triple(owner?.first, owner?.second, cached) }
                }.collectLatest { (binding, revision, cached) ->
                    if (binding != null) {
                        accountContext.publishAccount(binding) {
                            val request = cached.request
                            if (request != null &&
                                request.account == binding.accountId &&
                                request.accountRevision == revision &&
                                offlinePager.isCurrent(request)
                            ) {
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
                                        error =
                                            cached.error?.toOpenCloudError()?.safeMessage(
                                                getApplication(),
                                            ) ?: error,
                                    )
                                }
                            }
                        }
                    }
                }
        }
    }

    private fun observeDirectoryContent() {
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
                    if (result != null) {
                        accountContext.publishAccount(result.first.binding) {
                            if (activeLocation.value == result.first && directoryOptions.value == result.second) {
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
                }
        }
    }

    private fun observeSearchContent() {
        viewModelScope.launch(Dispatchers.IO) {
            combine(accountBindings, searchQuery, collectionSearchOnly) { binding, query, cachedOnly ->
                BrowserSearchRequest(binding, query, cachedOnly)
            }.flatMapLatest { request ->
                val binding = request.binding
                if (request.cachedOnly || binding == null || request.query.isBlank()) {
                    flowOf(request to SearchRepositoryResult(emptyList(), remoteSupported = false))
                } else {
                    searchRepository.search(binding.accountId, request.query).map { request to it }
                }
            }.collectLatest { (request, result) ->
                request.binding?.let { binding ->
                    accountContext.publishAccount(binding) {
                        if (request.query == searchQuery.value && request.cachedOnly == collectionSearchOnly.value) {
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
                }
            }
        }
    }

    fun load(accountId: String) {
        if (this.accountId == accountId) return
        placement.contextChanged()
        accountJob?.cancel()
        this.accountId = accountId
        val binding = accountContext.beginAccount(accountId)
        latestDiscovery = null
        val offlineRevision = offlinePager.account(accountId).accountRevision
        searchQuery.value = ""
        activeLocation.value = null
        directoryOptions.value = DirectoryPageOptions(showHidden = state.value.fileDisplay.showHidden)
        reduce { forAccountLoad(binding) }
        backupPicker.resetForAccount()
        encryptedFolders.invalidate()
        offlineBindings.value = binding to offlineRevision
        accountBindings.value = binding
        accountJob =
            viewModelScope.launch(Dispatchers.IO) {
                launch {
                    sharedInventory.observe(accountId).collectLatest { shares ->
                        accountContext.publishAccount(binding) {
                            reduce {
                                copy(
                                    backupPickerSharedNames =
                                        shares.filter { it.isFolder }.associate { it.id to it.name },
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
                        }.collectLatest { values ->
                            accountContext.publishAccount(binding) { reduce { copy(recentResources = values) } }
                        }
                }
                launch {
                    store.transferInventory().invalidations(accountId).collectLatest {
                        refreshTransferOverview(binding)
                    }
                }
                launch {
                    store.observeBackups(accountId).collectLatest { backups ->
                        accountContext.publishAccount(binding) { reduce { copy(backups = backups) } }
                    }
                }
                launch {
                    mutableState
                        .map { it.pinCandidates() }
                        .distinctUntilChanged()
                        .combine(collectionPaging.invalidations(accountId)) { resources, _ -> resources }
                        .collectLatest { resources ->
                            val pins = collectionPaging.keptOffline(resources)
                            accountContext.publishAccount(binding) { reduce { copy(offlinePins = pins) } }
                        }
                }
                launch { transfers.reconcile() }
                launch { operations.reconcile() }
                launch {
                    operations.observe(accountId).collectLatest { values ->
                        accountContext.publishAccount(binding) { reduce { copy(operations = values) } }
                    }
                }
                accountContext.publishAccount(binding) { observeDiscovery(transfers.refreshAccount(accountId)) }
                observeAccountSpaces(binding)
            }
    }

    private suspend fun observeAccountSpaces(binding: BrowserAccountBinding) {
        store.observeSpaces(binding.accountId).collectLatest { spaces ->
            var restore: BrowserLocationRequest? = null
            accountContext.publishAccount(binding) {
                val active = activeLocation.value
                val selectedSpace = admittedBrowserSpace(spaces, active?.spaceId, state.value.spaceId)
                val removed = active != null && spaces.none { it.driveId == active.spaceId }
                if (removed) {
                    accountContext.locationUnavailable()
                    placement.contextChanged()
                    activeLocation.value = null
                    reduce {
                        copy(
                            currentFolderId = null,
                            folderTrail = emptyList(),
                            resources = emptyList(),
                            directoryPage = null,
                            selectedIds = emptySet(),
                        )
                    }
                }
                reduce { copy(spaces = spaces, spaceId = selectedSpace?.driveId) }
                if (activeLocation.value == null && selectedSpace != null) {
                    val folder =
                        restoredFolder.takeIf {
                            !removed && restoredAccount == binding.accountId && restoredSpace == selectedSpace.driveId
                        }
                    restore = accountContext.restore(binding, selectedSpace.driveId, folder)
                }
            }
            restore?.let { locationLoader.resolve(it) }
        }
    }

    fun selectSpace(spaceId: String) {
        accountContext.userNavigation()
        reduce { copy(spaceId = spaceId, currentFolderId = null, folderTrail = emptyList(), selectedIds = emptySet()) }
        setActiveLocation(spaceId, null)
        accountId?.let { observeDiscovery(transfers.refreshFolder(it, spaceId, null)) }
    }

    fun recordOpened(resource: ResourceEntity) {
        if (accountContext.admitResource(resource) == null) return
        recentFiles.record(resource.accountId, resource.spaceId, resource.remoteId)
    }

    suspend fun prepareExternalFile(resource: ResourceEntity): ResourceEntity = exports.prepareExternalFile(resource)

    fun exportFile(
        spaceId: String,
        resourceId: String,
        destination: Uri,
        removeLocal: Boolean,
    ) {
        exports.exportFile(spaceId, resourceId, destination, removeLocal)
    }

    fun dismissExportStatus() = reduce { copy(exportStatus = null) }

    fun refresh() {
        val location = activeLocation.value ?: return
        observeDiscovery(transfers.refreshFolder(location.accountId, location.spaceId, location.folderId))
        encryptedFolders.refresh(location.accountId, location.spaceId, location.folderId)
    }

    fun open(resource: ResourceEntity) {
        if (accountContext.admitResource(resource) == null || resource.kind != ResourceKind.FOLDER) return
        accountContext.userNavigation()
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
        val binding = accountContext.admitResource(resource) ?: return
        val request = accountContext.shortcut(binding, resource) ?: return
        viewModelScope.launch(Dispatchers.IO) { locationLoader.resolve(request) }
    }

    fun navigateUp() {
        val trail = state.value.folderTrail
        if (trail.isEmpty()) return
        accountContext.userNavigation()
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
    private suspend fun refreshTransferOverview(binding: BrowserAccountBinding) {
        try {
            val overview = store.transferInventory().overview(binding.accountId)
            accountContext.publishAccount(binding) { reduce { copy(transferOverview = overview) } }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            accountContext.publishAccount(binding) {
                reduce { copy(error = failure.toOpenCloudError().safeMessage(getApplication())) }
            }
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
            accountContext.publishAccount(location.binding) {
                if (activeLocation.value == location && directoryOptions.value == options) {
                    reduce { copy(error = failure.toOpenCloudError().safeMessage(getApplication())) }
                }
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

    fun showActions(resource: ResourceEntity?) {
        if (resource != null && accountContext.admitResource(resource) == null) return
        reduce { copy(actionResource = resource) }
    }

    fun dismissActions() = reduce { copy(actionResource = null) }

    fun createFolder(name: String) =
        mutate { account, space, parent -> transfers.createFolder(account, space, parent, name) }

    fun createEncryptedFolder(
        name: String,
        password: CharArray,
    ) {
        val binding = accountContext.binding
        val location = activeLocation.value
        if (binding == null || location == null || location.binding != binding) {
            password.fill('\u0000')
            return
        }
        encryptedCreation.folder(binding, location.spaceId, location.folderId, name, password)
    }

    fun createEncryptedSpace(
        name: String,
        password: CharArray,
    ) {
        val binding = accountContext.binding
        if (binding == null) {
            password.fill('\u0000')
            return
        }
        encryptedCreation.space(binding, name, password)
    }

    fun createSpace(name: String) {
        val binding = accountContext.binding ?: return
        val account = binding.accountId
        if (creatingSpace) return
        creatingSpace = true
        viewModelScope.launch {
            try {
                runCatching { createProjectSpace(getApplication(), store, account, name) }
                    .onSuccess { result ->
                        if (accountId == account && result is SpaceCreationResult.AwaitingDiscovery) {
                            reduce(binding) { copy(message = result.message(getApplication())) }
                        }
                    }.onFailure {
                        val message = it.toOpenCloudError().safeMessage(getApplication())
                        if (accountId == account) reduce(binding) { copy(error = message) }
                    }
            } finally {
                creatingSpace = false
            }
        }
    }

    fun rename(
        resource: ResourceEntity,
        name: String,
    ) = mutateResource(resource) {
        if (name != resource.name) {
            try {
                operations.enqueue(resource, resource.spaceId, resource.parentId, name, true)
            } catch (_: FileOperationNameConflictException) {
                throw OpenCloudException(OpenCloudError.Conflict)
            }
        }
    }

    fun move(resource: ResourceEntity) {
        if (accountContext.admitResource(resource) == null) return
        reduce { copy(clipboard = resource, clipboardItems = emptyList(), moving = true, actionResource = null) }
    }

    fun copy(resource: ResourceEntity) {
        if (accountContext.admitResource(resource) == null) return
        reduce { copy(clipboard = resource, clipboardItems = emptyList(), moving = false, actionResource = null) }
    }

    fun moveSelection() = prepareSelection(true)

    fun copySelection() = prepareSelection(false)

    fun favoriteSelection() = batchAction { transfers.setFavorite(it, true) }

    private fun prepareSelection(move: Boolean) {
        val captured = selectedResources()
        if (captured.isEmpty()) return
        val location = activeLocation.value
        val owner = accountContext.binding ?: return
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
                reduce(owner) {
                    copy(
                        clipboard = sources.firstOrNull(),
                        clipboardItems = sources,
                        moving = move,
                        selectedIds = emptySet(),
                    )
                }
            }.onFailure { reduce(owner) { copy(error = it.toOpenCloudError().safeMessage(getApplication())) } }
        }
    }

    fun cancelPlacement() = placement.cancelPlacement()

    fun place() = placement.place()

    fun keepBothPlacementConflict() = placement.keepBothPlacementConflict()

    fun retryOperation(id: String) =
        mutate { account, _, _ ->
            operations.retry(id, account)
        }

    fun dismissOperation(id: String) = mutate { account, _, _ -> operations.dismiss(id, account) }

    fun delete(resource: ResourceEntity) = mutateResource(resource) { transfers.delete(resource) }

    fun upload(uri: Uri) {
        val binding = accountContext.binding ?: return
        val account = binding.accountId
        val space = state.value.spaceId ?: return
        val parentPath =
            state.value.folderTrail
                .joinToString(separator = "/", prefix = "/") { it.name }
                .takeIf { state.value.folderTrail.isNotEmpty() }
        viewModelScope.launch {
            runCatching { withContext(Dispatchers.IO) { transfers.enqueueUpload(account, space, parentPath, uri) } }
                .onFailure { reduce(binding) { copy(error = it.toOpenCloudError().safeMessage(getApplication())) } }
        }
    }

    fun removeLocalCopy(resource: ResourceEntity) = mutateResource(resource) { transfers.removeLocalCopy(resource) }

    fun downloadForOffline(resource: ResourceEntity) {
        val binding = accountContext.admitResource(resource) ?: return
        viewModelScope.launch {
            runCatching { withContext(Dispatchers.IO) { transfers.makeAvailableOffline(resource) } }
                .onSuccess { reduce(binding) { copy(actionResource = null) } }
                .onFailure { reduce(binding) { copy(error = it.toOpenCloudError().safeMessage(getApplication())) } }
        }
    }

    fun toggleFavorite(resource: ResourceEntity) {
        val binding = accountContext.admitResource(resource) ?: return
        viewModelScope.launch {
            runCatching { withContext(Dispatchers.IO) { transfers.setFavorite(resource, !resource.isFavorite) } }
                .onSuccess {
                    reduce(binding) {
                        copy(
                            actionResource = null,
                            message = null,
                        )
                    }
                }.onFailure { reduce(binding) { copy(error = it.toOpenCloudError().safeMessage(getApplication())) } }
        }
    }

    fun setCollectionSearchOnly(cachedOnly: Boolean) {
        collectionSearchOnly.value = cachedOnly
    }

    fun setSearchQuery(query: String) {
        reduce { copy(searchQuery = query, remoteSearchError = null) }
        searchQuery.value = query
    }

    fun saveBackup(
        sourceTreeUri: Uri,
        draft: BackupDraft,
    ) = backupCommands.saveBackup(sourceTreeUri, draft)

    fun scanBackupsNow() = backupCommands.scanBackupsNow()

    fun deleteBackup(id: String) = backupCommands.deleteBackup(id)

    fun completeBackupSourceSelection(
        expectedAccountId: String?,
        expectedBackupId: String?,
        expectedFingerprint: String?,
        draft: BackupDraft,
        selectedSource: Uri,
    ) = backupCommands.completeBackupSourceSelection(
        expectedAccountId,
        expectedBackupId,
        expectedFingerprint,
        draft,
        selectedSource,
    )

    fun updateBackup(
        backup: FolderBackupEntity,
        draft: BackupDraft,
        selectedSource: Uri? = null,
    ) = backupCommands.updateBackup(backup, draft, selectedSource)

    fun openBackupPicker() = backupPicker.openBackupPicker()

    fun openBackupPickerSpace(space: SpaceEntity) = backupPicker.openBackupPickerSpace(space)

    fun openBackupPickerShare(root: BackupSharedRoot) = backupPicker.openBackupPickerShare(root)

    fun pageBackupPicker(previous: Boolean) = backupPicker.pageBackupPicker(previous)

    fun openBackupPickerSharedFolder(folder: BackupSharedFolder) = backupPicker.openBackupPickerSharedFolder(folder)

    fun openBackupPickerFolder(folder: ResourceEntity) {
        if (accountContext.admitResource(folder) == null) return
        backupPicker.openBackupPickerFolder(folder)
    }

    fun navigateBackupPickerUp() = backupPicker.navigateBackupPickerUp()

    fun createBackupPickerFolder(name: String) = backupPicker.createBackupPickerFolder(name)

    fun resolveConflict(
        transfer: TransferEntity,
        decision: ConflictDecision,
    ) = transferCommands.resolveConflict(transfer, decision)

    fun cancelUploadConflicts() = transferCommands.cancelUploadConflicts()

    fun showGlobalActionUnavailable() =
        reduce {
            copy(
                message =
                    getApplication<Application>().localizedString(R.string.browser_preview_navigation_unavailable),
            )
        }

    fun clearMessage() = reduce { copy(message = null, error = null) }

    private fun observeDiscovery(workId: UUID) {
        val binding = accountContext.binding ?: return
        latestDiscovery = workId
        reduce { copy(discoveryError = null) }
        viewModelScope.launch {
            workManager.getWorkInfoByIdFlow(workId).collectLatest { workInfo ->
                accountContext.publishAccount(binding) {
                    if (latestDiscovery ==
                        workId
                    ) {
                        reduce { copy(refreshing = workInfo?.state == WorkInfo.State.RUNNING) }
                    }
                    if (latestDiscovery == workId && workInfo?.state == WorkInfo.State.FAILED) {
                        val message = workInfo.outputData.getString(DISCOVERY_ERROR)
                        reduce { copy(discoveryError = message ?: "Remote discovery failed.") }
                    }
                }
            }
        }
    }

    private fun setActiveLocation(
        spaceId: String,
        folderId: String?,
    ) {
        accountId?.let { accountId ->
            val next = BrowserLocation(requireNotNull(accountContext.binding), spaceId, folderId)
            if (activeLocation.value != next) {
                placement.contextChanged()
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

    private fun mutateResource(
        resource: ResourceEntity,
        action: suspend () -> Unit,
    ) {
        if (accountContext.admitResource(resource) == null) return
        mutate { _, _, _ -> action() }
    }

    private fun mutate(action: suspend (String, String, String?) -> Unit) {
        val binding = accountContext.binding ?: return
        val account = binding.accountId
        val space = state.value.spaceId ?: return
        val parent = state.value.currentFolderId
        viewModelScope.launch {
            runCatching { withContext(Dispatchers.IO) { action(account, space, parent) } }
                .onSuccess { reduce(binding) { copy(selectedIds = emptySet(), actionResource = null) } }
                .onFailure {
                    reduce(binding) {
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
        val owner = accountContext.binding ?: return
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
            }.onSuccess { reduce(owner) { copy(selectedIds = emptySet()) } }
                .onFailure { reduce(owner) { copy(error = it.toOpenCloudError().safeMessage(getApplication())) } }
        }
    }

    private fun ensureSelectionContext(
        location: BrowserLocation?,
        selection: Set<String>,
        owner: BrowserAccountBinding,
    ) {
        if (activeLocation.value != location ||
            state.value.selectedIds != selection ||
            owner != accountContext.binding
        ) {
            throw CancellationException("Selection is no longer current")
        }
    }

    private suspend fun reduce(
        binding: BrowserAccountBinding,
        transform: FileBrowserUiState.() -> FileBrowserUiState,
    ) = accountContext.publishAccount(binding) { reduce(transform) }

    private fun reduce(transform: FileBrowserUiState.() -> FileBrowserUiState) {
        mutableState.update { previous ->
            val next = previous.transform()
            next.withRetainedSelection(previous.selectedResources)
        }
    }
}

internal fun preferredInitialBrowserSpace(spaces: List<SpaceEntity>): SpaceEntity? =
    spaces.firstOrNull { it.type.equals("personal", ignoreCase = true) }

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
    val accountRevision: Long = 0,
)

data class FileOperationPlacementConflict(
    val source: ResourceEntity,
    val destinationSpaceId: String,
    val parentId: String?,
    val moving: Boolean,
    val suggestedName: String,
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
    val binding: BrowserAccountBinding,
    val spaceId: String,
    val folderId: String?,
) {
    val accountId: String get() = binding.accountId
}

private data class BrowserSearchRequest(
    val binding: BrowserAccountBinding?,
    val query: String,
    val cachedOnly: Boolean,
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

data class BackupPickerPageState(
    val offset: Int,
    val total: Int,
    val pageSize: Int,
) {
    val hasPrevious: Boolean get() = offset > 0
    val hasNext: Boolean get() = offset.toLong() + pageSize < total
}

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
