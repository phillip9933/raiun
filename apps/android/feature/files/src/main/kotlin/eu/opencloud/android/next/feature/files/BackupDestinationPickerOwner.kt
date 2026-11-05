package eu.opencloud.android.next.feature.files

import android.app.Application
import eu.opencloud.android.next.core.database.DirectoryOverlay
import eu.opencloud.android.next.core.database.DirectorySort
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.RESOURCE_DIRECTORY_PAGE_SIZE
import eu.opencloud.android.next.core.database.ResourceDirectoryPage
import eu.opencloud.android.next.core.database.ResourceDirectoryPaging
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.designsystem.localizedString
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.sync.SharedFolderBrowser
import eu.opencloud.android.next.core.sync.SharedFolderPage
import eu.opencloud.android.next.core.sync.SharedFolderPageCursorSnapshot
import eu.opencloud.android.next.core.sync.SharedFolderRequest
import eu.opencloud.android.next.core.sync.SharedRootDiscovery
import eu.opencloud.android.next.core.sync.SharedUploadDestinationResolver
import eu.opencloud.android.next.core.sync.VaultRepository
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.mapLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID

/** Owns the backup destination picker's transient navigation and paging state. */
@OptIn(ExperimentalCoroutinesApi::class)
@Suppress("LargeClass", "ComplexCondition", "ReturnCount", "LongParameterList")
internal class BackupDestinationPickerOwner(
    private val application: Application,
    private val scope: CoroutineScope,
    private val directoryPaging: ResourceDirectoryPaging,
    store: FileBrowserStore,
    private val refreshFolder: (String, String, String?) -> UUID,
    private val createFolder: suspend (String, String, String?, String) -> Unit,
    private val state: StateFlow<FileBrowserUiState>,
    private val currentAccount: () -> String?,
    private val reduce: (FileBrowserUiState.() -> FileBrowserUiState) -> Unit,
    private val observeDiscovery: (UUID) -> Unit,
    private val ordinaryReads: BackupPickerOrdinaryReads? = null,
    private val mainDispatcher: CoroutineDispatcher = Dispatchers.Main.immediate,
) {
    private val accountId: String? get() = currentAccount()
    private val backupPickerLocation = MutableStateFlow<PickerLocation?>(null)
    private val backupPickerOffset = MutableStateFlow(0)
    private var backupPickerRevision = 0
    private var backupPickerVaultRevision = 0
    private var backupPickerSharedSnapshot: SharedBackupPickerSnapshot? = null
    private val backupPickerVaults = VaultRepository(application, store)
    private val sharedRoots = SharedRootDiscovery.create(application)
    private val sharedBrowser = SharedFolderBrowser.create(application)
    private val sharedDestinationResolver = SharedUploadDestinationResolver.create(application)

    fun start() {
        scope.launch(mainDispatcher) {
            backupPickerLocation
                .filterNotNull()
                .flatMapLatest { location ->
                    val pickerRevision = location.revision
                    (
                        ordinaryReads?.invalidations(location.accountId, location.spaceId, location.folderId)
                            ?: directoryPaging.invalidations(location.accountId, location.spaceId, location.folderId)
                    ).mapLatest {
                        loadBackupPickerOverlays(location, pickerRevision)
                    }.combine(backupPickerOffset) { overlays, offset ->
                        BackupPickerQuery(location, overlays, offset, pickerRevision)
                    }
                }.collectLatest { query ->
                    val location = query.location
                    val overlays = query.overlays
                    val offset = query.offset
                    val pickerRevision = query.pickerRevision
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

    fun resetForAccount() {
        backupPickerRevision++
        backupPickerVaultRevision++
        backupPickerSharedSnapshot = null
        backupPickerOffset.value = 0
        backupPickerLocation.value = null
        reduce {
            copy(
                backupPickerDestination = null,
                backupPickerSharedRoots = emptyList(),
                backupPickerSharedNames = emptyMap(),
                backupPickerSharedFolders = emptyList(),
                backupPickerResources = emptyList(),
                backupPickerTrail = emptyList(),
                backupPickerPage = null,
                backupPickerLoading = false,
                backupPickerCanSelect = false,
                backupPickerError = null,
            )
        }
    }

    @Suppress("TooGenericExceptionCaught") // UI boundary converts discovery errors and rethrows cancellation.
    private suspend fun loadBackupPickerOverlays(
        location: PickerLocation,
        pickerRevision: Int,
    ): List<DirectoryOverlay>? {
        if (!isCurrentBackupPickerLocation(location, pickerRevision)) return null
        return try {
            val path = location.path
            withContext(Dispatchers.IO) {
                ordinaryReads?.overlays(location.accountId, location.spaceId, path)
                    ?: backupPickerVaults.encryptedFolders(location.accountId, location.spaceId, path).map { root ->
                        DirectoryOverlay(root.directoryOverlayId, root.title, root.remoteVaultId, root.vaultPath)
                    }
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            if (isCurrentBackupPickerLocation(location, pickerRevision)) {
                reduce {
                    copy(
                        backupPickerResources = emptyList(),
                        backupPickerLoading = false,
                        backupPickerCanSelect = false,
                        backupPickerError = failure.toOpenCloudError().safeMessage(application),
                    )
                }
            }
            null
        }
    }

    private fun isCurrentBackupPickerLocation(
        location: PickerLocation,
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
        location: PickerLocation,
        overlays: List<DirectoryOverlay>,
        offset: Int,
        pageRevision: Int,
        pickerRevision: Int,
    ) {
        try {
            val page =
                withContext(Dispatchers.IO) {
                    ordinaryReads?.load(location.accountId, location.spaceId, location.folderId, offset, overlays)
                        ?: directoryPaging.load(
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
                }
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
                        backupPickerError = failure.toOpenCloudError().safeMessage(application),
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
        scope.launch(mainDispatcher) {
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
                                backupPickerError = it.toOpenCloudError().safeMessage(application),
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
        val label = "${application.localizedString(category)} · ${space.name}"
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
        backupPickerLocation.value = PickerLocation(account, space.driveId, null, "", backupPickerRevision)
        observeDiscovery(refreshFolder(account, space.driveId, null))
    }

    fun openBackupPickerShare(root: BackupSharedRoot) {
        val account = accountId ?: return
        backupPickerOffset.value = 0
        backupPickerLocation.value = null
        val label = "${application.localizedString(
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
        scope.launch(mainDispatcher) {
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
                            backupPickerError = it.toOpenCloudError().safeMessage(application),
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
        scope.launch(mainDispatcher) {
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
                            backupPickerError = failure.toOpenCloudError().safeMessage(application),
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
        backupPickerRevision++
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
        backupPickerLocation.value =
            PickerLocation(account, folder.spaceId, folder.remoteId, folder.path.trim('/'), backupPickerRevision)
        observeDiscovery(refreshFolder(account, folder.spaceId, folder.remoteId))
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
            backupPickerRevision++
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
            backupPickerLocation.value =
                PickerLocation(
                    account,
                    current.spaceId,
                    nextTrail.lastOrNull()?.id,
                    nextTrail.lastOrNull()?.path?.trim('/') ?: "",
                    backupPickerRevision,
                )
            observeDiscovery(refreshFolder(account, current.spaceId, nextTrail.lastOrNull()?.id))
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
        val revision = backupPickerRevision
        scope.launch(mainDispatcher) {
            runCatching { withContext(Dispatchers.IO) { createFolder(account, space, parentId, name) } }
                .onFailure {
                    if (accountId == account && revision == backupPickerRevision) {
                        reduce { copy(error = it.toOpenCloudError().safeMessage(application)) }
                    }
                }
        }
    }
}

private data class BackupPickerQuery(
    val location: PickerLocation,
    val overlays: List<DirectoryOverlay>?,
    val offset: Int,
    val pickerRevision: Int,
)

private data class SharedBackupPickerSnapshot(
    val request: SharedFolderRequest,
    val page: SharedFolderPage,
    val cursor: SharedFolderPageCursorSnapshot,
    val canSelect: Boolean,
)

private data class PickerLocation(
    val accountId: String,
    val spaceId: String,
    val folderId: String?,
    val path: String,
    val revision: Int,
)

/** Optional bounded reads used to exercise the existing picker lifecycle guards deterministically. */
internal interface BackupPickerOrdinaryReads {
    fun invalidations(
        account: String,
        space: String,
        parent: String?,
    ): Flow<Int>

    suspend fun overlays(
        account: String,
        space: String,
        path: String,
    ): List<DirectoryOverlay>

    suspend fun load(
        account: String,
        space: String,
        parent: String?,
        offset: Int,
        overlays: List<DirectoryOverlay>,
    ): ResourceDirectoryPage
}
