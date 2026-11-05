package eu.opencloud.android.next.feature.files

import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.database.TransferBrowserOverview
import eu.opencloud.android.next.core.model.ResourceKind
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.withContext

internal data class BrowserAccountBinding(
    val accountId: String,
    private val epoch: Long,
) {
    /** Presentation lifetime only; never persisted or used as a backend/account identifier. */
    val accountRevision: Long get() = epoch
}

internal data class BrowserLocationRequest(
    val binding: BrowserAccountBinding,
    val navigation: Long,
    val spaceId: String,
    val folderId: String?,
    val restoring: Boolean,
)

/** Main-thread admission for one account load and its requested browser navigation. */
internal class BrowserAccountContext(
    private val mainDispatcher: CoroutineDispatcher = Dispatchers.Main.immediate,
) {
    private var epoch = 0L
    private var navigation = 0L
    private val current = MutableStateFlow<BrowserAccountBinding?>(null)
    private var automaticRestoreAllowed = true
    val binding: BrowserAccountBinding? get() = current.value

    fun beginAccount(accountId: String): BrowserAccountBinding {
        epoch = Math.incrementExact(epoch)
        navigation = 0
        automaticRestoreAllowed = true
        return BrowserAccountBinding(accountId, epoch).also { current.value = it }
    }

    /** A resource-bearing UI callback may only start work for the currently displayed account. */
    fun admitResource(resource: ResourceEntity): BrowserAccountBinding? =
        binding?.takeIf { resource.accountId == it.accountId }

    fun userNavigation() {
        navigation = Math.incrementExact(navigation)
        automaticRestoreAllowed = false
    }

    fun shortcut(
        binding: BrowserAccountBinding,
        resource: ResourceEntity,
    ): BrowserLocationRequest? {
        if (current.value != binding || resource.accountId != binding.accountId) return null
        userNavigation()
        val folder = if (resource.kind == ResourceKind.FOLDER) resource.remoteId else resource.parentId
        return BrowserLocationRequest(binding, navigation, resource.spaceId, folder, false)
    }

    fun restore(
        binding: BrowserAccountBinding,
        space: String,
        folder: String?,
    ): BrowserLocationRequest? =
        if (current.value == binding && automaticRestoreAllowed) {
            BrowserLocationRequest(binding, navigation, space, folder, true)
        } else {
            null
        }

    fun locationUnavailable() {
        userNavigation()
        automaticRestoreAllowed = true
    }

    fun allowFallback(request: BrowserLocationRequest) {
        if (current.value == request.binding && navigation == request.navigation) automaticRestoreAllowed = true
    }

    suspend fun publishAccount(
        binding: BrowserAccountBinding,
        publish: () -> Unit,
    ) {
        withContext(mainDispatcher) {
            currentCoroutineContext().ensureActive()
            if (current.value == binding) publish()
        }
    }

    suspend fun publishLocation(
        request: BrowserLocationRequest,
        publish: () -> Unit,
    ) {
        publishAccount(request.binding) {
            if (navigation == request.navigation) publish()
        }
    }
}

/** Reads can finish after cancellation; only Main-thread binding/navigation admission publishes their result. */
internal class BrowserLocationLoader(
    private val context: BrowserAccountContext,
    private val read: suspend (String, String, String) -> ResourceEntity?,
    private val publish: (BrowserLocationRequest, List<FolderCrumb>) -> Unit,
    private val incomplete: (BrowserLocationRequest) -> Unit,
) {
    @Suppress("TooGenericExceptionCaught") // Storage failures use bounded location recovery; cancellation propagates.
    suspend fun resolve(request: BrowserLocationRequest) {
        val trail =
            try {
                readTrail(request)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                context.publishLocation(request) {
                    context.allowFallback(request)
                    incomplete(request)
                }
                return
            }
        context.publishLocation(request) {
            if (trail == null && !request.restoring) {
                context.allowFallback(request)
                incomplete(request)
            } else {
                publish(request, trail.orEmpty())
            }
        }
    }

    private suspend fun readTrail(request: BrowserLocationRequest): List<FolderCrumb>? {
        val trail = mutableListOf<FolderCrumb>()
        val visited = mutableSetOf<String>()
        var pending = request.folderId
        var folder = pending?.let { read(request.binding.accountId, request.spaceId, it) }
        while (folder?.kind == ResourceKind.FOLDER && visited.size < 256) {
            if (!visited.add(folder.remoteId)) break
            trail.add(FolderCrumb(folder.remoteId, folder.name))
            pending = folder.parentId
            folder = pending?.let { read(request.binding.accountId, request.spaceId, it) }
        }
        // Restore retains the existing root fallback; shortcuts require the complete trail.
        val complete = if (request.restoring) folder == null else pending == null
        return trail.asReversed().takeIf { complete }
    }
}

internal fun admittedBrowserSpace(
    spaces: List<SpaceEntity>,
    activeSpace: String?,
    displayedSpace: String?,
): SpaceEntity? =
    spaces.firstOrNull { it.driveId == activeSpace }
        ?: spaces.firstOrNull { it.driveId == displayedSpace }
        ?: preferredInitialBrowserSpace(spaces)

/** Preferences survive an account change; prior account resources and action metadata do not. */
internal fun FileBrowserUiState.forAccountLoad(binding: BrowserAccountBinding? = null): FileBrowserUiState =
    copy(
        accountRevision = binding?.accountRevision ?: accountRevision,
        exporting = false,
        exportStatus = null,
        remoteSearchSupported = false,
        isRemoteSearchLoading = false,
        remoteSearchError = null,
        spaces = emptyList(),
        spaceId = null,
        currentFolderId = null,
        folderTrail = emptyList(),
        backups = emptyList(),
        operations = emptyList(),
        clipboard = null,
        clipboardItems = emptyList(),
        moving = false,
        placementBusy = false,
        placementConflict = null,
        encryptedFolders = emptyList(),
        encryptedFoldersError = null,
        refreshing = false,
        discoveryError = null,
        error = null,
        message = null,
        transfers = emptyList(),
        transferOverview = TransferBrowserOverview(),
        bulkConflictCancelling = false,
        selectedIds = emptySet(),
        selectedResources = emptyList(),
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
