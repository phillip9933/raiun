package eu.opencloud.android.next.feature.files

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.sync.TransferManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

class ScannerDestinationPickerViewModel(
    application: Application,
) : AndroidViewModel(application) {
    private val store = FileBrowserStore(FileBrowserDatabase.create(application))
    private val transfers = TransferManager(application, store)
    private val mutableState = MutableStateFlow(ScannerDestinationPickerState())
    val state = mutableState.asStateFlow()
    private var browseJob: Job? = null
    private var setupJob: Job? = null
    private var accountId: String? = null
    private var initialSpaceId: String? = null
    private var initialPath: String? = null

    fun load(
        account: String,
        space: String,
        path: String,
    ) {
        accountId = account
        initialSpaceId = space
        initialPath = path
        setupJob?.cancel()
        browseJob?.cancel()
        mutableState.value = ScannerDestinationPickerState(busy = true)
        setupJob =
            viewModelScope.launch(Dispatchers.IO) {
                incomingAction({
                    val accountLabel =
                        store
                            .account(account)
                            ?.let {
                                "${it.displayName} · ${android.net.Uri.parse(it.serverUrl).host.orEmpty()}"
                            }.orEmpty()
                    val available = store.spaces(account).filter { !it.isDeleted && !it.isDisabled }
                    mutableState.value =
                        ScannerDestinationPickerState(spaces = available, busy = true, accountLabel = accountLabel)
                    val selected =
                        available.firstOrNull { it.driveId == space }
                            ?: error("The current scan destination is unavailable. Refresh and try again.")
                    mutableState.value =
                        ScannerDestinationPickerState(
                            spaces = available,
                            accountLabel = accountLabel,
                            spaceId = selected.driveId,
                            path = path,
                            busy = true,
                        )
                    val trail = resolveInitialTrail(account, space, path)
                    mutableState.value =
                        ScannerDestinationPickerState(
                            spaces = available,
                            accountLabel = accountLabel,
                            spaceId = selected.driveId,
                            path = path,
                            trail = trail,
                            busy = false,
                            loaded = true,
                        )
                    browse(account, selected.driveId, trail, path)
                }) { failure ->
                    mutableState.value =
                        mutableState.value.copy(
                            busy = false,
                            error = failure.toOpenCloudError().safeMessage(getApplication()),
                        )
                }
            }
    }

    fun stop() {
        setupJob?.cancel()
        browseJob?.cancel()
    }

    fun chooseSpace(spaceId: String) {
        val selected = state.value.spaces.firstOrNull { it.driveId == spaceId } ?: return
        val account = accountId ?: return
        mutableState.value =
            state.value.copy(
                spaceId = selected.driveId,
                path = "/",
                trail = emptyList(),
                validFolder = false,
                loaded = true,
            )
        browse(account, selected.driveId, emptyList(), "/")
    }

    fun showSpaces() {
        browseJob?.cancel()
        mutableState.value =
            state.value.copy(
                spaceId = null,
                path = "/",
                trail = emptyList(),
                folders = emptyList(),
                busy = false,
                validFolder = false,
                error = null,
            )
    }

    fun openBreadcrumb(index: Int) {
        val current = state.value
        val account = accountId ?: return
        val space = current.spaceId
        if (space == null || index !in current.trail.indices) return
        val trail = current.trail.take(index + 1)
        val path = trail.last().path
        mutableState.value = current.copy(path = path, trail = trail, validFolder = false)
        browse(account, space, trail, path)
    }

    fun openFolder(folder: ResourceEntity) {
        val account = accountId ?: return
        val space = state.value.spaceId
        if (space == null || folder !in state.value.folders || folder.kind != ResourceKind.FOLDER) return
        val trail = state.value.trail + folder
        mutableState.value = state.value.copy(path = folder.path, trail = trail, validFolder = false)
        browse(account, space, trail, folder.path)
    }

    fun up() {
        val current = state.value
        if (current.spaceId == null) return
        if (current.trail.isEmpty()) {
            showSpaces()
            return
        }
        val trail = current.trail.dropLast(1)
        val path = trail.lastOrNull()?.path ?: "/"
        mutableState.value = current.copy(path = path, trail = trail, validFolder = false)
        browse(requireNotNull(accountId), current.spaceId, trail, path)
    }

    fun retry() {
        val current = state.value
        val account = accountId ?: return
        val space = current.spaceId
        if (current.loaded && space != null) {
            browse(account, space, current.trail, current.path)
        } else {
            val original = initialSpaceId ?: space
            if (original != null) load(account, original, initialPath ?: current.path)
        }
    }

    private suspend fun resolveInitialTrail(
        account: String,
        space: String,
        path: String,
    ): List<ResourceEntity> {
        if (path.isBlank() || path.trimEnd('/') == "") return emptyList()
        val target =
            store.resourceAtPath(account, space, path)
                ?: error("The current scan folder could not be found. Refresh or choose another folder.")
        require(target.kind == ResourceKind.FOLDER) { "The current scan destination is not a folder." }
        val reversed = mutableListOf<ResourceEntity>()
        val visited = mutableSetOf<String>()
        var current = target
        while (current.path.isNotEmpty() && current.path != "/") {
            require(
                current.kind == ResourceKind.FOLDER &&
                    visited.add(
                        current.remoteId,
                    ) &&
                    visited.size <= MAX_FOLDER_DEPTH,
            ) {
                "The current scan folder could not be resolved. Refresh and try again."
            }
            reversed += current
            val parentId = current.parentId ?: break
            current = store.resource(account, space, parentId)
                ?: error("The current scan folder could not be resolved. Refresh and try again.")
        }
        return reversed.asReversed()
    }

    private fun browse(
        account: String,
        space: String,
        trail: List<ResourceEntity>,
        path: String,
    ) {
        browseJob?.cancel()
        val parentId = trail.lastOrNull()?.remoteId
        mutableState.value =
            mutableState.value.copy(busy = true, folders = emptyList(), validFolder = false, error = null)
        browseJob =
            viewModelScope.launch(Dispatchers.IO) {
                incomingAction({
                    transfers.refreshFolder(account, space, parentId)
                    currentCoroutineContext().ensureActive()
                    store.observeChildren(account, space, parentId).first().let { folders ->
                        mutableState.value =
                            mutableState.value.copy(
                                path = path,
                                folders = folders.filter { it.kind == ResourceKind.FOLDER },
                                busy = false,
                                validFolder = true,
                                error = null,
                            )
                    }
                    store.observeChildren(account, space, parentId).collect { folders ->
                        if (mutableState.value.spaceId == space && mutableState.value.path == path) {
                            mutableState.value =
                                mutableState.value.copy(folders = folders.filter { it.kind == ResourceKind.FOLDER })
                        }
                    }
                }) { failure ->
                    mutableState.value =
                        mutableState.value.copy(
                            busy = false,
                            validFolder = false,
                            error = failure.toOpenCloudError().safeMessage(getApplication()),
                        )
                }
            }
    }
}

data class ScannerDestinationPickerState(
    val accountLabel: String = "",
    val spaces: List<SpaceEntity> = emptyList(),
    val spaceId: String? = null,
    val path: String = "/",
    val trail: List<ResourceEntity> = emptyList(),
    val folders: List<ResourceEntity> = emptyList(),
    val busy: Boolean = true,
    val validFolder: Boolean = false,
    val loaded: Boolean = false,
    val error: String? = null,
)

private const val MAX_FOLDER_DEPTH = 256
