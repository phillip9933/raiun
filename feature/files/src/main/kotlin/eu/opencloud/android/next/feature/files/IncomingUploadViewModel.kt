package eu.opencloud.android.next.feature.files

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.sync.IncomingShareDestination
import eu.opencloud.android.next.core.sync.IncomingShareStore
import eu.opencloud.android.next.core.sync.SharedUploadQueue
import eu.opencloud.android.next.core.sync.SharedUploadSource
import eu.opencloud.android.next.core.sync.TransferManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

class IncomingUploadViewModel(
    application: Application,
) : AndroidViewModel(application) {
    private val store = FileBrowserStore(FileBrowserDatabase.create(application))
    private val intake = IncomingShareStore(application)
    private val transfers = TransferManager(application, store)
    private val mutableState = MutableStateFlow(IncomingUploadState())
    val state = mutableState.asStateFlow()
    private var batchId: String? = null
    private var browseJob: Job? = null
    private var intakeJob: Job? = null
    private var pendingSources: List<Uri> = emptyList()

    fun load(
        id: String,
        sources: List<Uri>,
    ) {
        if (batchId != null) return
        batchId = id
        pendingSources = sources
        intakeJob =
            viewModelScope.launch(Dispatchers.IO) {
                incomingAction({
                    val files = if (intake.isStaged(id)) intake.stage(id, emptyList()) {} else emptyList()
                    val accounts = store.activeAccounts()
                    mutableState.value =
                        restoredState(
                            id,
                            files,
                            accounts,
                        ).copy(sourceCount = if (files.isEmpty()) sources.size else files.size)
                    if (!state.value.destinationLocked) accounts.firstOrNull()?.let { selectAccount(it.id) }
                }) {
                    mutableState.value =
                        state.value.copy(busy = false, error = it.toOpenCloudError().safeMessage(getApplication()))
                }
            }
    }

    private suspend fun restoredState(
        batch: String,
        files: List<SharedUploadSource>,
        accounts: List<AccountEntity>,
    ): IncomingUploadState {
        val initial = IncomingUploadState(files = files, accounts = accounts, busy = false)
        val destination = intake.destination(batch) ?: return initial
        require(accounts.any { it.id == destination.accountId }) { "The original account is unavailable." }
        val spaces = store.spaces(destination.accountId).filter { !it.isDeleted && !it.isDisabled }
        require(spaces.any { it.driveId == destination.spaceId }) { "The original destination is unavailable." }
        return initial.copy(
            accountId = destination.accountId,
            spaces = spaces,
            spaceId = destination.spaceId,
            destinationLocked = true,
            restoredPath = destination.parentPath,
        )
    }

    fun selectAccount(id: String) {
        if (state.value.destinationLocked) return
        browseJob?.cancel()
        mutableState.value =
            state.value.copy(
                accountId = id,
                spaces = emptyList(),
                spaceId = null,
                trail = emptyList(),
                folders = emptyList(),
                error = null,
            )
        browseJob =
            viewModelScope.launch(Dispatchers.IO) {
                transfers.refreshAccount(id)
                store.observeSpaces(id).collect { spaces ->
                    val available = spaces.filter { !it.isDeleted && !it.isDisabled }
                    mutableState.update { current ->
                        if (current.accountId == id) current.copy(spaces = available) else current
                    }
                }
            }
    }

    fun selectSpace(id: String) {
        if (state.value.destinationLocked) return
        if (state.value.spaces.none { it.driveId == id }) return
        mutableState.value = state.value.copy(spaceId = id, trail = emptyList())
        browse()
    }

    fun openFolder(folder: ResourceEntity) {
        if (state.value.destinationLocked) return
        if (folder !in state.value.folders) return
        mutableState.value = state.value.copy(trail = state.value.trail + folder)
        browse()
    }

    fun up() {
        if (state.value.destinationLocked) return
        mutableState.value = state.value.copy(trail = state.value.trail.dropLast(1))
        browse()
    }

    private fun browse() {
        val account = state.value.accountId ?: return
        val space = state.value.spaceId ?: return
        val parent =
            state.value.trail
                .lastOrNull()
                ?.remoteId
        browseJob?.cancel()
        mutableState.value = state.value.copy(folders = emptyList())
        browseJob =
            viewModelScope.launch(Dispatchers.IO) {
                transfers.refreshFolder(account, space, parent)
                store.observeChildren(account, space, parent).collect { files ->
                    mutableState.update { current ->
                        if (current.accountId == account &&
                            current.spaceId == space &&
                            current.trail.lastOrNull()?.remoteId == parent
                        ) {
                            current.copy(folders = files.filter { it.kind == ResourceKind.FOLDER })
                        } else {
                            current
                        }
                    }
                }
            }
    }

    fun upload() {
        val selected = state.value
        if (selected.busy || selected.accountId == null || selected.spaceId == null) return
        val account = selected.accountId
        val space = selected.spaceId
        mutableState.value = state.value.copy(busy = true, error = null)
        intakeJob =
            viewModelScope.launch(Dispatchers.IO) {
                incomingAction({
                    val coroutine = currentCoroutineContext()
                    if (!intake.isStaged(requireNotNull(batchId))) {
                        require(pendingSources.isNotEmpty()) { "The shared files are unavailable." }
                        val staged = intake.stage(requireNotNull(batchId), pendingSources) { coroutine.ensureActive() }
                        mutableState.value = state.value.copy(files = staged)
                    }
                    val queue = SharedUploadQueue(getApplication())
                    val path =
                        selected.restoredPath ?: selected.trail
                            .lastOrNull()
                            ?.path
                            .orEmpty()
                    intake.submit(requireNotNull(batchId), IncomingShareDestination(account, space, path)) {
                        queue.enqueue(account, space, path, it)
                    }
                    mutableState.value = state.value.copy(busy = false, complete = true)
                }) {
                    val accepted =
                        runCatching {
                            intake.destination(
                                requireNotNull(batchId),
                            ) != null
                        }.getOrDefault(false)
                    mutableState.value =
                        state.value.copy(
                            busy = false,
                            destinationLocked = accepted,
                            error = it.toOpenCloudError().safeMessage(getApplication()),
                        )
                }
            }
    }

    fun discard(onDone: () -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
            intakeJob?.cancel()
            intakeJob?.join()
            batchId?.let { intake.discard(it) }
            kotlinx.coroutines.withContext(Dispatchers.Main) { onDone() }
        }
    }
}

data class IncomingUploadState(
    val files: List<SharedUploadSource> = emptyList(),
    val sourceCount: Int = 0,
    val accounts: List<AccountEntity> = emptyList(),
    val accountId: String? = null,
    val spaces: List<SpaceEntity> = emptyList(),
    val spaceId: String? = null,
    val trail: List<ResourceEntity> = emptyList(),
    val folders: List<ResourceEntity> = emptyList(),
    val busy: Boolean = true,
    val destinationLocked: Boolean = false,
    val complete: Boolean = false,
    val error: String? = null,
    val restoredPath: String? = null,
)
