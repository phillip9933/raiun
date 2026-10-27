package eu.opencloud.android.next.feature.shares

import eu.opencloud.android.next.core.database.SharedLocalFile
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.SharedMetadataException
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.sync.SharedDownloadRequest
import eu.opencloud.android.next.core.sync.SharedFolderRequest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed interface IncomingBrowserItem {
    val name: String

    data class Folder(
        override val name: String,
        val request: SharedFolderRequest,
        val hidden: Boolean = false,
    ) : IncomingBrowserItem

    data class File(
        override val name: String,
        val request: SharedDownloadRequest,
        val mimeType: String?,
        val localCopy: SharedLocalFile? = null,
    ) : IncomingBrowserItem
}

@Suppress("LongParameterList") // Rows, lease, copy flow and navigation metadata form one atomic page result.
internal class IncomingBrowserPage(
    val items: List<IncomingBrowserItem>,
    val unavailable: Int = 0,
    val copies: Flow<List<SharedLocalFile>> = emptyFlow(),
    val uploadDestination: SharedFolderRequest? = null,
    val folderName: String? = null,
    val offset: Int = 0,
    val total: Int = items.size,
    val current: suspend () -> Boolean,
)

enum class SharedCopyAction { KEEP, TEMPORARY, REMOVE }

internal fun interface IncomingBrowserBackend {
    suspend fun upload(
        destination: SharedFolderRequest,
        sourceUri: String,
    ): Unit = throw OpenCloudException(OpenCloudError.AccessDenied)

    suspend fun loadPage(
        account: String,
        folder: SharedFolderRequest?,
        offset: Int,
        refresh: Boolean,
    ): IncomingBrowserPage = load(account, folder)

    suspend fun load(
        account: String,
        folder: SharedFolderRequest?,
    ): IncomingBrowserPage
}

data class IncomingBrowserState(
    val account: String? = null,
    val trail: List<IncomingBrowserItem.Folder> = emptyList(),
    val items: List<IncomingBrowserItem> = emptyList(),
    val loading: Boolean = false,
    val unavailable: Int = 0,
    val error: String? = null,
    val uploadDestination: SharedFolderRequest? = null,
    val offset: Int = 0,
    val total: Int = 0,
)

/** Navigation and publication belong to the owner's main dispatcher; stale requests cannot restore old rows. */
internal class IncomingBrowserController(
    private val owner: CoroutineScope,
    private val backend: IncomingBrowserBackend,
    private val io: CoroutineDispatcher = Dispatchers.IO,
    private val errorMessage: (OpenCloudError) -> String = { it.safeMessage() },
    private val onTrailChanged: (List<IncomingBrowserItem.Folder>) -> Unit = {},
    private val performCopyAction: suspend (IncomingBrowserItem.File, SharedCopyAction) -> Unit = { _, _ ->
        error("Copy actions are unavailable")
    },
) {
    private val mutableState = MutableStateFlow(IncomingBrowserState())
    val state = mutableState.asStateFlow()
    private var pending: Job? = null
    private var revision = 0L
    private var currentPage: (suspend () -> Boolean)? = null

    fun load(
        account: String,
        restored: List<IncomingBrowserItem.Folder> = emptyList(),
    ) {
        if (state.value.account == account) return
        require(account.isNotBlank())
        val trail = IncomingBrowserTrail.restore(account, IncomingBrowserTrail.save(restored))
        navigate(IncomingBrowserState(account = account, trail = trail))
    }

    fun open(folder: IncomingBrowserItem.Folder) {
        val selected = state.value
        if (selected.loading || folder !in selected.items || folder.request.account != selected.account) return
        navigate(selected.copy(trail = selected.trail + folder, offset = 0))
    }

    fun back(): Boolean {
        if (state.value.trail.isEmpty()) return false
        navigate(state.value.copy(trail = state.value.trail.dropLast(1), offset = 0))
        return true
    }

    fun openShortcut(folder: IncomingBrowserItem.Folder) {
        if (folder.request.account != state.value.account) return
        navigate(state.value.copy(trail = listOf(folder), offset = 0))
    }

    fun refresh() = navigate(state.value.copy(offset = 0))

    fun page(forward: Boolean) {
        val selected = state.value
        if (selected.loading || selected.trail.isEmpty()) return
        val next = if (forward) selected.offset + 256 else (selected.offset - 256).coerceAtLeast(0)
        if (next == selected.offset || next >= selected.total) return
        navigate(selected.copy(offset = next), refresh = false)
    }

    fun upload(
        destination: SharedFolderRequest,
        sourceUri: String,
    ) {
        val selected = state.value
        if (selected.loading || selected.uploadDestination != destination) return
        navigate(selected) { backend.upload(destination, sourceUri) }
    }

    fun changeCopy(
        file: IncomingBrowserItem.File,
        action: SharedCopyAction,
    ) {
        val selected = state.value
        if (selected.loading || file !in selected.items || file.request.accountId != selected.account) return
        navigate(selected) { performCopyAction(file, action) }
    }

    fun clear() {
        revision++
        pending?.cancel()
        mutableState.value = IncomingBrowserState()
        currentPage = null
    }

    @Suppress("TooGenericExceptionCaught") // UI boundary sanitizes failures; coroutine cancellation is rethrown.
    private fun navigate(target: IncomingBrowserState, refresh: Boolean = true, beforeLoad: suspend () -> Unit = {}) {
        val account = target.account ?: return
        val ticket = ++revision
        val previous = state.value
        val previousCurrent = currentPage
        pending?.cancel()
        mutableState.value =
            target.copy(items = emptyList(), loading = true, error = null, unavailable = 0, uploadDestination = null)
        onTrailChanged(target.trail)
        pending =
            owner.launch {
                try {
                    val page =
                        withContext(io) {
                            beforeLoad()
                            currentCoroutineContext().ensureActive()
                            backend.loadPage(account, target.trail.lastOrNull()?.request, target.offset, refresh)
                        }
                    val valid = withContext(io) { page.current() }
                    currentCoroutineContext().ensureActive()
                    if (!valid) throw OpenCloudException(OpenCloudError.PreconditionFailed)
                    if (ticket == revision) {
                        currentPage = page.current
                        mutableState.value =
                            state.value.copy(
                                trail =
                                    state.value.trail.mapIndexed { index, folder ->
                                        if (index == state.value.trail.lastIndex && page.folderName != null) {
                                            folder.copy(name = page.folderName)
                                        } else {
                                            folder
                                        }
                                    },
                                items = page.items,
                                offset = page.offset,
                                total = page.total,
                                unavailable = page.unavailable,
                                loading = false,
                                uploadDestination = page.uploadDestination,
                            )
                    }
                    observeCopies(page, ticket)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: Exception) {
                    val retainPrevious = canRetainPage(refresh, previousCurrent)
                    currentCoroutineContext().ensureActive()
                    if (ticket == revision) {
                        mutableState.value =
                            (if (retainPrevious) previous else state.value).copy(
                                items = if (retainPrevious) previous.items else emptyList(),
                                loading = false,
                                error =
                                    errorMessage(failure.toOpenCloudError()) +
                                        ((failure as? SharedMetadataException)?.let { " [${it.stage.code}]" } ?: ""),
                                uploadDestination = null,
                            )
                    }
                }
            }
    }

    private suspend fun canRetainPage(
        refresh: Boolean,
        previousCurrent: (suspend () -> Boolean)?,
    ): Boolean {
        if (refresh || previousCurrent == null) return false
        return withContext(io) { runCatching { previousCurrent() }.getOrDefault(false) }
    }

    private suspend fun observeCopies(
        page: IncomingBrowserPage,
        ticket: Long,
    ) {
        page.copies.collect { copies ->
            val valid = withContext(io) { page.current() }
            currentCoroutineContext().ensureActive()
            if (!valid) throw OpenCloudException(OpenCloudError.PreconditionFailed)
            if (ticket == revision) {
                val indexed = copies.associateBy { Triple(it.accountId, it.scopeId, it.remoteId) }
                val items =
                    state.value.items.map { item ->
                        if (item is IncomingBrowserItem.File) {
                            val request = item.request
                            item.copy(
                                localCopy = indexed[Triple(request.accountId, request.scopeId, request.file.remoteId)],
                            )
                        } else {
                            item
                        }
                    }
                mutableState.value = state.value.copy(items = items)
            }
        }
    }
}
