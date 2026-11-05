package eu.opencloud.android.next.ui

import eu.opencloud.android.next.core.sync.VaultFolder
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

/** Route identity is captured before suspension; only the route lifecycle owns sessions and keys. */
internal data class VaultDestinationOwnerSnapshot(
    val opened: VaultRouteSession,
    val account: String,
    val lockRevision: Long,
    val routeGeneration: Long,
    val showHidden: Boolean,
)

internal interface VaultDestinationOwner {
    fun capture(): VaultDestinationOwnerSnapshot?

    fun isCurrent(owner: VaultDestinationOwnerSnapshot): Boolean

    fun closeContents()

    fun reportFailure(
        owner: VaultDestinationOwnerSnapshot,
        failure: Exception,
    )
}

/** Immutable presentation/source binding survives closure of the original directory, never its action lease. */
internal data class PresentedVaultFolder(
    val route: VaultRouteEntry,
    val remote: VaultFolder,
)

/** Owns only destination jobs and snapshots. The route clears this owner before closing its session. */
internal class VaultDestinationPicker(
    private val scope: CoroutineScope,
    private val state: MutableStateFlow<VaultRouteState>,
    private val owner: VaultDestinationOwner,
) {
    private var job: Job? = null
    private var generation = 0L
    private var directory: VaultRouteDirectorySnapshot? = null
    private val previousOffsets = mutableListOf<Long>()
    private var sources: Map<String, PresentedVaultFolder> = emptyMap()
    private var selectedSource: PresentedVaultFolder? = null

    fun source(id: String): PresentedVaultFolder? = sources[id]

    fun begin(
        selected: PresentedVaultFolder,
        path: String,
        presentedEntries: Map<String, PresentedVaultFolder>,
    ) {
        selectedSource = selected
        load(path, presentedEntries)
    }

    fun load(
        path: String,
        presentedEntries: Map<String, PresentedVaultFolder>,
    ) {
        val request = request(path) ?: return
        if (state.value.destinationPickerPath == null) sources = presentedEntries.toMap()
        job?.cancel()
        closeDirectory()
        owner.closeContents()
        state.value =
            state.value.copy(
                entries = emptyList(),
                destinationPickerPath = path,
                destinationPickerEntries = emptyList(),
                destinationPickerPage = null,
                destinationPickerLoading = true,
                destinationPickerError = null,
            )
        job = scope.launch { openDirectory(request) }
    }

    private data class Request(
        val owner: VaultDestinationOwnerSnapshot,
        val path: String,
        val revision: Long,
        val excludedPath: String?,
    )

    private fun request(path: String): Request? =
        owner.capture()?.let { captured ->
            Request(captured, path, ++generation, selectedSource?.remote?.takeIf { it.isFolder }?.path)
        }

    private fun isCurrent(request: Request): Boolean = generation == request.revision && owner.isCurrent(request.owner)

    @Suppress("TooGenericExceptionCaught") // Destination snapshots close on cancellation and late completion.
    private suspend fun openDirectory(request: Request) {
        var snapshot: VaultRouteDirectorySnapshot? = null
        var adopted = false
        try {
            snapshot = request.owner.opened.openDirectory(request.path, request.owner.showHidden, request.excludedPath)
            currentCoroutineContext().ensureActive()
            val entries = snapshot.page(0, VAULT_DIRECTORY_PAGE_SIZE)
            currentCoroutineContext().ensureActive()
            if (!isCurrent(request)) return
            directory = snapshot
            adopted = true
            publishPage(snapshot, entries, 0)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            if (isCurrent(request)) owner.reportFailure(request.owner, failure)
        } finally {
            if (!adopted) snapshot?.close()
        }
    }

    fun page(previous: Boolean) {
        val snapshot = directory
        val page = state.value.destinationPickerPage
        if (snapshot == null || page == null || state.value.destinationPickerLoading) return
        val canMove = if (previous) page.hasPrevious else page.hasNext
        if (!canMove) return
        val offset = if (previous) previousOffsets.lastOrNull() else page.offset + page.count
        val request = request(state.value.destinationPickerPath.orEmpty())
        if (offset != null && request != null) {
            job?.cancel()
            state.value = state.value.copy(destinationPickerEntries = emptyList(), destinationPickerLoading = true)
            job = scope.launch { loadPage(request, snapshot, page.offset, offset, previous) }
        }
    }

    @Suppress("TooGenericExceptionCaught") // Page revocation reports safe errors and closes the invalid snapshot.
    private suspend fun loadPage(
        request: Request,
        snapshot: VaultRouteDirectorySnapshot,
        previousOffset: Long,
        offset: Long,
        previous: Boolean,
    ) {
        var delivered = false
        try {
            val entries = snapshot.page(offset, VAULT_DIRECTORY_PAGE_SIZE)
            currentCoroutineContext().ensureActive()
            if (!isCurrent(request) || directory !== snapshot) return
            if (previous) {
                previousOffsets.removeAt(previousOffsets.lastIndex)
            } else {
                previousOffsets += previousOffset
            }
            publishPage(snapshot, entries, offset)
            delivered = true
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            if (isCurrent(request)) owner.reportFailure(request.owner, failure)
        } finally {
            if (!delivered && directory === snapshot) closeDirectory()
        }
    }

    private fun publishPage(
        snapshot: VaultRouteDirectorySnapshot,
        entries: List<VaultFolder>,
        offset: Long,
    ) {
        state.value =
            state.value.copy(
                destinationPickerLoading = false,
                destinationPickerError = null,
                destinationPickerPage =
                    VaultDirectoryPageState(
                        offset,
                        snapshot.totalCount,
                        entries.size,
                        previousOffsets.isNotEmpty(),
                    ),
                destinationPickerEntries =
                    entries.map { entry ->
                        VaultRouteEntry(
                            entry.id + "\u0000" + entry.path,
                            entry.name,
                            entry.path,
                            entry.isFolder,
                            false,
                            entry.size,
                            entry.contentType,
                            displaySize = if (entry.isFolder) null else encryptedPlaintextSize(entry.size),
                        )
                    },
            )
    }

    private fun closeDirectory() {
        directory?.close()
        directory = null
        previousOffsets.clear()
        state.value = state.value.copy(destinationPickerPage = null)
    }

    fun clear() {
        generation++
        job?.cancel()
        job = null
        closeDirectory()
        sources = emptyMap()
        selectedSource = null
        state.value =
            state.value.copy(
                destinationPickerPath = null,
                destinationPickerEntries = emptyList(),
                destinationPickerLoading = false,
                destinationPickerError = null,
            )
    }
}
