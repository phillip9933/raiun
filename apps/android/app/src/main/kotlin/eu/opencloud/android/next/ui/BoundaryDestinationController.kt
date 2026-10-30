package eu.opencloud.android.next.ui

import android.content.Context
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.sync.BoundaryDestinationFolder
import eu.opencloud.android.next.core.sync.BoundaryEndpoint
import eu.opencloud.android.next.core.sync.BoundaryEntry
import eu.opencloud.android.next.core.sync.BoundaryMoveIncompleteException
import eu.opencloud.android.next.core.sync.BoundaryNameIndex
import eu.opencloud.android.next.core.sync.BoundaryTransfer
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultLocationKind
import eu.opencloud.android.next.core.sync.requireBoundaryPlacement
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.Closeable

internal data class BoundaryDestinationState(
    val locations: List<VaultLocation> = emptyList(),
    val location: VaultLocation? = null,
    val path: String = "",
    val folders: List<BoundaryDestinationFolder> = emptyList(),
    val page: BoundaryDestinationPage? = null,
    val targetValidated: Boolean = false,
    val unlock: VaultLocation? = null,
    val loading: Boolean = true,
    val transferring: Boolean = false,
    val error: OpenCloudError? = null,
    val incompleteDestination: Boolean = false,
    val incompleteMove: Boolean = false,
    val complete: Boolean = false,
    val plaintextWarning: Boolean = false,
    val conflict: BoundaryPlacementConflict? = null,
)

internal data class BoundaryPlacementConflict(
    val name: String,
    val proposedName: String,
)

/** One modal owns destination unlock, browsing and transfer cancellation; source unlock stays route-owned. */
@Suppress("TooGenericExceptionCaught") // All provider failures become safe domain UI errors; cancellation is rethrown.
internal class BoundaryDestinationController(
    private val context: Context,
    private val request: BoundaryTransferRequest,
    private val repository: BoundaryDestinationRepository = AndroidBoundaryDestinationRepository(context),
    dispatcher: CoroutineDispatcher = Dispatchers.Main.immediate,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
) : Closeable {
    private val scope = CoroutineScope(SupervisorJob() + dispatcher)
    private val mutableState = MutableStateFlow(BoundaryDestinationState())
    val state = mutableState.asStateFlow()
    private val pager = BoundaryDestinationPager(context, ioDispatcher)
    private var destination: BoundaryEndpoint? = null
    private var unlocked: BoundaryUnlockedDestination? = null
    private var task: Job? = null
    private var sources: List<Pair<BoundaryEndpoint, BoundaryEntry>> = emptyList()
    private var generation = 0L
    private var password: CharArray? = null
    private var closed = false

    init {
        loadLocations()
    }

    fun loadLocations() {
        if (closed || state.value.transferring) return
        invalidateBrowse()
        releaseDestination()
        mutableState.value =
            mutableState.value.copy(
                locations = emptyList(),
                location = null,
                folders = emptyList(),
                path = "",
                unlock = null,
                page = null,
                targetValidated = false,
            )
        launchBrowse { revision ->
            val locations = repository.locations(request.accountId).filter { !it.isDisabled && !it.offlineOnly }
            requireActive(revision)
            val resolved =
                request.unlocked?.let(::listOf) ?: request.ordinary.map { resource ->
                    val root =
                        locations.singleOrNull { !it.isVaultRoot && it.driveId == resource.spaceId }
                            ?: throw OpenCloudException(OpenCloudError.PreconditionFailed)
                    val endpoint = repository.ordinaryEndpoint(request.accountId, root)
                    requireActive(revision)
                    endpoint to
                        BoundaryEntry(
                            resource.remoteId,
                            resource.path.trim('/'),
                            resource.name,
                            resource.kind == ResourceKind.FOLDER,
                            resource.sizeBytes,
                            resource.eTag,
                            resource.mimeType,
                        )
                }
            requireActive(revision)
            if (resolved.isEmpty()) throw OpenCloudException(OpenCloudError.PreconditionFailed)
            sources = resolved
            mutableState.value = mutableState.value.copy(locations = locations)
        }
    }

    fun select(location: VaultLocation) {
        if (closed || state.value.transferring) return
        invalidateBrowse()
        releaseDestination()
        mutableState.value =
            mutableState.value.copy(
                location = location,
                folders = emptyList(),
                page = null,
                path = "",
                unlock = null,
                targetValidated = false,
                plaintextWarning = false,
                error = null,
            )
        if (location.isVaultRoot) {
            selectEncrypted(location)
        } else {
            launchBrowse { revision ->
                val endpoint = repository.ordinaryEndpoint(request.accountId, location)
                requireActive(revision)
                destination = endpoint
                readFolders("", revision)
            }
        }
    }

    private fun selectEncrypted(location: VaultLocation) {
        val owned = sources.firstOrNull()?.first?.takeIf { it.identity == vaultIdentity(location) }
        if (owned != null) {
            destination = owned
            browse("")
        } else {
            mutableState.value = mutableState.value.copy(location = null, unlock = location, loading = false)
        }
    }

    fun unlock(value: CharArray) {
        val location = state.value.unlock
        val busy = closed || state.value.loading || state.value.transferring
        if (location == null || busy) {
            value.fill('\u0000')
            return
        }
        password?.fill('\u0000')
        password = value
        launchBrowse { revision ->
            val session =
                try {
                    repository.unlock(request.accountId, location, password = value)
                } finally {
                    value.fill('\u0000')
                    if (password === value) password = null
                }
            var adopted = false
            try {
                requireActive(revision)
                unlocked = session
                destination = session.endpoint
                adopted = true
                mutableState.value = mutableState.value.copy(location = location, unlock = null)
                readFolders("", revision)
            } finally {
                if (!adopted) session.close()
            }
        }
        task?.invokeOnCompletion {
            value.fill('\u0000')
            if (password === value) password = null
        }
    }

    fun open(folder: BoundaryDestinationFolder) {
        val current = state.value
        val location = current.location ?: return
        val busy = closed || current.loading || current.transferring
        if (busy || folder !in current.folders) return
        if (folder.isVaultRoot && !location.isVaultRoot) {
            select(
                location.copy(
                    kind = VaultLocationKind.FOLDER_VAULT,
                    remoteVaultId = folder.id,
                    title = folder.name,
                    vaultPath = folder.path,
                    isVaultRoot = true,
                ),
            )
        } else {
            browse(folder.path)
        }
    }

    fun browse(path: String) {
        if (closed || state.value.transferring) return
        mutableState.value = mutableState.value.copy(path = path)
        launchBrowse { revision -> readFolders(path, revision) }
    }

    fun page(previous: Boolean) {
        val current = state.value
        val page = current.page
        val directionAllowed = if (previous) page?.hasPrevious == true else page?.hasNext == true
        val busy = closed || current.loading || current.transferring
        if (page == null || busy || !directionAllowed) return
        launchBrowse(clearDirectory = false) { revision ->
            val next = pager.page(previous, page) { requireCurrent(revision) }
            requireActive(revision)
            mutableState.value = mutableState.value.copy(folders = next.folders, page = next.page)
        }
    }

    fun up() {
        if (state.value.path.isEmpty()) loadLocations() else browse(state.value.path.substringBeforeLast('/', ""))
    }

    private suspend fun readFolders(
        path: String,
        revision: Long,
    ) {
        val endpoint = requireNotNull(destination)
        val next = pager.open(endpoint, path) { requireCurrent(revision) }
        requireActive(revision)
        mutableState.value =
            mutableState.value.copy(
                path = path,
                folders = next.folders,
                page = next.page,
                targetValidated = true,
                plaintextWarning = sources.any { it.first.encrypted } && !endpoint.encrypted,
            )
    }

    fun keepBoth() = transfer(keepBoth = true)

    fun cancelConflict() {
        mutableState.value = mutableState.value.copy(conflict = null)
        if (!closed && state.value.location != null) browse(state.value.path)
    }

    fun transfer(keepBoth: Boolean = false) {
        val endpoint = destination ?: return
        val current = state.value
        if (!canTransfer(current)) return
        val parent = current.path
        val selected = sources
        invalidateBrowse()
        val revision = generation
        mutableState.value =
            current.copy(
                transferring = true,
                page = null,
                error = null,
                incompleteMove = false,
                incompleteDestination = false,
                conflict = null,
            )
        task =
            scope.launch {
                try {
                    val plan = preparePlacement(endpoint, parent, selected)
                    requireActive(revision)
                    if (plan.conflict != null && !keepBoth) {
                        mutableState.value = mutableState.value.copy(transferring = false, conflict = plan.conflict)
                        return@launch
                    }
                    val names = plan.names
                    withContext(ioDispatcher) {
                        selected.forEachIndexed { index, (source, entry) ->
                            source.requireUnchanged(entry)
                            requireBoundaryPlacement(source, entry, endpoint, parent, names[index])
                        }
                    }
                    selected.forEachIndexed { index, (source, entry) ->
                        BoundaryTransfer(context).execute(
                            source,
                            entry,
                            endpoint,
                            parent,
                            request.move,
                            targetName = names[index],
                        )
                    }
                    requireActive(revision)
                    mutableState.value =
                        mutableState.value.copy(
                            transferring = false,
                            complete = true,
                            targetValidated = false,
                        )
                    request.onComplete()
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: BoundaryMoveIncompleteException) {
                    transferFailed(revision, failure.error, incompleteMove = true)
                } catch (failure: Exception) {
                    transferFailed(revision, failure.toOpenCloudError(), incompleteMove = false)
                }
            }
    }

    private fun canTransfer(current: BoundaryDestinationState): Boolean {
        val idle = !closed && !current.loading && !current.transferring
        return idle && current.targetValidated && current.error == null
    }

    private fun transferFailed(
        revision: Long,
        error: OpenCloudError,
        incompleteMove: Boolean,
    ) {
        if (closed || revision != generation) return
        mutableState.value =
            mutableState.value.copy(
                transferring = false,
                error = error,
                incompleteMove = incompleteMove,
                incompleteDestination = !incompleteMove,
                targetValidated = false,
                folders = emptyList(),
                page = null,
            )
    }

    private suspend fun preparePlacement(
        endpoint: BoundaryEndpoint,
        parent: String,
        selected: List<Pair<BoundaryEndpoint, BoundaryEntry>>,
    ): BoundaryPlacementPlan =
        withContext(ioDispatcher) {
            endpoint.openNameIndex(context, parent).use { index ->
                reserveBoundaryPlacementNames(selected.asSequence().map { it.second }, index)
            }
        }

    private fun launchBrowse(
        clearDirectory: Boolean = true,
        block: suspend (Long) -> Unit,
    ) {
        if (closed || state.value.transferring) return
        invalidateBrowse(clearDirectory)
        val revision = generation
        val next =
            mutableState.value.copy(
                loading = true,
                error = null,
                incompleteDestination = false,
                incompleteMove = false,
            )
        mutableState.value =
            if (clearDirectory) {
                next.copy(folders = emptyList(), page = null, targetValidated = false, plaintextWarning = false)
            } else {
                next
            }
        task =
            scope.launch {
                try {
                    block(revision)
                    requireActive(revision)
                    mutableState.value = mutableState.value.copy(loading = false)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: Exception) {
                    if (!closed && revision == generation) {
                        pager.close()
                        mutableState.value =
                            mutableState.value.copy(
                                loading = false,
                                error = failure.toOpenCloudError(),
                                targetValidated = false,
                                page = null,
                            )
                    }
                }
            }
    }

    private fun invalidateBrowse(clearDirectory: Boolean = true) {
        task?.cancel()
        task = null
        generation++
        if (clearDirectory) pager.close()
    }

    private suspend fun requireActive(revision: Long) {
        currentCoroutineContext().ensureActive()
        requireCurrent(revision)
    }

    private fun requireCurrent(revision: Long) {
        if (closed || revision != generation) throw CancellationException("Destination request changed")
    }

    private fun releaseDestination() {
        password?.fill('\u0000')
        password = null
        unlocked?.close()
        unlocked = null
        destination = null
    }

    override fun close() {
        if (closed) return
        closed = true
        invalidateBrowse()
        scope.cancel()
        releaseDestination()
        sources = emptyList()
        mutableState.value =
            mutableState.value.copy(
                locations = emptyList(),
                location = null,
                folders = emptyList(),
                page = null,
                targetValidated = false,
                unlock = null,
                loading = false,
                transferring = false,
            )
    }
}

private fun vaultIdentity(location: VaultLocation): String =
    "vault:${location.accountId}:${location.canonicalServer}:${location.driveId}:${location.remoteVaultId}"

internal data class BoundaryPlacementPlan(
    val names: List<String>,
    val conflict: BoundaryPlacementConflict?,
)

/** Only the selected request's resulting names remain in memory; existing siblings and reservations stay indexed. */
internal suspend fun reserveBoundaryPlacementNames(
    entries: Sequence<BoundaryEntry>,
    index: BoundaryNameIndex,
): BoundaryPlacementPlan {
    val names = ArrayList<String>()
    var conflict: BoundaryPlacementConflict? = null
    for (entry in entries) {
        currentCoroutineContext().ensureActive()
        val name = reserveBoundaryName(entry, index)
        if (name != entry.name && conflict == null) conflict = BoundaryPlacementConflict(entry.name, name)
        names += name
    }
    currentCoroutineContext().ensureActive()
    return BoundaryPlacementPlan(names, conflict)
}

private suspend fun reserveBoundaryName(
    entry: BoundaryEntry,
    index: BoundaryNameIndex,
): String {
    currentCoroutineContext().ensureActive()
    if (index.reserve(entry.name)) return entry.name
    var number = 1L
    while (true) {
        currentCoroutineContext().ensureActive()
        val candidate = numberedEncryptedCandidate(entry.name, entry.directory, number)
        if (index.reserve(candidate)) return candidate
        if (number == Long.MAX_VALUE) throw OpenCloudException(OpenCloudError.PreconditionFailed)
        number = Math.addExact(number, 1L)
    }
}
