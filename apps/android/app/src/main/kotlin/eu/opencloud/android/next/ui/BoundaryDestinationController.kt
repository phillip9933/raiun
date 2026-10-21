package eu.opencloud.android.next.ui

import android.content.Context
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.sync.BoundaryEndpoint
import eu.opencloud.android.next.core.sync.BoundaryEntry
import eu.opencloud.android.next.core.sync.BoundaryMoveIncompleteException
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

internal data class BoundaryDestinationFolder(
    val id: String,
    val path: String,
    val name: String,
    val vault: VaultLocation? = null,
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
    private var destination: BoundaryEndpoint? = null
    private var unlocked: BoundaryUnlockedDestination? = null
    private var task: Job? = null
    private var sources: List<Pair<BoundaryEndpoint, BoundaryEntry>> = emptyList()
    private var generation = 0L
    private var password: CharArray? = null

    init {
        loadLocations()
    }

    fun loadLocations() {
        if (state.value.transferring) return
        password?.fill('\u0000')
        password = null
        unlocked?.close()
        unlocked = null
        destination = null
        launchBrowse {
            val locations = repository.locations(request.accountId).filter { !it.isDisabled && !it.offlineOnly }
            currentCoroutineContext().ensureActive()
            val resolved =
                request.unlocked?.let(::listOf) ?: request.ordinary.map { resource ->
                    val root =
                        locations.singleOrNull { !it.isVaultRoot && it.driveId == resource.spaceId }
                            ?: throw OpenCloudException(OpenCloudError.PreconditionFailed)
                    val endpoint = repository.ordinaryEndpoint(request.accountId, root)
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
            currentCoroutineContext().ensureActive()
            sources = resolved
            if (sources.isEmpty()) throw OpenCloudException(OpenCloudError.PreconditionFailed)
            currentCoroutineContext().ensureActive()
            mutableState.value =
                mutableState.value.copy(
                    locations = locations,
                    location = null,
                    folders = emptyList(),
                    path = "",
                    unlock = null,
                )
        }
    }

    fun select(location: VaultLocation) {
        if (state.value.transferring) return
        task?.cancel()
        password?.fill('\u0000')
        password = null
        unlocked?.close()
        unlocked = null
        destination = null
        if (location.isVaultRoot) {
            val owned = sources.firstOrNull()?.first?.takeIf { it.identity == vaultIdentity(location) }
            if (owned != null) {
                destination = owned
                mutableState.value = mutableState.value.copy(location = location, unlock = null)
                browse("")
            } else {
                mutableState.value =
                    mutableState.value.copy(
                        location = null,
                        folders = emptyList(),
                        unlock = location,
                        loading = false,
                        error = null,
                        plaintextWarning = false,
                    )
            }
        } else {
            launchBrowse {
                val endpoint = repository.ordinaryEndpoint(request.accountId, location)
                currentCoroutineContext().ensureActive()
                destination = endpoint
                mutableState.value = mutableState.value.copy(location = location, unlock = null)
                readFolders("")
            }
        }
    }

    fun unlock(value: CharArray) {
        val location = state.value.unlock
        if (location == null || state.value.loading || state.value.transferring) {
            value.fill('\u0000')
            return
        }
        password?.fill('\u0000')
        password = value
        launchBrowse {
            val session =
                try {
                    repository.unlock(request.accountId, location, password = value)
                } finally {
                    value.fill('\u0000')
                    if (password === value) password = null
                }
            var adopted = false
            try {
                currentCoroutineContext().ensureActive()
                val endpoint = session.endpoint
                unlocked = session
                destination = endpoint
                adopted = true
                mutableState.value = mutableState.value.copy(location = location, unlock = null)
                readFolders("")
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
        folder.vault?.let(::select) ?: browse(folder.path)
    }

    fun browse(path: String) = launchBrowse { readFolders(path) }

    fun up() {
        if (state.value.path.isEmpty()) loadLocations() else browse(state.value.path.substringBeforeLast('/', ""))
    }

    private suspend fun readFolders(path: String) {
        val location = requireNotNull(state.value.location)
        val endpoint = requireNotNull(destination)
        val folders =
            if (location.isVaultRoot) {
                withContext(ioDispatcher) {
                    endpoint.list(path)
                }.filter { it.directory }.map { BoundaryDestinationFolder(it.id, it.path, it.name) }
            } else {
                repository.folders(request.accountId, location, path).map { folder ->
                    val vault =
                        if (folder.isVaultRoot) {
                            location.copy(
                                kind = VaultLocationKind.FOLDER_VAULT,
                                remoteVaultId = folder.id,
                                title = folder.name,
                                vaultPath = folder.path,
                                isVaultRoot = true,
                            )
                        } else {
                            null
                        }
                    BoundaryDestinationFolder(folder.id, folder.path, folder.name, vault)
                }
            }
        currentCoroutineContext().ensureActive()
        mutableState.value =
            mutableState.value.copy(
                path = path,
                folders = folders.sortedBy { it.name.lowercase() },
                plaintextWarning =
                    sources.any { it.first.encrypted } && !endpoint.encrypted,
            )
    }

    fun keepBoth() = transfer(keepBoth = true)

    fun cancelConflict() {
        mutableState.value = mutableState.value.copy(conflict = null)
    }

    fun transfer(keepBoth: Boolean = false) {
        val endpoint = destination ?: return
        if (state.value.loading || state.value.transferring) return
        val parent = state.value.path
        task?.cancel()
        mutableState.value =
            mutableState.value.copy(
                transferring = true,
                error = null,
                incompleteMove = false,
                incompleteDestination = false,
                conflict = null,
            )
        task =
            scope.launch {
                try {
                    val plan = preparePlacement(endpoint, parent)
                    if (plan.conflict != null && !keepBoth) {
                        mutableState.value = mutableState.value.copy(transferring = false, conflict = plan.conflict)
                        return@launch
                    }
                    val names = plan.names
                    withContext(ioDispatcher) {
                        sources.forEachIndexed { index, (source, entry) ->
                            source.requireUnchanged(entry)
                            requireBoundaryPlacement(source, entry, endpoint, parent, names[index])
                        }
                    }
                    sources.forEachIndexed { index, (source, entry) ->
                        BoundaryTransfer(
                            context,
                        ).execute(source, entry, endpoint, parent, request.move, targetName = names[index])
                    }
                    mutableState.value = mutableState.value.copy(transferring = false, complete = true)
                    request.onComplete()
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: BoundaryMoveIncompleteException) {
                    mutableState.value =
                        mutableState.value.copy(transferring = false, error = failure.error, incompleteMove = true)
                } catch (failure: Exception) {
                    mutableState.value =
                        mutableState.value.copy(
                            transferring = false,
                            error = failure.toOpenCloudError(),
                            incompleteDestination = true,
                        )
                }
            }
    }

    private suspend fun preparePlacement(
        endpoint: BoundaryEndpoint,
        parent: String,
    ): BoundaryPlacementPlan {
        val existing = withContext(ioDispatcher) { endpoint.existingNames(parent) }.toMutableSet()
        var conflict: BoundaryPlacementConflict? = null
        val names =
            sources.map { (_, entry) ->
                val name =
                    if (entry.name in
                        existing
                    ) {
                        numberedEncryptedName(entry.name, entry.directory, existing)
                    } else {
                        entry.name
                    }
                if (name != entry.name && conflict == null) conflict = BoundaryPlacementConflict(entry.name, name)
                existing += name
                name
            }
        return BoundaryPlacementPlan(names, conflict)
    }

    private fun launchBrowse(block: suspend () -> Unit) {
        if (state.value.transferring) return
        task?.cancel()
        val revision = ++generation
        mutableState.value =
            mutableState.value.copy(loading = true, error = null, incompleteDestination = false, incompleteMove = false)
        task =
            scope.launch {
                try {
                    block()
                    if (revision == generation) mutableState.value = mutableState.value.copy(loading = false)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: Exception) {
                    if (revision ==
                        generation
                    ) {
                        mutableState.value =
                            mutableState.value.copy(loading = false, error = failure.toOpenCloudError())
                    }
                }
            }
    }

    override fun close() {
        scope.cancel()
        password?.fill('\u0000')
        password = null
        unlocked?.close()
        unlocked = null
        destination = null
        sources = emptyList()
    }
}

private fun vaultIdentity(location: VaultLocation): String =
    "vault:${location.accountId}:${location.canonicalServer}:${location.driveId}:${location.remoteVaultId}"

private data class BoundaryPlacementPlan(
    val names: List<String>,
    val conflict: BoundaryPlacementConflict?,
)
