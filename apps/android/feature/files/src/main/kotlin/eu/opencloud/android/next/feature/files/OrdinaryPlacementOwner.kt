package eu.opencloud.android.next.feature.files

import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.sync.FileOperationNameConflictException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicReference

/**
 * Owns ordinary placement attempts and conflict presentation in the browser's scope.
 * Account, location and accepted UI state remain with the ViewModel; enqueue retains
 * conditional operation admission. Navigation hides stale UI without permitting a
 * second attempt while the first enqueue is still running. A revision fences
 * results across leave-and-return transitions even when the location values match.
 */
internal class OrdinaryPlacementOwner(
    private val scope: CoroutineScope,
    private val state: StateFlow<FileBrowserUiState>,
    private val currentAccount: () -> String?,
    private val reduce: (FileBrowserUiState.() -> FileBrowserUiState) -> Unit,
    private val failureMessage: (Exception) -> String,
    private val enqueue: suspend (ResourceEntity, String, String?, String, Boolean, String) -> Unit,
) {
    private var placementInFlight = false
    private val contextRevision = AtomicReference(PlacementContextRevision(0))

    fun cancelPlacement() = reduce { copy(clipboard = null, clipboardItems = emptyList(), placementConflict = null) }

    // Cancellation is rethrown; preserve explicit batch and stale-context exits.
    @Suppress("TooGenericExceptionCaught", "CyclomaticComplexMethod", "ReturnCount")
    fun place() {
        val current = state.value
        val account = currentAccount() ?: return
        val space = current.spaceId ?: return
        val parent = current.currentFolderId
        val sources = current.clipboardItems.ifEmpty { listOfNotNull(current.clipboard) }
        if (sources.isEmpty() || placementInFlight) return
        if (sources.any { it.accountId != account }) {
            cancelPlacement()
            return
        }
        val target = FileOperationPlacementTarget(account, space, parent, contextRevision.get())
        placementInFlight = true
        reduce { copy(placementBusy = true) }
        scope.launch {
            try {
                for (source in sources) {
                    if (!isPlacementContextCurrent(target)) return@launch
                    val failure =
                        try {
                            withContext(Dispatchers.IO) {
                                enqueue(source, space, parent, source.name, current.moving, source.name)
                            }
                            null
                        } catch (cancelled: CancellationException) {
                            throw cancelled
                        } catch (error: Exception) {
                            error
                        }
                    if (!isPlacementContextCurrent(target)) return@launch
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
                        reduce { copy(error = failureMessage(failure)) }
                        return@launch
                    }
                    removePlacementSource(source)
                }
                if (isPlacementContextCurrent(target)) {
                    reduce { copy(selectedIds = emptySet(), actionResource = null) }
                }
            } finally {
                placementInFlight = false
                if (isPlacementContextCurrent(target)) {
                    reduce { copy(placementBusy = false) }
                }
            }
        }
    }

    // Cancellation is rethrown; preserve explicit retry and stale-context exits.
    @Suppress("TooGenericExceptionCaught", "ReturnCount")
    fun keepBothPlacementConflict() {
        val conflict = state.value.placementConflict ?: return
        val account = currentAccount()
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
            FileOperationPlacementTarget(
                conflict.source.accountId,
                conflict.destinationSpaceId,
                conflict.parentId,
                contextRevision.get(),
            )
        placementInFlight = true
        reduce { copy(placementBusy = true) }
        scope.launch {
            try {
                val failure =
                    try {
                        withContext(Dispatchers.IO) {
                            enqueue(
                                conflict.source,
                                conflict.destinationSpaceId,
                                conflict.parentId,
                                conflict.suggestedName,
                                conflict.moving,
                                conflict.source.name,
                            )
                        }
                        null
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (error: Exception) {
                        error
                    }
                if (!isPlacementContextCurrent(target)) return@launch
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
                                error = failureMessage(failure),
                            )
                        }
                    }
                }
            } finally {
                placementInFlight = false
                if (isPlacementContextCurrent(target)) {
                    reduce { copy(placementBusy = false) }
                }
            }
        }
    }

    private fun isPlacementContextCurrent(target: FileOperationPlacementTarget): Boolean =
        contextRevision.get() == target.revision &&
            currentAccount() == target.accountId &&
            state.value.spaceId == target.spaceId &&
            state.value.currentFolderId == target.parentId

    /** Called by account/location authority only for real transitions, including account changes without a Space. */
    fun contextChanged() {
        contextRevision.updateAndGet { it.next() }
        reduce { copy(placementBusy = false, placementConflict = null) }
    }

    private fun removePlacementSource(source: ResourceEntity) =
        reduce {
            val remaining =
                (clipboardItems.ifEmpty { listOfNotNull(clipboard) }).filterNot {
                    it.remoteId == source.remoteId && it.spaceId == source.spaceId
                }
            copy(clipboard = remaining.firstOrNull(), clipboardItems = remaining, placementConflict = null)
        }
}

private data class FileOperationPlacementTarget(
    val accountId: String,
    val spaceId: String,
    val parentId: String?,
    val revision: PlacementContextRevision,
)

private data class PlacementContextRevision(
    val value: Long,
) {
    fun next() = PlacementContextRevision(Math.incrementExact(value))
}
