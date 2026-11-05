package eu.opencloud.android.next.ui

import eu.opencloud.android.next.core.sync.VaultFolder
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow

internal data class OpenedVaultDirectory(
    val snapshot: VaultRouteDirectorySnapshot,
    val entries: List<VaultFolder>,
    val showHidden: Boolean,
)

internal data class VaultDirectoryPageRequest(
    val opened: VaultRouteSession,
    val snapshot: VaultRouteDirectorySnapshot,
    val account: String,
    val page: VaultDirectoryPageState,
    val offset: Long,
    val previous: Boolean,
)

/** The route lifecycle retains session admission, cancellation, action leases and failure policy. */
internal interface VaultDirectoryOwner {
    fun showHidden(): Boolean

    fun isCurrent(
        opened: VaultRouteSession,
        token: Long,
        account: String,
    ): Boolean

    fun isRouteCurrent(
        token: Long,
        account: String,
    ): Boolean

    fun present(entries: List<VaultFolder>): List<VaultRouteEntry>

    fun clearPresented()

    fun reportFailure(
        failure: Exception,
        token: Long,
        account: String,
    )
}

/** Owns directory snapshots and their page bookmarks; the route closes it before closing its session. */
internal class VaultDirectoryContent(
    private val state: MutableStateFlow<VaultRouteState>,
    private val owner: VaultDirectoryOwner,
) {
    private var directory: VaultRouteDirectorySnapshot? = null
    private val previousOffsets = mutableListOf<Long>()

    suspend fun openFirst(
        opened: VaultRouteSession,
        path: String,
    ): OpenedVaultDirectory {
        while (true) {
            val visibility = owner.showHidden()
            val snapshot = opened.openDirectory(path, visibility)
            var delivered = false
            try {
                currentCoroutineContext().ensureActive()
                val entries = snapshot.page(0, VAULT_DIRECTORY_PAGE_SIZE)
                currentCoroutineContext().ensureActive()
                if (visibility == owner.showHidden()) {
                    delivered = true
                    return OpenedVaultDirectory(snapshot, entries, visibility)
                }
            } finally {
                if (!delivered) snapshot.close()
            }
        }
    }

    suspend fun currentVisibility(
        opened: VaultRouteSession,
        first: OpenedVaultDirectory,
    ): OpenedVaultDirectory {
        if (first.showHidden == owner.showHidden()) return first
        first.snapshot.close()
        return openFirst(opened, "")
    }

    fun adopt(
        snapshot: VaultRouteDirectorySnapshot,
        offsets: List<Long> = emptyList(),
    ) {
        directory = snapshot
        previousOffsets.clear()
        previousOffsets.addAll(offsets)
    }

    suspend fun replace(
        opened: VaultRouteSession,
        path: String,
        token: Long,
        account: String,
    ) {
        if (!owner.isCurrent(opened, token, account)) return
        close()
        val first = openFirst(opened, path)
        var adopted = false
        try {
            if (!owner.isCurrent(opened, token, account)) return
            adopt(first.snapshot)
            adopted = true
            state.value =
                state.value.copy(
                    entries = owner.present(first.entries),
                    directoryPage = VaultDirectoryPageState(0, first.snapshot.totalCount, first.entries.size, false),
                    currentPath = path,
                    loading = false,
                    error = null,
                )
        } finally {
            if (!adopted) first.snapshot.close()
        }
    }

    @Suppress("ReturnCount") // Independent snapshot and page bounds fail closed before a page job is admitted.
    fun pageRequest(
        opened: VaultRouteSession,
        account: String,
        previous: Boolean,
    ): VaultDirectoryPageRequest? {
        val snapshot = directory ?: return null
        val page = state.value.directoryPage ?: return null
        val canMove = if (previous) page.hasPrevious else page.hasNext
        if (state.value.loading || !canMove) return null
        val offset = if (previous) previousOffsets.lastOrNull() ?: return null else page.offset + page.count
        return VaultDirectoryPageRequest(opened, snapshot, account, page, offset, previous)
    }

    @Suppress("TooGenericExceptionCaught") // Failed or cancelled pages revoke the snapshot and its leases.
    suspend fun loadPage(request: VaultDirectoryPageRequest, token: Long) {
        var delivered = false
        try {
            val entries = request.snapshot.page(request.offset, VAULT_DIRECTORY_PAGE_SIZE)
            currentCoroutineContext().ensureActive()
            if (!owner.isCurrent(request.opened, token, request.account) || directory !== request.snapshot) return
            if (request.previous) {
                previousOffsets.removeAt(previousOffsets.lastIndex)
            } else {
                previousOffsets +=
                    request.page.offset
            }
            state.value =
                state.value.copy(
                    entries = owner.present(entries),
                    directoryPage =
                        VaultDirectoryPageState(
                            request.offset,
                            request.snapshot.totalCount,
                            entries.size,
                            previousOffsets.isNotEmpty(),
                        ),
                    loading = false,
                    error = null,
                )
            delivered = true
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            if (owner.isRouteCurrent(token, request.account) && directory === request.snapshot) close()
            owner.reportFailure(failure, token, request.account)
        } finally {
            if (!delivered && directory === request.snapshot) close()
        }
    }

    fun close() {
        directory?.close()
        directory = null
        previousOffsets.clear()
        owner.clearPresented()
        state.value = state.value.copy(directoryPage = null)
    }
}
