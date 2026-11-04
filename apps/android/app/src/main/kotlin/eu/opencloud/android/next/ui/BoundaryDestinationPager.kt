package eu.opencloud.android.next.ui

import android.content.Context
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.sync.BoundaryDestinationFolder
import eu.opencloud.android.next.core.sync.BoundaryDestinationSnapshot
import eu.opencloud.android.next.core.sync.BoundaryEndpoint
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.Closeable
import java.util.ArrayDeque

internal data class BoundaryDestinationPage(
    val offset: Long,
    val total: Long,
    val count: Int,
    val hasPrevious: Boolean,
) {
    val hasNext: Boolean get() = offset + count < total
}

internal data class BoundaryDestinationWindow(
    val folders: List<BoundaryDestinationFolder>,
    val page: BoundaryDestinationPage,
)

/** Owns navigation metadata and offset bookmarks, never an endpoint or its source-owned unlock session. */
internal class BoundaryDestinationPager(
    private val context: Context,
    private val ioDispatcher: CoroutineDispatcher,
) : Closeable {
    private var snapshot: BoundaryDestinationSnapshot? = null
    private val previousOffsets = ArrayDeque<Long>()
    private var revision = 0L

    suspend fun open(
        endpoint: BoundaryEndpoint,
        path: String,
        admit: () -> Unit,
    ): BoundaryDestinationWindow {
        close()
        val ticket = revision
        var produced: BoundaryDestinationSnapshot? = null
        var adopted = false
        try {
            val created =
                withContext(ioDispatcher) {
                    endpoint.openDestinationFolders(context, path).also { produced = it }
                }
            requireCurrent(ticket, admit)
            val total = created.totalCount
            val folders = withContext(ioDispatcher) { created.page(0, 128) }
            requireCurrent(ticket, admit)
            val page = pageState(created, 0, total, folders, false)
            snapshot = created
            adopted = true
            return BoundaryDestinationWindow(folders, page)
        } finally {
            if (!adopted) produced?.close()
        }
    }

    suspend fun page(
        previous: Boolean,
        current: BoundaryDestinationPage,
        admit: () -> Unit,
    ): BoundaryDestinationWindow {
        val captured = snapshot ?: throw CancellationException("Destination inventory is closed")
        val ticket = revision
        val offset =
            if (previous) {
                previousOffsets.peekLast() ?: throw CancellationException("No previous destination page")
            } else {
                current.offset + current.count
            }
        var delivered = false
        try {
            val folders = withContext(ioDispatcher) { captured.page(offset, 128) }
            requireCurrent(ticket, admit)
            if (previous) previousOffsets.removeLast() else previousOffsets.addLast(current.offset)
            val page = pageState(captured, offset, current.total, folders, previousOffsets.isNotEmpty())
            delivered = true
            return BoundaryDestinationWindow(folders, page)
        } finally {
            if (!delivered && ticket == revision) close()
        }
    }

    private fun pageState(
        captured: BoundaryDestinationSnapshot,
        offset: Long,
        total: Long,
        folders: List<BoundaryDestinationFolder>,
        hasPrevious: Boolean,
    ): BoundaryDestinationPage {
        val validCount = total >= 0 && captured.totalCount == total && folders.size <= 128
        val validWindow = offset in 0..total && folders.size.toLong() <= total - offset
        val validProgress = folders.isNotEmpty() || offset == total
        if (!validCount || !validWindow || !validProgress) throw OpenCloudException(OpenCloudError.InvalidResponse)
        return BoundaryDestinationPage(offset, total, folders.size, hasPrevious)
    }

    private suspend fun requireCurrent(
        ticket: Long,
        admit: () -> Unit,
    ) {
        currentCoroutineContext().ensureActive()
        if (ticket != revision) throw CancellationException("Destination navigation changed")
        admit()
    }

    override fun close() {
        revision++
        snapshot?.close()
        snapshot = null
        previousOffsets.clear()
    }
}
