package eu.opencloud.android.next.core.sync

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

/** Operation-owned immutable directory; unrelated UI pages and destination writes do not consume its entries. */
interface BoundaryDirectorySnapshot : AutoCloseable {
    val totalCount: Long

    /** Sequence is one-based build order; start at zero, then advance by the actual number of returned entries. */
    suspend fun page(
        afterSequence: Long = 0,
        limit: Int = 128,
    ): List<BoundaryEntry>

    suspend fun findById(id: String): BoundaryEntry?

    suspend fun forEach(block: suspend (BoundaryEntry) -> Unit) {
        var after = 0L
        while (after < totalCount) {
            val entries = page(after)
            if (entries.isEmpty()) invalidBoundaryDirectory()
            for (entry in entries) {
                currentCoroutineContext().ensureActive()
                if (findById(entry.id) != entry) invalidBoundaryDirectory()
                block(entry)
                currentCoroutineContext().ensureActive()
                if (findById(entry.id) != entry) invalidBoundaryDirectory()
            }
            after += entries.size
        }
    }

    override fun close()
}

/** The producer must await its complete validated stream; emitting never suspends or retains a database cursor. */
internal suspend fun captureBoundaryDirectory(
    context: Context,
    path: String,
    guard: suspend () -> Unit,
    produce: suspend ((BoundaryEntry) -> Unit) -> Unit,
): BoundaryDirectorySnapshot {
    var store: BoundaryDirectoryStore? = null
    var delivered = false
    try {
        val result =
            withContext(Dispatchers.IO) {
                currentCoroutineContext().ensureActive()
                guard()
                currentCoroutineContext().ensureActive()
                requireBoundaryDirectoryParent(path)
                val building = BoundaryDirectoryStore(context, path)
                store = building
                val buildContext = currentCoroutineContext()
                produce { entry ->
                    buildContext.ensureActive()
                    building.add(entry)
                }
                guard()
                currentCoroutineContext().ensureActive()
                val count = building.finish()
                CapturedBoundaryDirectory(building, count, guard)
            }
        delivered = true
        return result
    } finally {
        // Includes cancellation while an IO result is returning to its original dispatcher.
        if (!delivered) store?.close()
    }
}

private class CapturedBoundaryDirectory(
    private val store: BoundaryDirectoryStore,
    override val totalCount: Long,
    private val guard: suspend () -> Unit,
) : BoundaryDirectorySnapshot {
    override suspend fun page(
        afterSequence: Long,
        limit: Int,
    ): List<BoundaryEntry> =
        deliver {
            store.page(afterSequence, limit)
        }

    override suspend fun findById(id: String): BoundaryEntry? = deliver { store.findById(id) }

    override suspend fun forEach(block: suspend (BoundaryEntry) -> Unit) {
        var completed = false
        try {
            var after = 0L
            while (after < totalCount) {
                val entries = page(after)
                if (entries.isEmpty()) invalidBoundaryDirectory()
                for (entry in entries) {
                    requireCurrent()
                    block(entry)
                    requireCurrent()
                }
                after += entries.size
            }
            requireCurrent()
            completed = true
        } finally {
            if (!completed) close()
        }
    }

    private suspend fun <T> deliver(read: () -> T): T {
        var delivered = false
        try {
            val result =
                withContext(Dispatchers.IO) {
                    requireCurrent()
                    val value = read()
                    requireCurrent()
                    value
                }
            delivered = true
            return result
        } finally {
            if (!delivered) close()
        }
    }

    private suspend fun requireCurrent() {
        store.requireOpen()
        currentCoroutineContext().ensureActive()
        guard()
        currentCoroutineContext().ensureActive()
        store.requireOpen()
    }

    override fun close() = store.close()
}
