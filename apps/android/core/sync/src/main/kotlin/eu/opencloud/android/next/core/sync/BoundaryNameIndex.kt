package eu.opencloud.android.next.core.sync

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

/** Exact, operation-owned membership plus reservations; conditional server writes remain authoritative. */
interface BoundaryNameIndex : AutoCloseable {
    /** Returns true once for an absent name, reserving it against later candidates in this operation. */
    suspend fun reserve(name: String): Boolean

    override fun close()
}

/** Producers fully validate the complete parent response before this private index can be published. */
internal suspend fun captureBoundaryNames(
    context: Context,
    path: String,
    guard: suspend () -> Unit,
    produce: suspend ((String) -> Unit) -> Unit,
): BoundaryNameIndex {
    var store: BoundaryNameStore? = null
    var delivered = false
    try {
        val result =
            withContext(Dispatchers.IO) {
                currentCoroutineContext().ensureActive()
                guard()
                currentCoroutineContext().ensureActive()
                requireBoundaryDirectoryParent(path)
                val building = BoundaryNameStore(context)
                store = building
                val buildContext = currentCoroutineContext()
                produce { name ->
                    buildContext.ensureActive()
                    building.add(name)
                }
                building.finish()
                guard()
                currentCoroutineContext().ensureActive()
                CapturedBoundaryNames(building, guard)
            }
        delivered = true
        return result
    } finally {
        if (!delivered) store?.close()
    }
}

private class CapturedBoundaryNames(
    private val store: BoundaryNameStore,
    private val guard: suspend () -> Unit,
) : BoundaryNameIndex {
    override suspend fun reserve(name: String): Boolean {
        var delivered = false
        try {
            val result =
                withContext(Dispatchers.IO) {
                    requireCurrent()
                    val reserved = store.reserve(name)
                    requireCurrent()
                    reserved
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
