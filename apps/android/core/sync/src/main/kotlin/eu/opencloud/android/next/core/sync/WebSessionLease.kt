package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.toOpenCloudError
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import java.util.concurrent.atomic.AtomicReference

/** Memory-only authorization boundary. A viewer must close on revocation; returned bytes cannot be recalled. */
class WebSessionLease<T : Any> internal constructor(
    session: T,
    private val permitted: () -> Boolean,
    private val isCurrent: suspend () -> Boolean,
) {
    private val payload = AtomicReference<T?>(session)

    // Drop sensitive causes; mapping rethrows cancellation.
    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    suspend fun current(): T =
        try {
            currentCoroutineContext().ensureActive()
            val selected = payload.get() ?: denied()
            if (!permitted() || !isCurrent()) denied()
            currentCoroutineContext().ensureActive()
            if (!permitted() || payload.get() !== selected) denied()
            selected
        } catch (failure: Exception) {
            close()
            throw OpenCloudException(failure.toOpenCloudError())
        }

    fun close() {
        payload.set(null)
    }

    private fun denied(): Nothing = throw OpenCloudException(OpenCloudError.AccessDenied)

    override fun toString(): String = "WebSessionLease(redacted)"
}
