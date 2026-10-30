package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.toOpenCloudError
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicReference

/** One fresh browser grant and one external dispatch. The owner permanently closes it on background/disposal. */
@Suppress("LongParameterList")
class BrowserHandoffController(
    private val owner: CoroutineScope,
    private val open: suspend () -> WebSessionLease<String>,
    private val launch: (String) -> Boolean,
    private val onUnavailable: () -> Unit,
    private val onError: (OpenCloudError) -> Unit,
    private val io: CoroutineDispatcher = Dispatchers.IO,
) {
    private val lease = AtomicReference<WebSessionLease<String>?>(null)
    private var job: Job? = null
    private var started = false
    private var closed = false

    fun start() {
        if (started || closed) return
        started = true
        job = owner.launch(start = CoroutineStart.UNDISPATCHED) { handoff() }
    }

    fun close() {
        closed = true
        job?.cancel()
        lease.getAndSet(null)?.close()
    }

    @Suppress("TooGenericExceptionCaught") // Cancellation stays cancellation; UI receives only typed errors.
    private suspend fun handoff() {
        try {
            val active = withContext(io) { open().also { lease.set(it) } }
            val url = withContext(io) { active.current() }
            currentCoroutineContext().ensureActive()
            if (!closed) {
                if (!active.isPermitted()) throw OpenCloudException(OpenCloudError.AccessDenied)
                if (!launch(url)) onUnavailable()
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            if (!closed) onError(failure.toOpenCloudError())
        } finally {
            closed = true
            lease.getAndSet(null)?.close()
        }
    }

    override fun toString(): String = "BrowserHandoffController(redacted)"
}
