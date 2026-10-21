package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.toOpenCloudError
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicReference

interface EmbeddedSessionSurface<T : Any> {
    fun show(session: T)

    fun close()
}

/** Single-use host. Call start/close on the owner's UI dispatcher; background/lock must call close. */
class EmbeddedHostController<T : Any>(
    private val owner: CoroutineScope,
    private val surface: EmbeddedSessionSurface<T>,
    private val open: suspend () -> WebSessionLease<T>,
    private val onError: (OpenCloudError) -> Unit,
    private val io: CoroutineDispatcher = Dispatchers.IO,
) {
    private val lease = AtomicReference<WebSessionLease<T>?>(null)
    private var job: Job? = null
    private var started = false
    private var closed = false
    private var surfaceClosed = false

    fun start() {
        if (started || closed) return
        started = true
        // Enter the cleanup region even when the owner is cancelled before its dispatcher runs.
        job = owner.launch(start = CoroutineStart.UNDISPATCHED) { runSession() }
    }

    fun close() {
        closed = true
        job?.cancel()
        dispose()
    }

    @Suppress("TooGenericExceptionCaught") // UI boundary emits typed errors only; cancellation is preserved.
    private suspend fun runSession() {
        try {
            val active = withContext(io) { open().also { lease.set(it) } }
            val payload = withContext(io) { active.current() }
            currentCoroutineContext().ensureActive()
            if (!closed) surface.show(payload)
            while (!closed) {
                delay(1000)
                withContext(io) { active.current() }
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            if (!closed) onError(failure.toOpenCloudError())
        } finally {
            closed = true
            dispose()
        }
    }

    private fun dispose() {
        lease.getAndSet(null)?.close()
        if (!surfaceClosed) {
            surfaceClosed = true
            surface.close()
        }
    }

    override fun toString(): String = "EmbeddedHostController(redacted)"
}
