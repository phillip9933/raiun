package eu.opencloud.android.next.core.sync

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean

/** A separate dispatcher can close sockets while the worker is blocked in a synchronous HTTP read. */
@Suppress("TooGenericExceptionCaught") // Cancelled sockets retain the coroutine cancellation cause.
internal suspend fun <T> withRequestCancellation(
    cancelRequests: () -> Unit,
    isOwned: (suspend () -> Boolean)? = null,
    block: suspend () -> T,
): T =
    coroutineScope {
        if (isOwned != null && !isOwned()) throw CancellationException("Work ownership revoked")
        val scope = this
        val finished = AtomicBoolean(false)
        val observer =
            launch(Dispatchers.Default, start = CoroutineStart.UNDISPATCHED) {
                try {
                    if (isOwned == null) awaitCancellation()
                    while (true) {
                        delay(250)
                        if (isOwned != null && !isOwned()) {
                            scope.cancel(CancellationException("Work ownership revoked"))
                        }
                    }
                } finally {
                    if (!finished.get()) cancelRequests()
                }
            }
        try {
            block()
        } catch (failure: Exception) {
            currentCoroutineContext().ensureActive()
            throw failure
        } finally {
            finished.set(true)
            observer.cancel()
        }
    }
