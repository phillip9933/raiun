package eu.opencloud.android.next.core.network

import java.util.concurrent.CancellationException
import java.util.concurrent.TimeUnit

/** Retains the synchronous transfer API while checking cancellation at least every 50 ms. */
internal fun awaitVerificationDelay(
    delayMillis: Long,
    checkActive: () -> Unit,
    nanoTime: () -> Long = System::nanoTime,
    sleepNanos: (Long) -> Unit = { TimeUnit.NANOSECONDS.sleep(it) },
) {
    checkActive()
    if (delayMillis == 0L) return
    require(delayMillis > 0)
    val duration = TimeUnit.MILLISECONDS.toNanos(delayMillis)
    val started = nanoTime()
    while (true) {
        val remaining = duration - (nanoTime() - started)
        if (remaining <= 0) break
        try {
            sleepNanos(minOf(remaining, TimeUnit.MILLISECONDS.toNanos(50)))
        } catch (cancelled: InterruptedException) {
            Thread.currentThread().interrupt()
            throw CancellationException("Verification cancelled").also { it.initCause(cancelled) }
        }
        checkActive()
    }
    checkActive()
}
