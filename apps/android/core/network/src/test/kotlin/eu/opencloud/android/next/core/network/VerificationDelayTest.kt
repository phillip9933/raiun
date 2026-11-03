package eu.opencloud.android.next.core.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.concurrent.CancellationException
import java.util.concurrent.TimeUnit

class VerificationDelayTest {
    @Test
    fun slicesRetainFullRequestedDelay() {
        var now = 0L
        val waits = mutableListOf<Long>()
        awaitVerificationDelay(125, {}, { now }) {
            waits += it
            now += it
        }
        assertEquals(listOf(50L, 50L, 25L), waits.map(TimeUnit.NANOSECONDS::toMillis))
        assertEquals(TimeUnit.MILLISECONDS.toNanos(125), now)
    }

    @Test
    fun cancellationStopsLongDelayAtFirstSlice() {
        var now = 0L
        var cancelled = false
        try {
            awaitVerificationDelay(
                30_000,
                { if (cancelled) throw CancellationException("Synthetic cancellation") },
                { now },
            ) {
                now += it
                cancelled = true
            }
            fail("Cancellation must escape")
        } catch (_: CancellationException) {
            assertTrue(now <= TimeUnit.MILLISECONDS.toNanos(50))
        }
    }

    @Test
    fun interruptedWaitPreservesThreadInterrupt() {
        try {
            awaitVerificationDelay(100, {}, { 0 }) { throw InterruptedException() }
            fail("Interruption must cancel verification")
        } catch (_: CancellationException) {
            assertTrue(Thread.currentThread().isInterrupted)
        } finally {
            Thread.interrupted()
        }
    }
}
