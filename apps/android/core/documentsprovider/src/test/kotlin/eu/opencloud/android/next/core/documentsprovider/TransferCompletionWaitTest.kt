package eu.opencloud.android.next.core.documentsprovider

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.FileNotFoundException
import java.util.concurrent.atomic.AtomicBoolean

class TransferCompletionWaitTest {
    @Test
    fun observesCompletionWithoutPollingTransfer() =
        runBlocking {
            val states = MutableStateFlow<String?>("RUNNING")
            val checked = CompletableDeferred<Unit>()
            val wait =
                async {
                    awaitEditDownload(states) {
                        checked.complete(Unit)
                        true
                    }
                }
            withTimeout(2_000) { checked.await() }
            states.value = "SUCCEEDED"
            withTimeout(2_000) { wait.await() }
        }

    @Test
    fun cancellationStopsUnchangedTransferWait() =
        runBlocking {
            val checked = CompletableDeferred<Unit>()
            val wait =
                async {
                    awaitEditDownload(MutableStateFlow("RUNNING")) {
                        checked.complete(Unit)
                        true
                    }
                }
            withTimeout(2_000) { checked.await() }
            withTimeout(2_000) { wait.cancelAndJoin() }
            assertTrue(wait.isCancelled)
        }

    @Test
    fun revocationFailsEvenWithoutTransferEmissions() =
        runBlocking {
            val allowed = AtomicBoolean(true)
            val checked = CompletableDeferred<Unit>()
            val wait =
                async {
                    try {
                        awaitEditDownload(MutableStateFlow("RUNNING")) {
                            checked.complete(Unit)
                            allowed.get()
                        }
                        false
                    } catch (_: IllegalStateException) {
                        true
                    }
                }
            withTimeout(2_000) { checked.await() }
            allowed.set(false)
            assertTrue(withTimeout(2_000) { wait.await() })
        }

    @Test
    fun stalledWaitHonorsCallerTimeout() =
        runBlocking {
            try {
                withTimeout(50) {
                    awaitEditDownload(MutableStateFlow("RUNNING")) { true }
                }
                fail("Stalled download must time out")
            } catch (_: TimeoutCancellationException) {
                // The surrounding provider deadline remains authoritative.
            }
        }

    @Test
    fun missingAndFailedTransfersFailClosed() =
        runBlocking {
            for (state in listOf(null, "FAILED", "CANCELLED", "CONFLICT", "AWAITING_UNLOCK", "future", "SUCCEEDED ")) {
                try {
                    awaitEditDownload(flowOf(state)) { true }
                    fail("Invalid transfer must fail")
                } catch (_: FileNotFoundException) {
                    // No writable document is returned.
                }
            }
        }
}
