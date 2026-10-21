package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class SharedReadPreparationTest {
    @Test fun reusesVerifiedReaderWithoutEnqueue() =
        runBlocking {
            var closed = 0
            val preparation =
                SharedReadPreparation(
                    { SharedReadSession(1, { closed++ }) { _, size -> ByteArray(size) } },
                    { error("Cached reads must not enqueue") },
                    { error("No transfer to poll") },
                    { true },
                )
            preparation.open().use { assertEquals(1, it.read(0, 1).size) }
            assertEquals(1, closed)
        }

    @Test fun missingCopyWaitsForSuccessThenReopensVerifiedReader() =
        runBlocking {
            var reads = 0
            var queued = 0
            val preparation =
                SharedReadPreparation({
                    if (reads++ == 0) throw SharedCopyUnavailable()
                    SharedReadSession(1, {}) { _, size -> ByteArray(size) }
                }, {
                    queued++
                    "transfer"
                }, {
                    assertEquals("transfer", it)
                    "SUCCEEDED"
                }, { true })
            preparation.open().close()
            assertEquals(2, reads)
            assertEquals(1, queued)
        }

    @Test fun permissionAndVersionFailuresNeverTriggerDownload() =
        runBlocking {
            for (error in listOf(OpenCloudError.AccessDenied, OpenCloudError.PreconditionFailed)) {
                val preparation =
                    SharedReadPreparation({ throw OpenCloudException(error) }, {
                        error("Must not download after denial or version change")
                    }, { "SUCCEEDED" }, { true })
                val failure = assertThrows(OpenCloudException::class.java) { runBlocking { preparation.open() } }
                assertEquals(error, failure.error)
            }
        }

    @Test fun failedTransferDoesNotReopenAndCancellationStopsWaiting() =
        runBlocking {
            val failed =
                SharedReadPreparation({ throw SharedCopyUnavailable() }, { "transfer" }, { "FAILED" }, { true })
            val failure = assertThrows(OpenCloudException::class.java) { runBlocking { failed.open() } }
            assertEquals(OpenCloudError.SourceUnavailable, failure.error)
            val polled = CompletableDeferred<Unit>()
            val waiting =
                SharedReadPreparation({ throw SharedCopyUnavailable() }, { "transfer" }, {
                    polled.complete(Unit)
                    "RUNNING"
                }, { true })
            val opening = async { waiting.open() }
            withTimeout(5_000) { polled.await() }
            opening.cancel()
            assertThrows(CancellationException::class.java) { runBlocking { opening.await() } }
            Unit
        }

    @Test fun revocationClosesReaderBeforeReturningIt() =
        runBlocking {
            var allowed = true
            var closed = 0
            val preparation =
                SharedReadPreparation({
                    allowed = false
                    SharedReadSession(1, { closed++ }) { _, size -> ByteArray(size) }
                }, { error("Must not enqueue") }, { "SUCCEEDED" }, { allowed })
            assertThrows(OpenCloudException::class.java) { runBlocking { preparation.open() } }
            assertEquals(1, closed)
        }
}
