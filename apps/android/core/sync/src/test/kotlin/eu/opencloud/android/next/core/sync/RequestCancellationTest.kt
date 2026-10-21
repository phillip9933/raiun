package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.TransferClient
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.SocketPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class RequestCancellationTest {
    @Test fun `revoked durable ownership closes a blocked request as cancellation`() =
        runBlocking {
            MockWebServer().use { server ->
                server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE))
                val client = TransferClient(OkHttpClient.Builder().readTimeout(1, TimeUnit.MINUTES).build())
                val owned = AtomicBoolean(true)
                val cancelled = AtomicBoolean(false)
                val job =
                    launch(Dispatchers.IO) {
                        try {
                            withRequestCancellation(client::cancelRequests, isOwned = { owned.get() }) {
                                client.download(server.url("/blocked").toString(), "Basic fixture", 0) { _, _, _ -> }
                            }
                        } catch (failure: CancellationException) {
                            cancelled.set(true)
                            throw failure
                        }
                    }
                assertNotNull(server.takeRequest(5, TimeUnit.SECONDS))
                owned.set(false)
                withTimeout(5_000) { job.join() }
                assertTrue(cancelled.get())
                assertTrue(job.isCancelled)
            }
        }

    @Test fun `already revoked ownership never executes request block`() =
        runBlocking {
            var executed = false
            var cancelled = false
            try {
                withRequestCancellation({}, isOwned = { false }) { executed = true }
            } catch (_: CancellationException) {
                cancelled = true
            }
            assertTrue(cancelled)
            assertFalse(executed)
        }

    @Test fun `successful owned request stops observer without cancelling client`() =
        runBlocking {
            var cancelled = false
            val result = withRequestCancellation({ cancelled = true }, isOwned = { true }) { "done" }
            assertEquals("done", result)
            assertFalse(cancelled)
        }

    @Test fun `cancellation closes a blocked request before its network timeout`() =
        runBlocking {
            MockWebServer().use { server ->
                server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE))
                val client = TransferClient(OkHttpClient.Builder().readTimeout(1, TimeUnit.MINUTES).build())
                val job =
                    launch(Dispatchers.IO) {
                        withRequestCancellation(client::cancelRequests) {
                            client.download(server.url("/blocked").toString(), "Basic fixture", 0) { _, _, _ -> }
                        }
                    }
                assertNotNull(server.takeRequest(5, TimeUnit.SECONDS))
                withTimeout(5_000) { job.cancelAndJoin() }
                assertTrue(job.isCancelled)
            }
        }
}
