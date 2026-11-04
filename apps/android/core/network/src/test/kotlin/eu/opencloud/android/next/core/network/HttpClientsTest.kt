package eu.opencloud.android.next.core.network

import okhttp3.Call
import okhttp3.Callback
import okhttp3.Request
import okhttp3.Response
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import okhttp3.mockwebserver.SocketPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class HttpClientsTest {
    @Test
    fun `ordinary owners reuse connections without retaining account headers`() {
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setBody("one"))
            server.enqueue(MockResponse().setBody("two"))
            val first = HttpClients.newClient()
            val second = HttpClients.newClient()
            assertSame(first.connectionPool, second.connectionPool)
            assertSame(first.dispatcher.executorService, second.dispatcher.executorService)
            assertNotSame(first.dispatcher, second.dispatcher)
            first
                .newCall(
                    Request
                        .Builder()
                        .url(server.url("/one"))
                        .header("Authorization", "Bearer first")
                        .build(),
                ).execute()
                .use { assertEquals("one", it.body!!.string()) }
            second
                .newCall(Request.Builder().url(server.url("/two")).build())
                .execute()
                .use { assertEquals("two", it.body!!.string()) }
            assertEquals("Bearer first", server.takeRequest().getHeader("Authorization"))
            val request = server.takeRequest()
            assertEquals(null, request.getHeader("Authorization"))
            assertEquals(1, request.sequenceNumber)
        }
    }

    @Test
    fun `cancelling one owner leaves another owners request running`() {
        val releaseSecond = CountDownLatch(1)
        val completed = CountDownLatch(2)
        val firstFailed = CountDownLatch(1)
        val secondSucceeded = CountDownLatch(1)
        MockWebServer().use { server ->
            server.dispatcher =
                object : okhttp3.mockwebserver.Dispatcher() {
                    override fun dispatch(request: RecordedRequest): MockResponse =
                        if (request.path == "/one") {
                            MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE)
                        } else {
                            check(releaseSecond.await(15, TimeUnit.SECONDS))
                            MockResponse().setBody("two")
                        }
                }
            val first = HttpClients.newClient()
            val second = HttpClients.newClient()

            fun callback(
                success: CountDownLatch?,
                failure: CountDownLatch?,
            ) = object : Callback {
                override fun onFailure(
                    call: Call,
                    e: IOException,
                ) {
                    failure?.countDown()
                    completed.countDown()
                }

                override fun onResponse(
                    call: Call,
                    response: Response,
                ) {
                    response.use { it.body!!.string() }
                    success?.countDown()
                    completed.countDown()
                }
            }
            val otherCall = second.newCall(Request.Builder().url(server.url("/two")).build())
            try {
                first.newCall(Request.Builder().url(server.url("/one")).build()).enqueue(callback(null, firstFailed))
                otherCall.enqueue(callback(secondSucceeded, null))
                checkNotNull(server.takeRequest(5, TimeUnit.SECONDS))
                checkNotNull(server.takeRequest(5, TimeUnit.SECONDS))
                first.dispatcher.cancelAll()
                assertTrue(firstFailed.await(5, TimeUnit.SECONDS))
                assertFalse(otherCall.isCanceled())
                releaseSecond.countDown()
                assertTrue(secondSucceeded.await(5, TimeUnit.SECONDS))
                assertTrue(completed.await(5, TimeUnit.SECONDS))
            } finally {
                releaseSecond.countDown()
                first.dispatcher.cancelAll()
                second.dispatcher.cancelAll()
            }
        }
    }
}
