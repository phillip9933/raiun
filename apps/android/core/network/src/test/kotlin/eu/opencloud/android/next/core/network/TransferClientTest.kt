package eu.opencloud.android.next.core.network

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayInputStream

class TransferClientTest {
    private lateinit var server: MockWebServer
    private lateinit var client: TransferClient

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
        client = TransferClient(OkHttpClient())
    }

    @After
    fun tearDown() = server.shutdown()

    @Test
    fun `HTTP errors discard response bodies and retain typed retry metadata`() {
        val cases =
            mapOf(
                401 to OpenCloudError.AuthenticationRequired,
                403 to OpenCloudError.AccessDenied,
                409 to OpenCloudError.Conflict,
                429 to OpenCloudError.RateLimited(90),
                502 to OpenCloudError.ServerFailure(502, 90),
                507 to OpenCloudError.QuotaExceeded,
            )
        cases.forEach { (status, expected) ->
            server.enqueue(MockResponse().setResponseCode(404))
            server.enqueue(
                MockResponse().setResponseCode(status).setHeader("Retry-After", "90").setBody("Bearer secret"),
            )
            val failure =
                assertThrows(TransferHttpException::class.java) {
                    client.upload(server.url("file.txt").toString(), "Bearer token", null, 0, false, {
                        ByteArrayInputStream(byteArrayOf())
                    }, onProgress = {})
                }
            assertEquals(expected, failure.error)
            assertEquals(false, failure.toString().contains("secret"))
        }
    }

    @Test
    fun `DNS and timeout failures use typed contract and cancellation escapes`() {
        val failures =
            listOf(
                java.net.UnknownHostException("private host") to OpenCloudError.Connectivity,
                java.net.SocketTimeoutException("private URL") to OpenCloudError.Timeout,
            )
        failures.forEach { (exception, expected) ->
            val failingClient = TransferClient(OkHttpClient.Builder().addInterceptor { throw exception }.build())
            val failure =
                assertThrows(OpenCloudException::class.java) {
                    failingClient.tusOffset(server.url("upload").toString(), "Bearer token")
                }
            assertEquals(expected, failure.error)
        }
        val cancelled = java.util.concurrent.CancellationException("cancelled")
        val cancelledClient = TransferClient(OkHttpClient.Builder().addInterceptor { throw cancelled }.build())
        val failure =
            assertThrows(java.util.concurrent.CancellationException::class.java) {
                cancelledClient.tusOffset(server.url("upload").toString(), "Bearer token")
            }
        org.junit.Assert.assertSame(cancelled, failure)
    }

    @Test
    fun `plain upload streams content with conflict precondition`() {
        server.enqueue(MockResponse().setResponseCode(404))
        server.enqueue(MockResponse().setResponseCode(201).setHeader("ETag", "etag-1"))
        val bytes = "hello".toByteArray()

        val eTag =
            client.upload(server.url("file.txt").toString(), "Bearer token", "text/plain", bytes.size.toLong(), false, {
                ByteArrayInputStream(bytes)
            }, onProgress = {})

        assertEquals("etag-1", eTag)
        val preflight = server.takeRequest()
        assertEquals("HEAD", preflight.method)
        assertEquals("Bearer token", preflight.getHeader("Authorization"))
        assertEquals("no-cache", preflight.getHeader("Cache-Control"))
        val request = server.takeRequest()
        assertEquals("PUT", request.method)
        assertEquals("*", request.getHeader("If-None-Match"))
        assertEquals("hello", request.body.readUtf8())
    }

    @Test
    fun `download resumes with a range header`() {
        server.enqueue(
            MockResponse()
                .setResponseCode(206)
                .setBody("world")
                .setHeader("ETag", "\"v1\"")
                .setHeader("Content-Range", "bytes 5-9/10"),
        )
        var result = ""

        client.download(
            server.url("file.txt").toString(),
            "Basic credentials",
            5,
            DownloadExpectation(10, "\"v1\""),
        ) { input, _, resumed ->
            assertEquals(true, resumed)
            result = input.bufferedReader().readText()
        }

        assertEquals("world", result)
        assertEquals("bytes=5-", server.takeRequest().getHeader("Range"))
    }

    @Test
    fun `tus create head and patch preserve resumable state`() {
        server.enqueue(MockResponse().setResponseCode(201).setHeader("Location", server.url("uploads/1")))
        server.enqueue(MockResponse().setResponseCode(204).setHeader("Upload-Offset", "2"))
        server.enqueue(MockResponse().setResponseCode(204).setHeader("Upload-Offset", "5"))

        val url = client.createTusUpload(server.url("uploads").toString(), "Bearer token", 5, "filename ZmlsZS50eHQ=")
        assertEquals(2, client.tusOffset(url, "Bearer token"))
        assertEquals(
            5,
            client.patchTus(url, "Bearer token", 2, 3, {
                ByteArrayInputStream("llo".toByteArray())
            }, onProgress = {}),
        )
        server.takeRequest()
        server.takeRequest()
        assertEquals("llo", server.takeRequest().body.readUtf8())
    }

    @Test
    fun `tus patch writes only the declared chunk length`() {
        server.enqueue(MockResponse().setResponseCode(204).setHeader("Upload-Offset", "3"))

        client.patchTus(
            server.url("uploads/1").toString(),
            "Bearer token",
            0,
            3,
            { ByteArrayInputStream("abcdef".toByteArray()) },
            {},
        )

        assertEquals("abc", server.takeRequest().body.readUtf8())
    }

    @Test
    fun `precondition failure becomes a conflict`() {
        server.enqueue(MockResponse().setResponseCode(404))
        server.enqueue(MockResponse().setResponseCode(412))
        assertThrows(TransferConflictException::class.java) {
            client.upload(server.url("file.txt").toString(), "Bearer token", null, 0, false, {
                ByteArrayInputStream(byteArrayOf())
            }, onProgress = {})
        }
    }

    @Test
    fun `existing fresh upload target conflicts before opening source or sending PUT`() {
        server.enqueue(MockResponse().setResponseCode(200).setHeader("ETag", "existing-version"))
        var opened = false

        assertThrows(TransferConflictException::class.java) {
            client.upload(server.url("file.txt").toString(), "Bearer token", null, 9, false, {
                opened = true
                ByteArrayInputStream("different".toByteArray())
            }, onProgress = {})
        }

        assertEquals(false, opened)
        assertEquals(1, server.requestCount)
        assertEquals("HEAD", server.takeRequest().method)
    }

    @Test
    fun `uncertain preflight response fails without opening source or uploading`() {
        for (status in listOf(302, 401, 403, 405, 429, 500)) {
            server.enqueue(MockResponse().setResponseCode(status))
            var opened = false

            val failure =
                assertThrows(TransferHttpException::class.java) {
                    client.upload(server.url("file.txt").toString(), "Bearer token", null, 0, false, {
                        opened = true
                        ByteArrayInputStream(byteArrayOf())
                    }, onProgress = {})
                }

            assertEquals(status, failure.statusCode)
            assertEquals(false, opened)
            assertEquals("HEAD", server.takeRequest().method)
        }
        assertEquals(6, server.requestCount)
    }

    @Test
    fun `create collection issues MKCOL and accepts an existing collection`() {
        server.enqueue(MockResponse().setResponseCode(201))
        server.enqueue(MockResponse().setResponseCode(405))
        server.enqueue(MockResponse().setResponseCode(207).setBody(collectionResponse("<d:collection/>")))

        client.createCollection(server.url("Camera Uploads").toString(), "Bearer token")
        client.createCollection(server.url("Camera Uploads/2026").toString(), "Bearer token")

        val created = server.takeRequest()
        assertEquals("MKCOL", created.method)
        assertEquals("Bearer token", created.getHeader("Authorization"))
        assertEquals("MKCOL", server.takeRequest().method)
        val verification = server.takeRequest()
        assertEquals("PROPFIND", verification.method)
        assertEquals("0", verification.getHeader("Depth"))
        assertEquals("Bearer token", verification.getHeader("Authorization"))
    }

    @Test fun `existing regular file cannot satisfy collection creation`() {
        server.enqueue(MockResponse().setResponseCode(405))
        server.enqueue(MockResponse().setResponseCode(207).setBody(collectionResponse("")))
        val failure =
            org.junit.Assert.assertThrows(OpenCloudException::class.java) {
                client.createCollection(server.url("Camera Uploads/2026").toString(), "Bearer token")
            }
        assertEquals(OpenCloudError.InvalidResponse, failure.error)
        assertEquals(2, server.requestCount)
    }

    private fun collectionResponse(type: String) =
        """
        <d:multistatus xmlns:d="DAV:"><d:response><d:href>/Camera%20Uploads/2026</d:href>
        <d:propstat><d:prop><d:resourcetype>$type</d:resourcetype></d:prop>
        <d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>
        """.trimIndent()
}
