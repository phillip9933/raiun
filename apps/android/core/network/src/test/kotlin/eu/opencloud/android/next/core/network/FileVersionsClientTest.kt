package eu.opencloud.android.next.core.network

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class FileVersionsClientTest {
    private val server = MockWebServer().apply { start() }
    private val client = FileVersionsClient(OkHttpClient(), EndpointPolicy(allowLoopbackHttp = true))
    private val root get() = server.url("/remote.php/dav/spaces/space").toString()

    @After fun close() = server.shutdown()

    @Test fun `lists only successful version properties and orders newest first`() {
        server.enqueue(
            MockResponse().setResponseCode(207).setBody(
                listing(
                    row("/remote.php/dav/meta/file/v/", collection = true) +
                        row("/remote.php/dav/meta/file/v/old", date = "Wed, 01 Oct 2025 12:00:00 GMT") +
                        row("/remote.php/dav/meta/file/v/new", date = "Thu, 02 Oct 2025 12:00:00 GMT") +
                        row("/remote.php/dav/meta/file/v/denied", status = "403 Forbidden"),
                ),
            ),
        )
        val versions = client.list(root, "file", "Bearer test")
        assertEquals(listOf("new", "old"), versions.map { it.id })
        assertEquals(12L, versions.first().sizeBytes)
        val request = server.takeRequest()
        assertEquals("PROPFIND", request.method)
        assertEquals("1", request.getHeader("Depth"))
        assertEquals("/remote.php/dav/meta/file/v/", request.path)
    }

    @Test fun `OpenCloud metadata parent collection is not a revision`() {
        server.enqueue(
            MockResponse().setResponseCode(207).setBody(
                listing(
                    row("/remote.php/dav/meta/file/", collection = true) +
                        row("/remote.php/dav/meta/file/v/123", date = "Thu, 02 Oct 2025 12:00:00 GMT"),
                ),
            ),
        )
        assertEquals(listOf("123"), client.list(root, "file", "Bearer test").map { it.id })
    }

    @Test fun `restore protects destination rather than applying its etag to source`() {
        server.enqueue(MockResponse().setResponseCode(204))
        val destination = "$root/notes.txt"
        client.restore(root, "file", "old", destination, "\"current\"", "Bearer test")
        val request = server.takeRequest()
        assertEquals("COPY", request.method)
        assertEquals("/remote.php/dav/meta/file/v/old", request.path)
        assertEquals(destination, request.getHeader("Destination"))
        assertEquals("<$destination> ([\"current\"])", request.getHeader("If"))
        assertEquals("T", request.getHeader("Overwrite"))
    }

    @Test fun `conflict is not retried as unconditional restore`() {
        server.enqueue(MockResponse().setResponseCode(412))
        val error =
            assertThrows(TransferHttpException::class.java) {
                client.restore(root, "file", "old", "$root/notes.txt", "\"current\"", "Bearer test")
            }
        assertEquals(412, error.statusCode)
        assertEquals(1, server.requestCount)
    }

    @Test fun `rejects untrusted hrefs and XML entities`() {
        listOf(
            "https://evil.example/remote.php/dav/meta/file/v/old",
            "/remote.php/dav/meta/other/v/old",
            "/remote.php/dav/meta/file/v/a%2Fb",
        ).forEach { href ->
            server.enqueue(MockResponse().setResponseCode(207).setBody(listing(row(href))))
            assertThrows(IllegalArgumentException::class.java) { client.list(root, "file", "Bearer test") }
        }
        server.enqueue(
            MockResponse().setResponseCode(207).setBody("<!DOCTYPE x [<!ENTITY x SYSTEM 'file:///secret'>]><x/>"),
        )
        assertThrows(IllegalArgumentException::class.java) { client.list(root, "file", "Bearer test") }
    }

    @Test fun `redirects never forward credentials`() {
        server.enqueue(MockResponse().setResponseCode(302).setHeader("Location", server.url("/other")))
        assertThrows(TransferHttpException::class.java) { client.list(root, "file", "Bearer test") }
        assertEquals(1, server.requestCount)
    }

    @Test fun `rejects unsafe restoration before any request`() {
        listOf("..", "../other", "bad\\name").forEach {
            assertThrows(IllegalArgumentException::class.java) {
                client.restore(root, "file", it, "$root/notes.txt", "\"current\"", "Bearer test")
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            client.restore(root, "file", "old", "https://evil.example/file", "\"current\"", "Bearer test")
        }
        assertTrue(server.requestCount == 0)
    }

    private fun listing(rows: String) = "<d:multistatus xmlns:d=\"DAV:\">$rows</d:multistatus>"

    private fun row(
        href: String,
        date: String = "Wed, 01 Oct 2025 12:00:00 GMT",
        status: String = "200 OK",
        collection: Boolean = false,
    ) =
        """<d:response><d:href>$href</d:href><d:propstat><d:prop><d:getlastmodified>$date</d:getlastmodified><d:getcontentlength>12</d:getcontentlength><d:resourcetype>${if (collection) "<d:collection/>" else ""}</d:resourcetype></d:prop><d:status>HTTP/1.1 $status</d:status></d:propstat></d:response>"""
}
