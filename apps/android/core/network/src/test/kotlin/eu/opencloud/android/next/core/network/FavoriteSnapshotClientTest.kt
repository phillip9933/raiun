package eu.opencloud.android.next.core.network

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class FavoriteSnapshotClientTest {
    private lateinit var server: MockWebServer
    private val client = FavoriteSnapshotClient(OkHttpClient())

    @Before fun setUp() {
        server = MockWebServer().also { it.start() }
    }

    @After fun tearDown() = server.shutdown()

    @Test fun `complete favorites search uses authoritative roots and preserves literal plus`() {
        server.enqueue(reply(item("/custom/s/a+b", "id"), 1))
        assertEquals(mapOf("space" to setOf("id")), read())
        val request = server.takeRequest()
        assertEquals("REPORT", request.method)
        assertTrue(request.body.readUtf8().contains("<oc:pattern>is:favorite</oc:pattern>"))
        server.enqueue(reply("", 0))
        assertEquals(mapOf("space" to emptySet<String>()), read())
    }

    @Test fun `partial malformed and untrusted responses cannot prove favorite absence`() {
        val valid = item("/custom/s/file", "id")
        val responses =
            listOf(
                reply(valid, 2),
                reply(valid, 1).removeHeader("Content-Range"),
                reply(valid, 1).setHeader("Content-Range", "invalid/1"),
                reply(valid + valid, 2),
                reply(item("https://other.invalid/custom/s/file", "id"), 1),
                reply(item("/custom/sibling/file", "id"), 1),
                reply(item("/custom/s/file", "id").replace("200 OK", "403 Forbidden"), 1),
                reply("", 0).setBody("<html/>"),
                reply("", 0).setBody("<!DOCTYPE x [<!ENTITY secret SYSTEM 'file:///private'>]><x>&secret;</x>"),
            )
        responses.forEach { response ->
            server.enqueue(response)
            assertThrows(OpenCloudException::class.java) { read() }
        }
    }

    @Test fun `redirects are not followed`() {
        server.enqueue(MockResponse().setResponseCode(302).addHeader("Location", server.url("/elsewhere")))
        assertThrows(TransferHttpException::class.java) { read() }
        assertEquals(1, server.requestCount)
    }

    @Test fun `OpenCloud empty search can omit content range`() {
        server.enqueue(reply("", 0).removeHeader("Content-Range"))
        assertEquals(mapOf("space" to emptySet<String>()), read())
    }

    @Test fun `search legacy DAV prefix maps only to the same authoritative space`() {
        server.enqueue(reply(item("/remote.php/dav/spaces/s/Docs/a.jpg", "id"), 1))
        assertEquals(
            mapOf("space" to mapOf("id" to "/Docs/a.jpg")),
            client.locations(
                server.url("/remote.php/dav/files/user").toString(),
                "Bearer token",
                mapOf("space" to server.url("/dav/spaces/s").toString()),
            ),
        )
        server.enqueue(reply(item("/remote.php/dav/spaces/other/file", "id"), 1))
        assertThrows(OpenCloudException::class.java) {
            client.locations(
                server.url("/search").toString(),
                "Bearer token",
                mapOf("space" to server.url("/dav/spaces/s").toString()),
            )
        }
    }

    @Test fun `locations preserve decoded names and reject encoded separators`() {
        server.enqueue(reply(item("/custom/s/Docs/A%2BB", "id"), 1))
        assertEquals(
            mapOf("space" to mapOf("id" to "/Docs/A+B")),
            client.locations(
                server.url("/search").toString(),
                "Bearer token",
                mapOf(
                    "space" to server.url("/custom/s").toString(),
                ),
            ),
        )
        server.enqueue(reply(item("/custom/s/Docs/A%2FB", "id"), 1))
        assertThrows(OpenCloudException::class.java) { read() }
    }

    private fun read() =
        client.snapshot(
            server.url("/search").toString(),
            "Bearer token",
            mapOf(
                "space" to server.url("/custom/s").toString(),
            ),
        )

    private fun reply(
        body: String,
        count: Int,
    ) = MockResponse()
        .setResponseCode(207)
        .addHeader("Content-Range", "items 0-${(count - 1).coerceAtLeast(0)}/$count")
        .setBody("""<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">$body</d:multistatus>""")

    private fun item(
        path: String,
        id: String,
    ) =
        """<d:response><d:href>$path</d:href><d:propstat><d:prop><oc:fileid>$id</oc:fileid></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"""
}
