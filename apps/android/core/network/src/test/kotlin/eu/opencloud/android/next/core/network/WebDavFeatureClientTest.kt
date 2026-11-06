package eu.opencloud.android.next.core.network

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okio.Buffer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class WebDavFeatureClientTest {
    private lateinit var server: MockWebServer
    private lateinit var client: WebDavFeatureClient

    @Before fun setUp() {
        server = MockWebServer()
        server.start()
        client = WebDavFeatureClient(OkHttpClient(), TEST_INITIATOR_ID)
    }

    @After fun tearDown() = server.shutdown()

    @Test fun `trash rejects declarations entities NUL malformed and alternate encoded unsafe XML`() {
        val malicious = "<!DOCTYPE x [<!ENTITY secret SYSTEM 'https://secret.example'>]><x>&secret;</x>"
        val bodies =
            listOf(
                malicious.toByteArray() to "UTF-8",
                "<!DOCTYPE x SYSTEM 'https://secret.example'><x/>".toByteArray() to "UTF-8",
                "<!ENTITY secret 'expanded'><x/>".toByteArray() to "UTF-8",
                "<x>\u0000</x>".toByteArray() to "UTF-8",
                "<x>private".toByteArray() to "UTF-8",
                "<x>&unknown;</x>".toByteArray() to "UTF-8",
                ("<?xml version='1.0' encoding='UTF-16'?>" + malicious).toByteArray(Charsets.UTF_16) to "UTF-16",
                ("<?xml version='1.0' encoding='ISO-8859-1'?>" + malicious).toByteArray(Charsets.ISO_8859_1) to
                    "ISO-8859-1",
            )
        bodies.forEach { (bytes, encoding) ->
            server.enqueue(
                MockResponse()
                    .setResponseCode(207)
                    .setHeader("Content-Type", "application/xml; charset=$encoding")
                    .setBody(Buffer().write(bytes)),
            )
            val failure =
                assertThrows(OpenCloudException::class.java) {
                    client.trash(server.url("dav/spaces/storage-id").toString(), "space", "Bearer test")
                }
            assertEquals(OpenCloudError.InvalidResponse, failure.error)
            assertEquals("The server returned incomplete or unexpected metadata.", failure.message)
        }
        assertEquals(bodies.size, server.requestCount)
    }

    @Test fun `trash accepts legal escaped names and alternate response encoding with arbitrary namespace prefix`() {
        val xml =
            trashResponse()
                .replace("report.pdf", "日本語 &amp; café 😀.pdf")
                .replace("d:", "dav:")
                .replace("xmlns:d=", "xmlns:dav=")
        server.enqueue(
            MockResponse()
                .setResponseCode(207)
                .setHeader("Content-Type", "application/xml; charset=UTF-16")
                .setBody(Buffer().write(xml.toByteArray(Charsets.UTF_16))),
        )
        val item = client.trash(server.url("dav/spaces/storage-id").toString(), "space", "Bearer test").single()
        assertEquals("日本語 & café 😀.pdf", item.name)
        assertEquals("/Documents/日本語 & café 😀.pdf", item.originalPath)
    }

    @Test fun `trash retains bounded metadata response bytes`() {
        server.enqueue(
            MockResponse().setResponseCode(207).setBody(" ".repeat(LISTING_METADATA_LIMIT_BYTES.toInt() + 1)),
        )
        val failure =
            assertThrows(OpenCloudException::class.java) {
                client.trash(server.url("dav/spaces/storage-id").toString(), "space", "Bearer test")
            }
        assertEquals(OpenCloudError.InvalidResponse, failure.error)
    }

    @Test fun `trash sizes ignore failed properties and require aggregate size for folders`() {
        val responses =
            listOf(
                "<d:getcontentlength>42</d:getcontentlength><d:resourcetype/>",
                "<d:getcontentlength>0</d:getcontentlength><d:resourcetype><d:collection/></d:resourcetype>",
                "<oc:size>120</oc:size><d:resourcetype><d:collection/></d:resourcetype>",
                "<d:getcontentlength>-1</d:getcontentlength><d:resourcetype/>",
            ).mapIndexed { index, properties ->
                """<d:response><d:href>/dav/spaces/trash-bin/storage-id/$index</d:href><d:propstat><d:prop>$properties</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat><d:propstat><d:prop><oc:size>999</oc:size></d:prop><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat></d:response>"""
            }.joinToString("")
        server.enqueue(
            MockResponse()
                .setResponseCode(
                    207,
                ).setBody(
                    """<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">$responses</d:multistatus>""",
                ),
        )
        assertEquals(
            listOf(
                42L,
                null,
                120L,
                null,
            ),
            client.trash(server.url("dav/spaces/storage-id").toString(), "s", "Bearer test").map {
                it.sizeBytes
            },
        )
    }

    @Test fun `trash list maps original path and deletion date`() {
        server.enqueue(MockResponse().setResponseCode(207).setBody(trashResponse()))
        val resources = client.trash(server.url("dav/spaces/storage-id").toString(), "space", "Basic auth")
        assertEquals(1, resources.size)
        assertEquals("report.pdf", resources.single().name)
        assertEquals("/Documents/report.pdf", resources.single().originalPath)
        val request = server.takeRequest()
        assertEquals("PROPFIND", request.method)
        assertEquals("1", request.getHeader("Depth"))
        assertTrue(request.path.orEmpty().endsWith("/dav/spaces/trash-bin/storage-id"))
    }

    @Test fun `restore and permanent delete use oCIS space trash item endpoint`() {
        server.enqueue(MockResponse().setResponseCode(201))
        server.enqueue(MockResponse().setResponseCode(204))
        val root = server.url("dav/spaces/storage-id").toString()
        client.restore(
            root,
            "trash-id",
            server.url("dav/spaces/storage-id/Documents/report.pdf").toString(),
            "Bearer token",
        )
        client.permanentlyDelete(root, "trash-id", "Bearer token")
        val restore = server.takeRequest()
        val delete = server.takeRequest()
        assertEquals("MOVE", restore.method)
        assertTrue(restore.path.orEmpty().endsWith("/dav/spaces/trash-bin/storage-id/trash-id"))
        assertTrue(restore.getHeader("Destination").orEmpty().endsWith("/Documents/report.pdf"))
        assertOpenCloudWriteHeaders(restore)
        assertEquals("DELETE", delete.method)
        assertTrue(delete.path.orEmpty().endsWith("/dav/spaces/trash-bin/storage-id/trash-id"))
        assertOpenCloudWriteHeaders(delete)
    }

    @Test fun `normal delete uses oCIS space URL and redacts response body`() {
        val gatewayBody = """{"error":"permission denied by storage provider"}"""
        server.enqueue(MockResponse().setResponseCode(403).setBody(gatewayBody))
        val resourceUrl = server.url("dav/spaces/storage-id/Documents/report.pdf").toString()

        val exception =
            assertThrows(TransferHttpException::class.java) {
                client.delete(resourceUrl, "Bearer token", "\"v1\"")
            }

        assertEquals(403, exception.statusCode)
        assertEquals("Access was denied.", exception.message)
        val request = server.takeRequest()
        assertEquals("DELETE", request.method)
        assertTrue(request.path.orEmpty().endsWith("/dav/spaces/storage-id/Documents/report.pdf"))
        assertOpenCloudWriteHeaders(request)
    }

    @Test fun `normal delete accepts successful no-content response`() {
        server.enqueue(MockResponse().setResponseCode(204))
        client.delete(server.url("dav/spaces/storage-id/report.pdf").toString(), "Bearer token", "\"v1\"")
        assertEquals("DELETE", server.takeRequest().method)
    }

    @Test fun `file rename encodes name and prevents stale overwrite`() {
        server.enqueue(MockResponse().setResponseCode(201))
        client.renameFile(server.url("dav/spaces/s/old.txt").toString(), "new + 文.txt", "\"v1\"", "Bearer token")
        val request = server.takeRequest()
        assertEquals("MOVE", request.method)
        assertEquals("F", request.getHeader("Overwrite"))
        assertEquals("\"v1\"", request.getHeader("If-Match"))
        assertTrue(request.getHeader("Destination").orEmpty().endsWith("new%20+%20%E6%96%87.txt"))
        server.enqueue(MockResponse().setResponseCode(412))
        assertThrows(TransferHttpException::class.java) {
            client.renameFile(server.url("dav/spaces/s/old.txt").toString(), "new.txt", "\"v1\"", "Bearer token")
        }
    }

    @Test fun `delete without a strong version is contained before network`() {
        assertThrows(OpenCloudException::class.java) {
            client.delete(server.url("file").toString(), "Bearer token", "W/\"weak\"")
        }
        assertEquals(0, server.requestCount)
    }

    private fun trashResponse() =
        """<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/spaces/trash-bin/storage-id</d:href></d:response><d:response><d:href>/dav/spaces/trash-bin/storage-id/trash-id</d:href><d:propstat><d:prop><oc:trashbin-original-filename>report.pdf</oc:trashbin-original-filename><oc:trashbin-original-location>Documents/report.pdf</oc:trashbin-original-location><oc:trashbin-delete-datetime>2026-09-08T10:15:30Z</oc:trashbin-delete-datetime><d:resourcetype/></d:prop></d:propstat></d:response></d:multistatus>"""

    private fun assertOpenCloudWriteHeaders(request: okhttp3.mockwebserver.RecordedRequest) {
        assertEquals("Bearer token", request.getHeader("Authorization"))
        assertEquals("application/xml; charset=utf-8", request.getHeader("Content-Type"))
        assertEquals(TEST_INITIATOR_ID, request.getHeader("Initiator-ID"))
        assertEquals(null, request.getHeader("OCS-APIREQUEST"))
        assertEquals("XMLHttpRequest", request.getHeader("X-Requested-With"))
        assertTrue(request.getHeader("X-Request-ID").orEmpty().isNotBlank())
    }

    private companion object {
        const val TEST_INITIATOR_ID = "android-client-instance"
    }
}
