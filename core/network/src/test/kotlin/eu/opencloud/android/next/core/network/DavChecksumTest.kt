package eu.opencloud.android.next.core.network

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class DavChecksumTest {
    @Test fun `parses combined checksums and ignores weak checksum algorithms`() {
        val result =
            parseDavObject(
                xml("<oc:checksums><oc:checksum>MD5:$MD5 ADLER32:062c0215</oc:checksum></oc:checksums>"),
                URL,
            )
        assertEquals(mapOf("MD5" to MD5), result.checksums)
        assertThrows(OpenCloudException::class.java) {
            parseDavObject(xml("<oc:checksums><oc:checksum>SHA256:bad</oc:checksum></oc:checksums>"), URL)
        }
    }

    @Test fun `destination without checksum uses conditional byte verification`() {
        MockWebServer().use { server ->
            server.start()
            val client = DavOperationClient(OkHttpClient())
            listOf("hello", "other").forEach { body ->
                server.enqueue(MockResponse().setResponseCode(207).setBody(xml("")))
                server.enqueue(MockResponse().setBody(body).setHeader("ETag", "\"v1\""))
                val matches =
                    client.matchesFingerprint(
                        server.url("/file").toString(),
                        "checksum-v1:MD5:5:$MD5",
                        "Bearer test",
                        {},
                    )
                if (body == "hello") assertTrue(matches) else assertFalse(matches)
                assertEquals("PROPFIND", server.takeRequest().method)
                val get = server.takeRequest()
                assertEquals("GET", get.method)
                assertEquals("\"v1\"", get.getHeader("If-Match"))
            }
        }
    }

    @Test fun `download checksum prefers SHA256 and rejects changed metadata`() {
        MockWebServer().use { server ->
            server.start()
            val client = TransferClient(OkHttpClient())
            val url = server.url("/file").toString()
            server.enqueue(
                MockResponse()
                    .setResponseCode(
                        207,
                    ).setBody(xml("<oc:checksums><oc:checksum>MD5:$MD5 SHA256:$SHA256</oc:checksum></oc:checksums>")),
            )
            assertEquals(
                "SHA-256" to SHA256,
                client.downloadChecksum(url, "Bearer test", DownloadExpectation(5, "\"v1\"")),
            )
            assertEquals("PROPFIND", server.takeRequest().method)
            server.enqueue(MockResponse().setResponseCode(207).setBody(xml("")))
            assertThrows(OpenCloudException::class.java) {
                client.downloadChecksum(url, "Bearer test", DownloadExpectation(5, "\"v2\""))
            }
        }
    }

    @Test fun `only unsupported and missing checksums are optional`() {
        MockWebServer().use { server ->
            server.start()
            val client = TransferClient(OkHttpClient())
            val url = server.url("/file").toString()
            server.enqueue(MockResponse().setResponseCode(405))
            assertEquals(null, client.downloadChecksum(url, "Bearer test", DownloadExpectation(5, "\"v1\"")))
            server.enqueue(MockResponse().setResponseCode(207).setBody(xml("")))
            assertEquals(null, client.downloadChecksum(url, "Bearer test", DownloadExpectation(5, "\"v1\"")))
            server.enqueue(MockResponse().setResponseCode(207).setBody(xmlWithChecksumStatus(404)))
            assertEquals(null, client.downloadChecksum(url, "Bearer test", DownloadExpectation(5, "\"v1\"")))
            server.enqueue(MockResponse().setResponseCode(401))
            assertThrows(TransferHttpException::class.java) {
                client.downloadChecksum(url, "Bearer test", DownloadExpectation(5, "\"v1\""))
            }
            server.enqueue(MockResponse().setResponseCode(207).setBody("broken"))
            assertThrows(OpenCloudException::class.java) {
                client.downloadChecksum(url, "Bearer test", DownloadExpectation(5, "\"v1\""))
            }
        }
    }

    @Test fun `checksum property denial and server error fail closed`() {
        MockWebServer().use { server ->
            server.start()
            val client = TransferClient(OkHttpClient())
            val url = server.url("/file").toString()
            for (status in listOf(403, 500)) {
                server.enqueue(MockResponse().setResponseCode(207).setBody(xmlWithChecksumStatus(status)))
                val failure =
                    assertThrows(TransferHttpException::class.java) {
                        client.downloadChecksum(url, "Bearer test", DownloadExpectation(5, "\"v1\""))
                    }
                assertEquals(status, failure.statusCode)
            }
        }
    }

    private fun xmlWithChecksumStatus(status: Int) =
        """<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/file</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>5</d:getcontentlength><d:getetag>"v1"</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat><d:propstat><d:prop><oc:checksums/></d:prop><d:status>HTTP/1.1 $status unavailable</d:status></d:propstat></d:response></d:multistatus>"""

    private fun xml(checksums: String) =
        """
        <d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/file</d:href>
        <d:propstat><d:prop><d:resourcetype/><d:getcontentlength>5</d:getcontentlength><d:getetag>"v1"</d:getetag>
        $checksums</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>
        """.trimIndent()

    private companion object {
        const val MD5 = "5d41402abc4b2a76b9719d911017c592"
        const val SHA256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        const val URL = "https://cloud.example/file"
    }
}
