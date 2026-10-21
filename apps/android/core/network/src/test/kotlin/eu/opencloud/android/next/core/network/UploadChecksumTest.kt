package eu.opencloud.android.next.core.network

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class UploadChecksumTest {
    @Test fun `matching server sha256 avoids downloading the uploaded bytes again`() {
        MockWebServer().use { server ->
            val hash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
            server.enqueue(MockResponse().setResponseCode(207).setBody(properties(hash)))
            val fingerprint = ContentFingerprint.read("hello".byteInputStream(), 5)
            TransferClient(OkHttpClient()).verifyUpload(server.url("file").toString(), "Bearer test", fingerprint, true)
            assertEquals("PROPFIND", server.takeRequest().method)
            assertEquals(1, server.requestCount)
        }
    }

    @Test fun `wrong checksum fails and unavailable checksums retain full verification`() {
        MockWebServer().use { server ->
            val fingerprint = ContentFingerprint.read("hello".byteInputStream(), 5)
            repeat(6) {
                server.enqueue(MockResponse().setResponseCode(207).setBody(properties("0".repeat(64))))
                server.enqueue(MockResponse().setBody("other"))
            }
            val client = TransferClient(OkHttpClient())
            val failure =
                assertThrows(OpenCloudException::class.java) {
                    client.verifyUpload(server.url("file").toString(), "Bearer test", fingerprint, true)
                }
            assertEquals(OpenCloudError.PreconditionFailed, failure.error)
            server.enqueue(MockResponse().setResponseCode(405))
            server.enqueue(MockResponse().setBody("hello"))
            client.verifyUpload(server.url("file").toString(), "Bearer test", fingerprint, true)
            assertEquals(14, server.requestCount)
        }
    }

    @Test fun `postwrite verification waits for destination metadata to become visible`() {
        MockWebServer().use { server ->
            val hash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
            server.enqueue(MockResponse().setResponseCode(404))
            server.enqueue(MockResponse().setResponseCode(404))
            server.enqueue(MockResponse().setResponseCode(207).setBody(properties(hash)))
            val fingerprint = ContentFingerprint.read("hello".byteInputStream(), 5)

            TransferClient(OkHttpClient()).verifyUpload(
                server.url("file").toString(),
                "Bearer test",
                fingerprint,
                useServerChecksum = true,
            )

            assertEquals(3, server.requestCount)
            assertEquals("PROPFIND", server.takeRequest().method)
            assertEquals("GET", server.takeRequest().method)
            assertEquals("PROPFIND", server.takeRequest().method)
        }
    }

    @Test fun `transient metadata failures can still verify readable bytes`() {
        for (status in listOf(404, 425, 500, 503)) {
            MockWebServer().use { server ->
                server.enqueue(MockResponse().setResponseCode(status))
                server.enqueue(MockResponse().setBody("hello").setHeader("ETag", "\"v1\""))
                val fingerprint = ContentFingerprint.read("hello".byteInputStream(), 5)

                assertEquals(
                    "\"v1\"",
                    TransferClient(OkHttpClient()).verifyUpload(
                        server.url("file").toString(),
                        "Bearer test",
                        fingerprint,
                        useServerChecksum = true,
                    ),
                )
                assertEquals("PROPFIND", server.takeRequest().method)
                assertEquals("GET", server.takeRequest().method)
                assertEquals(2, server.requestCount)
            }
        }
    }

    @Test fun `invalid checksum metadata falls back to verifying the complete response bytes`() {
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setResponseCode(207).setBody("not a DAV multistatus"))
            server.enqueue(MockResponse().setBody("hello").setHeader("ETag", "\"v1\""))
            val fingerprint = ContentFingerprint.read("hello".byteInputStream(), 5)

            assertEquals(
                "\"v1\"",
                TransferClient(OkHttpClient()).verifyUpload(
                    server.url("file").toString(),
                    "Bearer test",
                    fingerprint,
                    useServerChecksum = true,
                ),
            )
            assertEquals("PROPFIND", server.takeRequest().method)
            assertEquals("GET", server.takeRequest().method)
        }
    }

    private fun properties(checksum: String) =
        """<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/file</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>5</d:getcontentlength><d:getetag>"v1"</d:getetag><oc:checksums><oc:checksum>SHA256:$checksum</oc:checksum></oc:checksums></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"""
}
