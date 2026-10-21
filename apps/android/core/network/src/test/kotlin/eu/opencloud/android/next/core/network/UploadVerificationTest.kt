package eu.opencloud.android.next.core.network

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.ByteArrayInputStream
import java.util.concurrent.CancellationException

class UploadVerificationTest {
    private val bytes = "original bytes".toByteArray()

    @Test fun `tus locations remain bound to original origin`() {
        val client = TransferClient(OkHttpClient())
        assertEquals(
            "https://cloud.example/uploads/one",
            client.resolveTusLocation("https://cloud.example/dav/", "/uploads/one"),
        )
        listOf(
            "https://other.example/upload",
            "http://cloud.example/upload",
            "https://cloud.example:444/upload",
            "https://user:secret@cloud.example/upload",
            "/upload#fragment",
        ).forEach { location ->
            val failure =
                assertThrows(OpenCloudException::class.java) {
                    client.resolveTusLocation("https://cloud.example/dav/", location)
                }
            assertEquals(OpenCloudError.Trust, failure.error)
        }
    }

    @Test fun `tus acknowledgements must match the entire submitted chunk`() {
        MockWebServer().use { server ->
            server.start()
            val client = TransferClient(OkHttpClient())
            listOf(-1, 2, 3, 6).forEach { offset ->
                server.enqueue(MockResponse().setResponseCode(204).setHeader("Upload-Offset", offset))
                val failure =
                    assertThrows(OpenCloudException::class.java) {
                        client.patchTus(
                            server.url("upload").toString(),
                            "Bearer token",
                            2,
                            3,
                            { ByteArrayInputStream("abc".toByteArray()) },
                            {},
                        )
                    }
                assertEquals(OpenCloudError.PreconditionFailed, failure.error)
            }
            server.enqueue(MockResponse().setHeader("Upload-Offset", -1))
            assertThrows(OpenCloudException::class.java) {
                client.tusOffset(server.url("upload").toString(), "Bearer token")
            }
        }
    }

    @Test fun `remote content must match original bytes not just status or length`() {
        MockWebServer().use { server ->
            server.start()
            val client = TransferClient(OkHttpClient())
            val fingerprint = ByteArrayInputStream(bytes).use { ContentFingerprint.read(it, bytes.size.toLong()) }
            server.enqueue(MockResponse().setBody(String(bytes)).setHeader("ETag", "opaque-version"))
            assertEquals(
                "opaque-version",
                client.verifyUpload(server.url("file").toString(), "Bearer token", fingerprint),
            )
            val request = server.takeRequest()
            assertEquals("GET", request.method)
            assertEquals("identity", request.getHeader("Accept-Encoding"))
            assertEquals("no-cache", request.getHeader("Cache-Control"))
            listOf("modified bytes", "short", "original bytes EXTRA").forEach { body ->
                server.enqueue(MockResponse().setBody(body))
                val failure =
                    assertThrows(OpenCloudException::class.java) {
                        client.verifyUpload(server.url("file").toString(), "Bearer token", fingerprint)
                    }
                assertEquals(OpenCloudError.PreconditionFailed, failure.error)
            }
        }
    }

    @Test fun `partial response cannot verify upload`() {
        MockWebServer().use { server ->
            server.start()
            server.enqueue(MockResponse().setResponseCode(206).setBody(String(bytes)))
            val fingerprint = ByteArrayInputStream(bytes).use { ContentFingerprint.read(it, bytes.size.toLong()) }
            assertThrows(TransferHttpException::class.java) {
                TransferClient(OkHttpClient()).verifyUpload(server.url("file").toString(), "Bearer token", fingerprint)
            }
        }
    }

    @Test fun `source length mismatch is rejected and cancellation retains identity`() {
        listOf(-1L, 0L, bytes.size.toLong() + 1).forEach { length ->
            assertThrows(OpenCloudException::class.java) {
                ByteArrayInputStream(bytes).use { ContentFingerprint.read(it, length) }
            }
        }
        val cancelled = CancellationException("cancelled")
        val failure =
            assertThrows(CancellationException::class.java) {
                ByteArrayInputStream(bytes).use { ContentFingerprint.read(it, bytes.size.toLong()) { throw cancelled } }
            }
        assertSame(cancelled, failure)
    }
}
