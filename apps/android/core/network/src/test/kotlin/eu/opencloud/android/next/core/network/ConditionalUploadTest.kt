package eu.opencloud.android.next.core.network

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class ConditionalUploadTest {
    @Test fun `editing checks the original version and reports conflicts without overwriting`() {
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setResponseCode(412))
            val client = TransferClient(OkHttpClient())
            assertThrows(TransferConflictException::class.java) {
                client.upload(
                    server.url("file.txt").toString(),
                    "Bearer test",
                    "text/plain",
                    5,
                    false,
                    { "hello".byteInputStream() },
                    expectedETag = "\"original\"",
                ) {}
            }
            val request = server.takeRequest()
            assertEquals("\"original\"", request.getHeader("If-Match"))
            assertNull(request.getHeader("If-None-Match"))
            assertEquals("hello", request.body.readUtf8())
        }
    }

    @Test fun `weak version cannot authorize a conditional edit`() {
        MockWebServer().use { server ->
            assertThrows(OpenCloudException::class.java) {
                TransferClient(OkHttpClient()).upload(
                    server.url("file").toString(),
                    "Bearer test",
                    null,
                    0,
                    false,
                    { "".byteInputStream() },
                    expectedETag = "W/\"version\"",
                ) {}
            }
            assertEquals(0, server.requestCount)
        }
    }
}
