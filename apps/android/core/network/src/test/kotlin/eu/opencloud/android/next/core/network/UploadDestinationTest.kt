package eu.opencloud.android.next.core.network

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Test

class UploadDestinationTest {
    @Test fun `new uploads require absence while explicit replacements allow an existing target`() {
        MockWebServer().use { server ->
            val client = TransferClient(OkHttpClient())
            for (overwrite in listOf(false, true)) {
                if (!overwrite) server.enqueue(MockResponse().setResponseCode(404))
                server.enqueue(MockResponse().setResponseCode(201))
                client.upload(
                    server.url("file").toString(),
                    "Bearer fixture",
                    null,
                    5,
                    overwrite,
                    { "hello".byteInputStream() },
                ) {}
                if (!overwrite) assertEquals("HEAD", server.takeRequest().method)
                val request = server.takeRequest()
                assertEquals("PUT", request.method)
                assertEquals(if (overwrite) null else "*", request.getHeader("If-None-Match"))
                assertEquals("hello", request.body.readUtf8())
            }
        }
    }
}
