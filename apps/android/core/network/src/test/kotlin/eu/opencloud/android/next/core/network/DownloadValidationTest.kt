package eu.opencloud.android.next.core.network

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class DownloadValidationTest {
    @Test fun `unexpected content coding cannot become cached file bytes`() {
        MockWebServer().use { server ->
            server.start()
            server.enqueue(MockResponse().setBody("hello").setHeader("Content-Encoding", "gzip"))
            assertThrows(OpenCloudException::class.java) {
                TransferClient(OkHttpClient()).download(
                    server.url("file").toString(),
                    "Bearer token",
                    0,
                    DownloadExpectation(5, null),
                ) { _, _, _ -> error("Unexpected encoding reached sink") }
            }
        }
    }

    @Test fun `only a single well formed strong tag can guard a mutation or resume`() {
        listOf("W/\"weak\"", "*", "\"one\", \"two\"", "\"has space\"", "\"bad\r\nheader\"").forEach { tag ->
            assertEquals(null, DownloadExpectation(0, tag).strongETag)
        }
        assertEquals("\"\"", DownloadExpectation(0, "\"\"").strongETag)
        assertEquals("\"opaque-1\"", DownloadExpectation(0, "\"opaque-1\"").strongETag)
    }

    @Test fun `changed version malformed ranges and lengths never reach sink`() {
        MockWebServer().use { server ->
            server.start()
            val responses =
                listOf(
                    MockResponse()
                        .setResponseCode(206)
                        .setBody("world")
                        .setHeader("ETag", "\"v2\"")
                        .setHeader("Content-Range", "bytes 5-9/10"),
                    MockResponse()
                        .setResponseCode(206)
                        .setBody("world")
                        .setHeader("ETag", "\"v1\"")
                        .setHeader("Content-Range", "bytes 4-8/10"),
                    MockResponse()
                        .setResponseCode(206)
                        .setBody("bad")
                        .setHeader("ETag", "\"v1\"")
                        .setHeader("Content-Range", "bytes 5-9/10"),
                )
            responses.forEach { response ->
                server.enqueue(response)
                assertThrows(OpenCloudException::class.java) {
                    TransferClient(OkHttpClient()).download(
                        server.url("file").toString(),
                        "Bearer token",
                        5,
                        DownloadExpectation(10, "\"v1\""),
                    ) { _, _, _ -> error("Invalid response reached sink") }
                }
            }
        }
    }

    @Test fun `range ignored by server restarts rather than appends`() {
        MockWebServer().use { server ->
            server.start()
            server.enqueue(MockResponse().setBody("helloworld").setHeader("ETag", "\"v1\""))
            TransferClient(OkHttpClient()).download(
                server.url("file").toString(),
                "Bearer token",
                5,
                DownloadExpectation(10, "\"v1\""),
            ) { input, _, resumed ->
                assertEquals(false, resumed)
                assertEquals("helloworld", input.bufferedReader().readText())
            }
            assertEquals("\"v1\"", server.takeRequest().getHeader("If-Match"))
        }
    }

    @Test fun `unvalidated partial content is never resumed`() {
        assertThrows(OpenCloudException::class.java) {
            TransferClient(OkHttpClient()).download(
                "https://cloud.example/file",
                "Bearer token",
                1,
                DownloadExpectation(10, "W/\"weak\""),
            ) { _, _, _ -> error("Unexpected sink") }
        }
    }
}
