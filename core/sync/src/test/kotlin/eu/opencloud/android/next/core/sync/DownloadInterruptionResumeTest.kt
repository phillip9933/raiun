package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.DownloadExpectation
import eu.opencloud.android.next.core.network.TransferClient
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.SocketPolicy
import okio.Buffer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.FileOutputStream
import java.io.IOException
import kotlin.random.Random

class DownloadInterruptionResumeTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun `interrupted large download resumes from durable bytes without repeating or skipping data`() {
        val bytes = Random(0x51A1).nextBytes(4 * 1024 * 1024)
        val partial = temporary.newFile("download.part")
        val validator = temporary.newFile("download.validator")
        val identity = "etag-v1\n${bytes.size}\n/dav/large.bin"
        val expectation = DownloadExpectation(bytes.size.toLong(), "\"v1\"")

        MockWebServer().use { server ->
            server.start()
            server.enqueue(
                MockResponse()
                    .setBody(Buffer().write(bytes))
                    .setHeader("ETag", "\"v1\"")
                    .setSocketPolicy(SocketPolicy.DISCONNECT_DURING_RESPONSE_BODY),
            )
            val client = TransferClient(OkHttpClient())
            val url = server.url("/dav/large.bin").toString()

            assertEquals(0L, prepareDownloadCheckpoint(partial, validator, identity, bytes.size.toLong(), true))
            assertThrows(IOException::class.java) {
                client.download(url, "Bearer synthetic", 0, expectation) { input, _, resumed ->
                    assertEquals(false, resumed)
                    FileOutputStream(partial).use { output ->
                        input.copyTo(output)
                    }
                }
            }

            val offset = prepareDownloadCheckpoint(partial, validator, identity, bytes.size.toLong(), true)
            assertTrue(offset in 1 until bytes.size.toLong())
            server.enqueue(
                MockResponse()
                    .setResponseCode(206)
                    .setBody(Buffer().write(bytes, offset.toInt(), bytes.size - offset.toInt()))
                    .setHeader("ETag", "\"v1\"")
                    .setHeader("Content-Range", "bytes $offset-${bytes.size - 1}/${bytes.size}"),
            )
            // A resumed worker attempt creates a fresh client after the broken connection.
            TransferClient(OkHttpClient()).download(url, "Bearer synthetic", offset, expectation) { input, _, resumed ->
                assertEquals(true, resumed)
                FileOutputStream(partial, true).use { output ->
                    input.copyTo(output)
                    output.fd.sync()
                }
            }

            assertEquals(bytes.size.toLong(), partial.length())
            assertArrayEquals(bytes, partial.readBytes())
            val first = server.takeRequest()
            val second = server.takeRequest()
            assertEquals(null, first.getHeader("Range"))
            assertEquals("bytes=$offset-", second.getHeader("Range"))
            assertEquals("\"v1\"", second.getHeader("If-Match"))
        }
    }
}
