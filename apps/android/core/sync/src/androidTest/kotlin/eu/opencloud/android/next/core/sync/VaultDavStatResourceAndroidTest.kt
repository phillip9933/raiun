package eu.opencloud.android.next.core.sync

import androidx.test.ext.junit.runners.AndroidJUnit4
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.VaultDavClient
import eu.opencloud.android.next.core.network.VaultDavEntry
import okhttp3.OkHttpClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.InputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/** Uses the existing sync instrumentation runner and test-only loopback policy; no new test dependencies. */
@RunWith(AndroidJUnit4::class)
class VaultDavStatResourceAndroidTest {
    @Test fun actualAndroidXmlPreservesSingleFileAndCollectionTypesWithDepthZero() {
        StatFixture(listOf(envelope(response()), envelope(response(collection = true)))).use { fixture ->
            val client = VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true))
            val file = client.statResource(fixture.root, "file", "Bearer synthetic")
            assertFalse(file.isFolder)
            assertEquals("file-id", file.id)
            assertEquals(96L, file.size)
            assertEquals("\"v1\"", file.strongETag)
            val fileRequest = fixture.request()
            assertEquals("PROPFIND", fileRequest.method)
            assertEquals("/dav/root/file", fileRequest.path)
            assertEquals("0", fileRequest.depth)
            val collection = client.statResource(fixture.root, "", "Bearer synthetic")
            assertTrue(collection.isFolder)
            assertEquals("", collection.relativePath)
            assertEquals(0L, collection.size)
            assertEquals("0", fixture.request().depth)
        }
    }

    @Test fun validSelfCannotEscapeAndroidTailExtraResourceOrTwoMiBValidation() {
        val huge = "<x:extra xmlns:x='urn:synthetic'>" + "a".repeat(2 * 1024 * 1024) + "</x:extra>"
        val bodies =
            listOf(
                envelope(response()).removeSuffix("</d:multistatus>"),
                envelope(response() + response()),
                envelope(response() + huge),
            )
        StatFixture(bodies).use { fixture ->
            val client = VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true))
            for (expected in listOf(
                OpenCloudError.InvalidResponse,
                OpenCloudError.InvalidResponse,
                OpenCloudError.DirectoryListingTooLarge,
            )) {
                val failure =
                    assertThrows(OpenCloudException::class.java) {
                        client.statResource(fixture.root, "file", "Bearer synthetic")
                    }
                assertEquals(expected, failure.error)
                assertEquals("0", fixture.request().depth)
            }
        }
    }

    @Test fun cancellingOwnedDavCallDoesNotCancelAnotherClientSharingItsHttpBase() {
        StatFixture(emptyList(), stall = true).use { fixture ->
            val shared = OkHttpClient()
            val first = VaultDavClient(shared, endpoints = EndpointPolicy(true))
            val other = VaultDavClient(shared, endpoints = EndpointPolicy(true))
            val executor = Executors.newFixedThreadPool(2)
            try {
                val pending =
                    executor.submit<VaultDavEntry> {
                        first.statResource(
                            fixture.root,
                            "file",
                            "Bearer synthetic",
                        )
                    }
                assertEquals("0", fixture.request().depth)
                val unrelated =
                    executor.submit<VaultDavEntry> {
                        other.statResource(
                            fixture.root,
                            "other",
                            "Bearer synthetic",
                        )
                    }
                assertEquals("0", fixture.request().depth)
                first.cancelRequests()
                val failed = assertThrows(ExecutionException::class.java) { pending.get(5, TimeUnit.SECONDS) }
                assertTrue(failed.cause is OpenCloudException)
                assertFalse(unrelated.isDone)
                other.cancelRequests()
                assertThrows(ExecutionException::class.java) { unrelated.get(5, TimeUnit.SECONDS) }
            } finally {
                first.cancelRequests()
                other.cancelRequests()
                executor.shutdownNow()
            }
        }
    }

    private data class Request(
        val method: String,
        val path: String,
        val depth: String?,
    )

    private class StatFixture(
        bodies: List<String>,
        private val stall: Boolean = false,
    ) : AutoCloseable {
        private val listener = ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"))
        private val responses = ConcurrentLinkedQueue(bodies)
        private val requests = LinkedBlockingQueue<Request>()
        private val sockets = ConcurrentHashMap.newKeySet<Socket>()
        private val release = CountDownLatch(1)
        val root = "http://127.0.0.1:${listener.localPort}/dav/root/"
        private val acceptor =
            Thread {
                while (!listener.isClosed) {
                    val socket =
                        try {
                            listener.accept()
                        } catch (_: java.io.IOException) {
                            break
                        }
                    sockets.add(socket)
                    Thread {
                        try {
                            handle(socket)
                        } catch (_: java.io.IOException) {
                            // The client deliberately closes oversized/cancelled responses.
                        } finally {
                            sockets.remove(socket)
                            socket.close()
                        }
                    }.apply {
                        isDaemon = true
                        start()
                    }
                }
            }.apply {
                isDaemon = true
                start()
            }

        fun request(): Request {
            val request = requests.poll(5, TimeUnit.SECONDS)
            assertNotNull(request)
            return requireNotNull(request)
        }

        private fun handle(socket: Socket) {
            socket.soTimeout = 5_000
            val input = socket.getInputStream()
            val first = line(input).split(' ')
            val headers = mutableMapOf<String, String>()
            while (true) {
                val header = line(input)
                if (header.isEmpty()) break
                headers[header.substringBefore(':').lowercase()] = header.substringAfter(':').trim()
            }
            val length = headers["content-length"]?.toInt() ?: 0
            require(length in 0..32_768)
            repeat(length) { if (input.read() < 0) throw EOFException() }
            requests.add(Request(first[0], first[1], headers["depth"]))
            if (stall) {
                release.await(10, TimeUnit.SECONDS)
            } else {
                val body = requireNotNull(responses.poll()).toByteArray(Charsets.UTF_8)
                val output = socket.getOutputStream()
                output.write(
                    (
                        "HTTP/1.1 207 Multi-Status\r\nContent-Type: application/xml; charset=utf-8\r\n" +
                            "Content-Length: ${body.size}\r\nConnection: close\r\n\r\n"
                    ).toByteArray(Charsets.US_ASCII),
                )
                output.write(body)
                output.flush()
            }
        }

        override fun close() {
            listener.close()
            release.countDown()
            sockets.forEach { it.close() }
            acceptor.join(2_000)
        }

        private fun line(input: InputStream): String {
            val bytes = ByteArrayOutputStream()
            while (bytes.size() < 4096) {
                val next = input.read()
                if (next < 0) throw EOFException()
                if (next == 10) return bytes.toString("US-ASCII").trimEnd('\r')
                bytes.write(next)
            }
            throw java.io.IOException("Synthetic header too long")
        }
    }

    private fun envelope(body: String) =
        "<d:multistatus xmlns:d='DAV:' xmlns:oc='http://owncloud.org/ns'>$body</d:multistatus>"

    private fun response(collection: Boolean = false): String {
        val path = if (collection) "/dav/root/" else "/dav/root/file"
        val name = if (collection) "root" else "file"
        val type = if (collection) "<d:collection/>" else ""
        val size = if (collection) 0 else 96
        return """<d:response><d:href>$path</d:href><d:propstat><d:prop>
            <d:resourcetype>$type</d:resourcetype><d:getcontentlength>$size</d:getcontentlength>
            <d:getetag>"v1"</d:getetag><oc:fileid>file-id</oc:fileid><oc:name>$name</oc:name>
            </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"""
    }
}
