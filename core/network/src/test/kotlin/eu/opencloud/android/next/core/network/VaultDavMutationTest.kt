package eu.opencloud.android.next.core.network

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class VaultDavMutationTest {
    private val server = MockWebServer()

    @Before
    fun startServer() {
        server.start()
    }

    @After
    fun stopServer() {
        server.shutdown()
    }

    @Test
    fun ciphertextCreateUsesCreateOnlyConditionAndBody() {
        val bytes = byteArrayOf(1, 2, 3, 4)
        server.enqueue(MockResponse().setResponseCode(201).setHeader("ETag", "\"new\""))
        val client = VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true))

        val etag =
            client.putCiphertext(
                server.url("dav/files/drive/").toString(),
                "folder/opaque",
                "Bearer test",
                contentLength = bytes.size.toLong(),
                contentType = "application/octet-stream",
            ) { output -> output.write(bytes) }

        val request = server.takeRequest()
        assertEquals("PUT", request.method)
        assertEquals("*", request.getHeader("If-None-Match"))
        assertEquals(null, request.getHeader("If-Match"))
        assertEquals("Bearer test", request.getHeader("Authorization"))
        assertArrayEquals(bytes, request.body.readByteArray())
        assertEquals("\"new\"", etag)
    }

    @Test
    fun ciphertextReplacementRequiresStrongEtag() {
        val client = VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true))
        assertThrows(OpenCloudException::class.java) {
            client.putCiphertext(
                server.url("dav/files/drive/").toString(),
                "opaque",
                "Bearer test",
                contentLength = 0,
                expectedETag = "W/\"weak\"",
            ) { }
        }
        assertEquals(0, server.requestCount)
    }

    @Test
    fun ciphertextCreateRejectsPathTraversalBeforeNetwork() {
        val client = VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true))
        assertThrows(OpenCloudException::class.java) {
            client.putCiphertext(
                server.url("dav/files/drive/").toString(),
                "../outside",
                "Bearer test",
                contentLength = 0,
            ) { }
        }
        assertEquals(0, server.requestCount)
    }

    @Test
    fun copyAndDeleteStayInsideAdvertisedRootAndUsePreconditions() {
        server.enqueue(MockResponse().setResponseCode(201))
        server.enqueue(MockResponse().setResponseCode(204))
        val client = VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true))
        val root = server.url("dav/files/drive/").toString()

        client.moveOrCopy(root, "opaque/source", "opaque/copy", "Bearer test", "\"source\"", copy = true)
        client.deleteResource(root, "opaque/source", "Bearer test", "\"source\"")

        val copy = server.takeRequest()
        assertEquals("COPY", copy.method)
        assertEquals("\"source\"", copy.getHeader("If-Match"))
        assertEquals("F", copy.getHeader("Overwrite"))
        assertEquals("Bearer test", copy.getHeader("Authorization"))
        assertTrue(copy.getHeader("Destination").orEmpty().startsWith(server.url("dav/files/drive/").toString()))
        val delete = server.takeRequest()
        assertEquals("DELETE", delete.method)
        assertEquals("\"source\"", delete.getHeader("If-Match"))
        assertEquals("Bearer test", delete.getHeader("Authorization"))
    }
}
