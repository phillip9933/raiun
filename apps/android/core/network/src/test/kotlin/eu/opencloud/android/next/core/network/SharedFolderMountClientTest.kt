package eu.opencloud.android.next.core.network

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test

class SharedFolderMountClientTest {
    private lateinit var server: MockWebServer
    private val policy = EndpointPolicy(true)
    private val client = SharedFolderMountClient(OkHttpClient(), policy)

    @Before fun start() {
        server = MockWebServer().also { it.start() }
    }

    @After fun stop() = server.shutdown()

    @Test fun `exact remote identity on a later page resolves without using mount drive ID`() {
        page(mount("one", "other", "wrong"), "?page=2")
        page(mount("mount-drive", "item", "remote-drive"))
        assertEquals("remote-drive", resolve())
        val first = server.takeRequest()
        assertEquals("/prefix/graph/v1beta1/me/drives", first.requestUrl?.encodedPath)
        assertEquals("driveType eq mountpoint", first.requestUrl?.queryParameter("\$filter"))
        assertEquals("Bearer token", first.getHeader("Authorization"))
        assertEquals("/prefix/graph/v1beta1/me/drives?page=2", server.takeRequest().path)
    }

    @Test fun `ambiguous incomplete deleted and non-mount matches do not invent a drive ID`() {
        page(mount("one", "item", "a") + "," + mount("two", "item", "b"))
        assertNull(resolve())
        page("""{"id":"mount-drive","driveType":"mountpoint","root":{"remoteItem":{"id":"item"}}}""")
        assertNull(resolve())
        page(mount("one", "item", "a").replace("\"root\":{", "\"root\":{\"deleted\":{},"))
        assertNull(resolve())
        page(mount("one", "item", "a").replace("mountpoint", "project"))
        assertNull(resolve())
    }

    @Test fun `a later failed page cannot return an earlier matching mount`() {
        page(mount("one", "item", "a"), "?page=2")
        server.enqueue(MockResponse().setResponseCode(429).setHeader("Retry-After", "30").setBody("private"))
        val failure = assertThrows(TransferHttpException::class.java) { resolve() }
        assertEquals(OpenCloudError.RateLimited(30), failure.error)
        assertNull(failure.cause)
    }

    @Test fun `foreign pages redirects duplicates loops and malformed or oversized bodies fail closed`() {
        MockWebServer().use { other ->
            other.start()
            page(mount("one", "item", "a"), other.url("/capture").toString())
            assertEquals(OpenCloudError.Trust, assertThrows(OpenCloudException::class.java) { resolve() }.error)
            server.enqueue(MockResponse().setResponseCode(302).setHeader("Location", other.url("/capture")))
            assertThrows(TransferHttpException::class.java) { resolve() }
            assertEquals(0, other.requestCount)
        }
        page(mount("same", "item", "a") + "," + mount("same", "item", "a"))
        assertThrows(OpenCloudException::class.java) { resolve() }
        page("", "?page=2")
        page("", "?page=2")
        assertThrows(OpenCloudException::class.java) { resolve() }
        for (body in listOf("private malformed data", "x".repeat(1024 * 1024 + 1))) {
            server.enqueue(MockResponse().setBody(body))
            val failure = assertThrows(OpenCloudException::class.java) { resolve() }
            assertEquals(OpenCloudError.InvalidResponse, failure.error)
            assertNull(failure.cause)
        }
    }

    @Test fun `mount resolution is followed by fresh root and access verification`() {
        page(mount("mount-drive", "item", "remote-drive"))
        server.enqueue(
            MockResponse().setBody(
                """
                {"id":"item","folder":{},"webDavUrl":"${server.url("/authoritative/")}",
                "@libre.graph.permissions.actions.allowedValues":["libre.graph/driveItem/children/read"]}
                """.trimIndent(),
            ),
        )
        val result =
            SharedFolderAccessClient(OkHttpClient(), policy).resolveWithMounts(
                server.url("/prefix/").toString(),
                "Bearer token",
                IncomingSharedItem("share", SharedRemoteItem("item")),
            ) as SharedFolderResolution.Resolved
        assertEquals("remote-drive", result.driveId)
        assertEquals(server.url("/authoritative/").toString(), result.webDavUrl)
        server.takeRequest()
        assertEquals(
            "/prefix/graph/v1.0/drives/remote-drive/items/item",
            server.takeRequest().requestUrl?.encodedPath,
        )
    }

    @Test fun `known remote drive identity skips mount discovery`() {
        server.enqueue(MockResponse().setResponseCode(403))
        val result =
            SharedFolderAccessClient(OkHttpClient(), policy).resolveWithMounts(
                server.url("/prefix/").toString(),
                "Bearer token",
                IncomingSharedItem("share", SharedRemoteItem("item", parentReference = SharedParentReference("drive"))),
            )
        assertEquals(SharedFolderResolution.Unavailable, result)
        assertEquals(1, server.requestCount)
        assertEquals("/prefix/graph/v1.0/drives/drive/items/item", server.takeRequest().requestUrl?.encodedPath)
    }

    private fun resolve() = client.remoteDriveId(server.url("/prefix/").toString(), "Bearer token", "item")

    private fun page(
        items: String,
        next: String? = null,
    ) {
        val link = next?.let { ",\"@odata.nextLink\":\"$it\"" }.orEmpty()
        server.enqueue(MockResponse().setBody("""{"value":[$items]$link}"""))
    }

    private fun mount(
        id: String,
        item: String,
        drive: String,
    ) = """
        {"id":"$id","driveType":"mountpoint","root":{"remoteItem":{
        "id":"$item","parentReference":{"driveId":"$drive"}}}}
        """.trimIndent()
}
