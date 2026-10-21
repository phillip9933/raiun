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

class IncomingSharesClientTest {
    private lateinit var server: MockWebServer
    private val client = IncomingSharesClient(OkHttpClient(), EndpointPolicy(true))

    @Before fun start() {
        server = MockWebServer().also { it.start() }
    }

    @After fun stop() = server.shutdown()

    @Test fun `discovery preserves remote identity mount state and grant recipients without inferring access`() {
        server.enqueue(
            MockResponse().setBody(
                """
                {"value":[{"id":"share","@client.synchronize":true,"remoteItem":{
                "id":"foreign-resource","name":"Shared folder","folder":{},
                "webDavUrl":"${server.url("dav/shared/root")}","parentReference":{"driveId":"foreign-drive"},
                "permissions":[{"id":"grant","roles":["custom-role"],
                "@libre.graph.permissions.actions":["libre.graph/driveItem/upload/create"],
                "grantedToV2":{"group":{"id":"team"}}}]}}]}
                """.trimIndent(),
            ),
        )
        val item = client.list(server.url("/prefix/").toString(), "Bearer token").single()
        assertEquals("foreign-resource", item.remoteItem.id)
        assertEquals("foreign-drive", item.remoteItem.parentReference?.driveId)
        assertEquals(true, item.synchronized)
        assertEquals(
            "team",
            item.remoteItem.permissions
                ?.single()
                ?.grantedToV2
                ?.group
                ?.id,
        )
        assertNull(item.effectiveActions)
        val request = server.takeRequest()
        assertEquals("/prefix/graph/v1beta1/me/drive/sharedWithMe", request.path)
        assertEquals("Bearer token", request.getHeader("Authorization"))
    }

    @Test fun `missing DAV root remains unresolved instead of being synthesized`() {
        server.enqueue(MockResponse().setBody("""{"value":[${item("one")}]}"""))
        val result = list().single()
        assertNull(result.remoteItem.webDavUrl)
        assertNull(result.effectiveActions)
    }

    @Test fun `outer folder facets and share names are accepted without manufacturing remote fields`() {
        server.enqueue(
            MockResponse().setBody(
                """
                {"value":[{"id":"mount","name":"Shared team files","folder":{},
                "@libre.graph.permissions.actions.allowedValues":["libre.graph/driveItem/children/read"],
                "remoteItem":{"id":"remote","permissions":null}}]}
                """.trimIndent(),
            ),
        )
        val result = list().single()
        assertEquals("Shared team files", result.name)
        assertEquals(setOf("libre.graph/driveItem/children/read"), result.effectiveActions)
        assertNull(result.remoteItem.name)
        assertNull(result.remoteItem.webDavUrl)
        assertNull(result.remoteItem.permissions)
    }

    @Test fun `pagination returns the complete inventory and rejects duplicate identities`() {
        server.enqueue(MockResponse().setBody("""{"value":[${item("one")}],"@odata.nextLink":"?page=2"}"""))
        server.enqueue(MockResponse().setBody("""{"value":[${item("two")}]}"""))
        assertEquals(listOf("one", "two"), list().map { it.id })
        server.enqueue(MockResponse().setBody("""{"value":[${item("one")}],"@odata.nextLink":"?page=2"}"""))
        server.enqueue(MockResponse().setBody("""{"value":[${item("one")}]}"""))
        assertThrows(OpenCloudException::class.java) { list() }
    }

    @Test fun `foreign origins and different endpoint pagination never receive credentials`() {
        MockWebServer().use { foreign ->
            foreign.start()
            server.enqueue(MockResponse().setBody("""{"value":[],"@odata.nextLink":"${foreign.url("/steal")}"}"""))
            assertThrows(OpenCloudException::class.java) { list() }
            assertEquals(0, foreign.requestCount)
            server.enqueue(MockResponse().setBody("""{"value":[],"@odata.nextLink":"/other-endpoint"}"""))
            assertThrows(OpenCloudException::class.java) { list() }
            assertEquals(2, server.requestCount)
        }
    }

    @Test fun `untrusted DAV URLs are rejected before they can become destinations`() {
        val remote = item("one").replace("\"folder\":{}", "\"folder\":{},\"webDavUrl\":\"https://foreign.test/dav\"")
        server.enqueue(MockResponse().setBody("""{"value":[$remote]}"""))
        val error = assertThrows(OpenCloudException::class.java) { list() }
        assertEquals(OpenCloudError.Trust, error.error)
    }

    @Test fun `failed later pages and malformed envelopes never return partial snapshots or raw errors`() {
        server.enqueue(MockResponse().setBody("""{"value":[${item("one")}],"@odata.nextLink":"?page=2"}"""))
        server.enqueue(MockResponse().setResponseCode(503).setBody("secret server response"))
        assertThrows(TransferHttpException::class.java) { list() }
        server.enqueue(MockResponse().setBody("{}"))
        assertEquals(OpenCloudError.InvalidResponse, assertThrows(OpenCloudException::class.java) { list() }.error)
        server.enqueue(MockResponse().setBody("not JSON secret"))
        val error = assertThrows(OpenCloudException::class.java) { list() }
        assertEquals(OpenCloudError.InvalidResponse, error.error)
        assertNull(error.cause)
    }

    @Test fun `loops redirects and oversized pages fail without following or retaining response data`() {
        val endpoint = "/graph/v1beta1/me/drive/sharedWithMe"
        server.enqueue(MockResponse().setBody("""{"value":[],"@odata.nextLink":"$endpoint"}"""))
        assertThrows(OpenCloudException::class.java) { list() }
        assertEquals(1, server.requestCount)
        server.enqueue(MockResponse().setResponseCode(302).addHeader("Location", "/other"))
        assertThrows(TransferHttpException::class.java) { list() }
        assertEquals(2, server.requestCount)
        server.enqueue(MockResponse().setBody(" ".repeat(4 * 1024 * 1024 + 1)))
        assertEquals(OpenCloudError.InvalidResponse, assertThrows(OpenCloudException::class.java) { list() }.error)
    }

    @Test fun `rate limits retain retry delay without retaining the response body`() {
        server.enqueue(MockResponse().setResponseCode(429).addHeader("Retry-After", "42").setBody("private details"))
        val error = assertThrows(TransferHttpException::class.java) { list() }
        assertEquals(OpenCloudError.RateLimited(42), error.error)
        assertNull(error.cause)
    }

    private fun list() = client.list(server.url("/").toString(), "Bearer token")

    private fun item(id: String) = """{"id":"$id","remoteItem":{"id":"remote-$id","name":"Folder","folder":{}}}"""
}
