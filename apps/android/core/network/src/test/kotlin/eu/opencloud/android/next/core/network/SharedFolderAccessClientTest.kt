package eu.opencloud.android.next.core.network

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class SharedFolderAccessClientTest {
    private lateinit var server: MockWebServer
    private val client = SharedFolderAccessClient(OkHttpClient(), EndpointPolicy(true))
    private val share =
        IncomingSharedItem(
            "share",
            SharedRemoteItem("item", parentReference = SharedParentReference("drive")),
            effectiveActions = setOf("libre.graph/driveItem/upload/create"),
        )

    @Before fun start() {
        server = MockWebServer().also { it.start() }
    }

    @After fun stop() = server.shutdown()

    @Test fun `fresh effective access overrides cached access and requests the exact remote item`() {
        server.enqueue(MockResponse().setBody(metadata("""["libre.graph/driveItem/children/read"]""")))
        val result = resolve() as SharedFolderResolution.Resolved
        assertEquals(server.url("/dav/shared/").toString(), result.webDavUrl)
        assertTrue(result.access.canBrowse)
        assertFalse(result.access.canUpload)
        assertFalse(result.access.canReadContent)
        val request = server.takeRequest()
        assertEquals("/prefix/graph/v1.0/drives/drive/items/item", request.requestUrl?.encodedPath)
        assertEquals("@libre.graph.permissions.actions.allowedValues", request.requestUrl?.queryParameter("\$select"))
        assertEquals("Bearer token", request.getHeader("Authorization"))
    }

    @Test fun `remote folder access uses item metadata rather than the beta share jail endpoint`() {
        server.dispatcher =
            object : Dispatcher() {
                override fun dispatch(request: RecordedRequest): MockResponse =
                    when (request.requestUrl?.encodedPath) {
                        "/prefix/graph/v1.0/drives/drive/items/item" ->
                            MockResponse().setBody(metadata("""["libre.graph/driveItem/children/read"]"""))
                        else ->
                            MockResponse().setResponseCode(400).setBody(
                                """{"error":{"code":"invalidRequest","message":"id does not belong to a share jail"}}""",
                            )
                    }
            }
        val result = resolve() as SharedFolderResolution.Resolved
        assertTrue(result.access.canBrowse)
        assertFalse(result.access.canUpload)
        assertEquals(1, server.requestCount)
    }

    @Test fun `upload and create permissions remain independent and unknown actions grant nothing`() {
        val access = SharedFolderAccess(setOf("libre.graph/driveItem/upload/create", "unknown"))
        assertTrue(access.canUpload)
        assertFalse(access.canCreateFolder)
        assertFalse(access.canBrowse)
        assertFalse(access.canReadContent)
        assertTrue(SharedFolderAccess(setOf("libre.graph/driveItem/children/create")).canCreateFolder)
        server.enqueue(MockResponse().setBody(metadata("[]")))
        assertFalse((resolve() as SharedFolderResolution.Resolved).access.canBrowse)
    }

    @Test fun `missing identities roots and permissions do not use cached metadata or grants`() {
        assertEquals(
            SharedFolderResolution.Unresolved(SharedFolderMissing.IDENTITY),
            resolve(share.copy(remoteItem = share.remoteItem.copy(parentReference = null))),
        )
        assertEquals(0, server.requestCount)
        server.enqueue(MockResponse().setBody("""{"id":"item","folder":{}}"""))
        assertEquals(SharedFolderResolution.Unresolved(SharedFolderMissing.DAV_ROOT), resolve())
        server.enqueue(MockResponse().setBody(metadata("null")))
        assertEquals(SharedFolderResolution.Unresolved(SharedFolderMissing.EFFECTIVE_ACCESS), resolve())
    }

    @Test fun `revoked missing and deleted folders return unavailable without cached fallback`() {
        for (status in listOf(403, 404, 410)) {
            server.enqueue(MockResponse().setResponseCode(status).setBody("private error"))
            assertEquals(SharedFolderResolution.Unavailable, resolve())
        }
        server.enqueue(MockResponse().setBody("""{"id":"item","deleted":{}}"""))
        assertEquals(SharedFolderResolution.Unavailable, resolve())
        server.enqueue(MockResponse().setBody("""{"id":"item","file":{}}"""))
        assertEquals(SharedFolderResolution.Unresolved(SharedFolderMissing.FOLDER), resolve())
    }

    @Test fun `identity mismatch untrusted root and malformed payload fail safely`() {
        val bodies =
            listOf(
                """{"id":"wrong","folder":{}}""",
                """{"id":"item","parentReference":{"driveId":"other-drive"},"folder":{}}""",
                metadata("[]").replace(server.url("/dav/shared/").toString(), "https://untrusted.example/dav/"),
                "private malformed response",
                "x".repeat(1024 * 1024 + 1),
            )
        bodies.forEach { body ->
            server.enqueue(MockResponse().setBody(body))
            val error = assertThrows(OpenCloudException::class.java) { resolve() }
            assertNull(error.cause)
            assertFalse(error.message.orEmpty().contains("private"))
        }
    }

    @Test fun `redirects and rate limits preserve safe HTTP errors without credential forwarding`() {
        MockWebServer().use { other ->
            other.start()
            server.enqueue(MockResponse().setResponseCode(302).setHeader("Location", other.url("/capture")))
            assertThrows(TransferHttpException::class.java) { resolve() }
            assertEquals(0, other.requestCount)
        }
        server.enqueue(MockResponse().setResponseCode(429).setHeader("Retry-After", "60").setBody("private"))
        val failure = assertThrows(TransferHttpException::class.java) { resolve() }
        assertFalse(failure.message.orEmpty().contains("private"))
        assertEquals(OpenCloudError.RateLimited(60), failure.error)
    }

    @Test fun `metadata diagnostics distinguish parsing and item mismatches without response details`() {
        val cases =
            listOf(
                "private malformed response" to SharedMetadataStage.ITEM_FORMAT,
                """{"id":"private-other-item"}""" to SharedMetadataStage.ITEM_IDENTITY,
            )
        cases.forEach { (body, stage) ->
            server.enqueue(MockResponse().setBody(body))
            val failure = assertThrows(SharedMetadataException::class.java) { resolve() }
            assertEquals(stage, failure.stage)
            assertEquals(OpenCloudError.InvalidResponse, failure.error)
            assertNull(failure.cause)
            assertFalse(failure.toString().contains("private"))
        }
    }

    @Test fun `shared parent reference does not override the verified item identity or effective rights`() {
        server.enqueue(
            MockResponse().setBody(
                metadata("""["libre.graph/driveItem/children/read"]""")
                    .replace("\"folder\":{}", "\"folder\":{},\"parentReference\":{\"driveId\":\"drive!root\"}"),
            ),
        )
        val result = resolve() as SharedFolderResolution.Resolved
        assertEquals("drive", result.driveId)
        assertEquals("item", result.itemId)
        assertTrue(result.access.canBrowse)
        assertFalse(result.access.canUpload)
    }

    @Test fun `missing metadata address uses discovery only after DAV confirms the exact folder`() {
        enqueueAddresslessMetadata()
        server.enqueue(collection("item"))
        val result = resolve(addressedShare()) as SharedFolderResolution.Resolved
        assertEquals(server.url("/dav/shared/").toString(), result.webDavUrl)
        assertTrue(result.access.canBrowse)
        assertFalse(result.access.canUpload)
        server.takeRequest()
        val dav = server.takeRequest()
        assertEquals("PROPFIND", dav.method)
        assertEquals("0", dav.getHeader("Depth"))
        assertEquals("/dav/shared/", dav.path)
    }

    @Test fun `OpenCloud root resource drive reference matches the metadata storage drive reference`() {
        server.enqueue(
            MockResponse().setBody(
                metadata("[]").replace("\"folder\":{}", "\"folder\":{},\"parentReference\":{\"driveId\":\"drive\"}"),
            ),
        )
        val rooted =
            share.copy(
                remoteItem = share.remoteItem.copy(parentReference = SharedParentReference("drive!root")),
            )
        assertEquals("item", (resolve(rooted) as SharedFolderResolution.Resolved).itemId)
    }

    @Test fun `mount supplies missing address but DAV still verifies the exact remote folder`() {
        enqueueAddresslessMetadata()
        server.enqueue(
            MockResponse().setBody(
                """{"value":[{"id":"mount","driveType":"mountpoint","root":{"remoteItem":{
                "id":"item","parentReference":{"driveId":"drive"},"webDavUrl":"${server.url("/dav/shared/")}"}}}]}""",
            ),
        )
        server.enqueue(collection("item"))
        val result = client.resolveWithMounts(server.url("/prefix/").toString(), "Bearer token", share)
        assertTrue((result as SharedFolderResolution.Resolved).access.canBrowse)
        assertEquals(3, server.requestCount)
    }

    @Test fun `OpenCloud mount address without parent reference is verified and usable`() {
        enqueueAddresslessMetadata()
        server.enqueue(
            MockResponse().setBody(
                """{"value":[{"id":"mount","driveType":"mountpoint","root":{"remoteItem":{
                "id":"item","webDavUrl":"${server.url("/dav/shared/")}"}}}]}""",
            ),
        )
        server.enqueue(collection("item"))
        val result = client.resolveWithMounts(server.url("/prefix/").toString(), "Bearer token", share)
        assertEquals(server.url("/dav/shared/").toString(), (result as SharedFolderResolution.Resolved).webDavUrl)
        assertFalse(result.access.canUpload)
    }

    @Test fun `unmounted share uses documented resource address with exact identity verification`() {
        enqueueAddresslessMetadata()
        server.enqueue(MockResponse().setBody("""{"value":[]}"""))
        server.enqueue(collection("item", "/prefix/dav/spaces/item/"))
        val result = client.resolveWithMounts(server.url("/prefix/").toString(), "Bearer token", share)
        assertEquals(
            server.url("/prefix/dav/spaces/item/").toString(),
            (result as SharedFolderResolution.Resolved).webDavUrl,
        )
        assertTrue(result.access.canBrowse)
        server.takeRequest()
        server.takeRequest()
        assertEquals("/prefix/dav/spaces/item/", server.takeRequest().path)
    }

    @Test fun `resource address fallback rejects a different collection identity`() {
        enqueueAddresslessMetadata()
        server.enqueue(MockResponse().setBody("""{"value":[]}"""))
        server.enqueue(collection("replacement", "/prefix/dav/spaces/item/"))
        val failure =
            assertThrows(SharedMetadataException::class.java) {
                client.resolveWithMounts(server.url("/prefix/").toString(), "Bearer token", share)
            }
        assertEquals(SharedMetadataStage.ITEM_IDENTITY, failure.stage)
    }

    @Test fun `equivalent encoded DAV collection addresses keep identity verification`() {
        server.enqueue(collection("item", "/dav/spaces/storage%24space%21folder/"))
        RemoteDiscoveryClient(OkHttpClient()).requireCollectionIdentity(
            server.url("/dav/spaces/storage\$space!folder/").toString(),
            "Bearer token",
            "item",
        )
    }

    @Test fun `stale or untrusted discovery address cannot expose a replacement folder`() {
        enqueueAddresslessMetadata()
        server.enqueue(collection("replacement"))
        assertThrows(SharedMetadataException::class.java) { resolve(addressedShare()) }
        enqueueAddresslessMetadata()
        server.enqueue(MockResponse().setResponseCode(403))
        assertThrows(TransferHttpException::class.java) { resolve(addressedShare()) }
        enqueueAddresslessMetadata()
        val remote = share.remoteItem.copy(webDavUrl = "https://untrusted.example/folder/")
        assertEquals(
            OpenCloudError.Trust,
            assertThrows(OpenCloudException::class.java) { resolve(share.copy(remoteItem = remote)) }.error,
        )
        assertEquals(5, server.requestCount)
    }

    private fun addressedShare() =
        share.copy(remoteItem = share.remoteItem.copy(webDavUrl = server.url("/dav/shared/").toString()))

    private fun enqueueAddresslessMetadata() {
        server.enqueue(
            MockResponse().setBody(
                """{"id":"item","folder":{},"parentReference":{"driveId":"drive!root"},
                "@libre.graph.permissions.actions.allowedValues":["libre.graph/driveItem/children/read"]}""",
            ),
        )
    }

    private fun collection(
        id: String,
        href: String = "/dav/shared/",
    ) = MockResponse().setResponseCode(207).setBody(
        """<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response>
            <d:href>$href</d:href><d:propstat><d:prop><oc:fileid>$id</oc:fileid>
            <d:resourcetype><d:collection/></d:resourcetype></d:prop>
            <d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>""",
    )

    private fun resolve(item: IncomingSharedItem = share) =
        client.resolve(server.url("/prefix/").toString(), "Bearer token", item)

    private fun metadata(actions: String) =
        """
        {"id":"item","folder":{},"webDavUrl":"${server.url("/dav/shared/")}",
        "@libre.graph.permissions.actions.allowedValues":$actions}
        """.trimIndent()
}
