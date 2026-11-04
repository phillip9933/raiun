package eu.opencloud.android.next.core.network

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.SocketPolicy
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class VaultDavStatResourceTest {
    private lateinit var server: MockWebServer
    private lateinit var client: VaultDavClient

    @Before fun setup() {
        server = MockWebServer().also { it.start() }
        client = VaultDavClient(OkHttpClient(), endpoints = EndpointPolicy(true))
    }

    @After fun close() = server.shutdown()

    @Test fun fileStatUsesDepthZeroAndPreservesExactEncodedIdentityAndVersion() {
        val path = "folder/enc+東京"
        val href = "/dav/root/folder/enc%2B%E6%9D%B1%E4%BA%AC"
        enqueue(envelope(response(href, "opaque-id", "enc+東京")))
        val resource = client.statResource(root(), path, "Bearer synthetic")
        assertEquals("opaque-id", resource.id)
        assertEquals(path, resource.relativePath)
        assertEquals("enc+東京", resource.rawName)
        assertEquals(96L, resource.size)
        assertEquals("\"v1\"", resource.strongETag)
        assertEquals(server.url(href).toString(), resource.href)
        assertFalse(resource.isFolder)
        assertFalse(resource.isVaultMarker)
        val request = server.takeRequest()
        assertEquals("PROPFIND", request.method)
        assertEquals("0", request.getHeader("Depth"))
        assertEquals("Bearer synthetic", request.getHeader("Authorization"))
        assertEquals(listOf("dav", "root", "folder", "enc+東京"), request.requestUrl!!.pathSegments)
        assertTrue(request.body.readUtf8().contains("<d:getcontentlength/>"))
    }

    @Test fun collectionStatPreservesCollectionAndExplicitMarkerRatherThanPretendingItIsAFile() {
        enqueue(
            envelope(
                response(
                    "/dav/root/",
                    "root-id",
                    "root",
                    collection = true,
                    extra = "<d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype>",
                ),
            ),
        )
        val resource = client.statResource(root(), "", "Bearer synthetic")
        assertTrue(resource.isFolder)
        assertTrue(resource.isVaultMarker)
        assertEquals("", resource.relativePath)
        assertEquals(0L, resource.size)
    }

    @Test fun weakOrMalformedTagsNeverBecomeStrongVersionProofs() {
        for (etag in listOf("W/\"weak\"", "unquoted", "")) {
            enqueue(envelope(response(etag = etag)))
            assertNull(client.statResource(root(), "file", "Bearer synthetic").strongETag)
        }
    }

    @Test fun missingSelfAndAnyAdditionalResponseAreRejectedIncludingDepthIgnoringServers() {
        val self = response()
        val alternatives =
            listOf(
                "",
                response("/dav/root/other", "other", "other"),
                self + self,
                self + response("/dav/root/file/child", "child", "child"),
                self + response("/dav/root/sibling", "sibling", "sibling"),
                response("/dav/root/file/child", "child", "child") + self,
            )
        alternatives.forEach { assertInvalid(envelope(it)) }
    }

    @Test fun outsideOriginQueryFragmentUserinfoAndEscapingHrefsAreRejected() {
        val hrefs =
            listOf(
                "https://other.example.test/dav/root/file",
                "/dav/root/file?secret=synthetic",
                "/dav/root/file#fragment",
                "http://synthetic@127.0.0.1:${server.port}/dav/root/file",
                "/outside/file",
                "/dav/root/%2Ffile",
                "/dav/root/%2E%2E/file",
            )
        hrefs.forEach { assertInvalid(envelope(response(href = it))) }
    }

    @Test fun requiredPropertiesAndResourceShapeRemainStrict() {
        val valid = response()
        val invalid =
            listOf(
                valid.replace("<oc:fileid>file-id</oc:fileid>", ""),
                valid.replace("<oc:fileid>file-id</oc:fileid>", "<oc:fileid> </oc:fileid>"),
                valid.replace("<oc:name>file</oc:name>", "<oc:name>different</oc:name>"),
                valid.replace("<d:getcontentlength>96</d:getcontentlength>", ""),
                valid.replace(
                    "<d:getcontentlength>96</d:getcontentlength>",
                    "<d:getcontentlength>-1</d:getcontentlength>",
                ),
                valid.replace("<d:resourcetype></d:resourcetype>", ""),
                valid.replace(
                    "<d:resourcetype></d:resourcetype>",
                    "<d:resourcetype><d:collection/><d:collection/></d:resourcetype>",
                ),
                valid.replace("</d:prop>", "<oc:fileid>duplicate</oc:fileid></d:prop>"),
                valid.replace("HTTP/1.1 200 OK", "HTTP/1.1 404 Not Found"),
            )
        invalid.forEach { assertInvalid(envelope(it)) }
    }

    @Test fun validSelfCannotEscapeMalformedTailNestedResponseOrExternalEntityRefusal() {
        assertInvalid(envelope(response()).removeSuffix("</d:multistatus>"))
        assertInvalid(envelope(response() + "<d:response>"))
        assertInvalid(envelope(response().replace("</d:prop>", "<d:response/></d:prop>")))
        assertInvalid(
            "<!DOCTYPE d:multistatus [<!ENTITY outside SYSTEM 'file:///synthetic-not-readable'>]>" +
                envelope(response()),
        )
        assertInvalid("<notdav>" + response() + "</notdav>")
    }

    @Test fun defaultTwoMiBResponseBudgetCountsForeignTailAfterValidSelf() {
        val extension = "<x:extra xmlns:x='urn:synthetic'>" + "a".repeat(2 * 1024 * 1024) + "</x:extra>"
        enqueue(envelope(response() + extension))
        val failure =
            assertThrows(OpenCloudException::class.java) {
                client.statResource(root(), "file", "Bearer synthetic")
            }
        assertEquals(OpenCloudError.DirectoryListingTooLarge, failure.error)
    }

    @Test fun configuredSmallerBudgetIsAlsoAppliedBeforeReturningAnyDescriptor() {
        val bounded = VaultDavClient(OkHttpClient(), maxXmlBytes = 128, endpoints = EndpointPolicy(true))
        enqueue(envelope(response()))
        val failure =
            assertThrows(OpenCloudException::class.java) {
                bounded.statResource(root(), "file", "Bearer synthetic")
            }
        assertEquals(OpenCloudError.DirectoryListingTooLarge, failure.error)
    }

    @Test fun httpErrorsRemainTypedAndNeverFallBackOrFollowRedirects() {
        for (status in listOf(301, 307, 403, 404, 405, 501)) {
            server.enqueue(MockResponse().setResponseCode(status).setHeader("Location", server.url("/other")))
            val before = server.requestCount
            val failure =
                assertThrows(OpenCloudException::class.java) {
                    client.statResource(root(), "file", "Bearer synthetic")
                }
            assertEquals(httpError(status), failure.error)
            assertEquals(before + 1, server.requestCount)
        }
    }

    @Test fun unsafeRequestPathAuthorizationAndCleartextPolicyFailBeforeAnyRequest() {
        for (path in listOf("/file", "../file", "folder/../file", "folder\\file", "file/", "file\u0001")) {
            assertThrows(OpenCloudException::class.java) { client.statResource(root(), path, "Bearer synthetic") }
        }
        assertThrows(OpenCloudException::class.java) { client.statResource(root(), "file", "Bearer\nsynthetic") }
        assertThrows(OpenCloudException::class.java) {
            VaultDavClient(OkHttpClient()).statResource(root(), "file", "Bearer synthetic")
        }
        assertEquals(0, server.requestCount)
    }

    @Test fun cancellingOneOwnedDavClientInterruptsItsCallWithoutCancellingAnotherClient() {
        val shared = OkHttpClient()
        val firstClient = VaultDavClient(shared, endpoints = EndpointPolicy(true))
        val other = VaultDavClient(shared, endpoints = EndpointPolicy(true))
        val executor = Executors.newFixedThreadPool(2)
        server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE))
        server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.NO_RESPONSE))
        try {
            val first = executor.submit<VaultDavEntry> { firstClient.statResource(root(), "file", "Bearer synthetic") }
            assertNotNull(server.takeRequest(5, TimeUnit.SECONDS))
            val second = executor.submit<VaultDavEntry> { other.statResource(root(), "other", "Bearer synthetic") }
            assertNotNull(server.takeRequest(5, TimeUnit.SECONDS))
            firstClient.cancelRequests()
            val failure = assertThrows(ExecutionException::class.java) { first.get(5, TimeUnit.SECONDS) }
            assertTrue(failure.cause is OpenCloudException)
            assertFalse(second.isDone)
            other.cancelRequests()
            assertThrows(ExecutionException::class.java) { second.get(5, TimeUnit.SECONDS) }
        } finally {
            firstClient.cancelRequests()
            other.cancelRequests()
            executor.shutdownNow()
        }
    }

    private fun root() = server.url("/dav/root/").toString()

    private fun enqueue(body: String) = server.enqueue(MockResponse().setResponseCode(207).setBody(body))

    private fun assertInvalid(body: String) {
        enqueue(body)
        val failure =
            assertThrows(OpenCloudException::class.java) {
                client.statResource(root(), "file", "Bearer synthetic")
            }
        assertEquals(OpenCloudError.InvalidResponse, failure.error)
    }

    private fun envelope(body: String) =
        "<d:multistatus xmlns:d='DAV:' xmlns:oc='http://owncloud.org/ns'>$body</d:multistatus>"

    @Suppress("LongParameterList")
    private fun response(
        href: String = "/dav/root/file",
        id: String = "file-id",
        name: String = "file",
        collection: Boolean = false,
        size: Long = if (collection) 0 else 96,
        etag: String = "\"v1\"",
        extra: String = "",
    ): String =
        """<d:response><d:href>$href</d:href><d:propstat><d:prop>
        <d:resourcetype>${if (collection) "<d:collection/>" else ""}</d:resourcetype>
        <d:getcontentlength>$size</d:getcontentlength><d:getetag>$etag</d:getetag>
        <oc:fileid>$id</oc:fileid><oc:name>$name</oc:name>$extra
        </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"""
}
