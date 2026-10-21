package eu.opencloud.android.next.core.network

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

class RemoteDiscoveryClientTest {
    @Test fun `visible and excluded aliases cannot claim the same cleanup identity`() {
        val collection = response("/dav/", "200 OK", "<d:resourcetype><d:collection/></d:resourcetype>")
        listOf(
            """<oc:name xmlns:oc="http://owncloud.org/ns">same</oc:name>""",
            """<oc:id xmlns:oc="http://owncloud.org/ns">same-id</oc:id>""",
        ).forEach { property ->
            val vault =
                response(
                    "/dav/secret",
                    "200 OK",
                    property + "<d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype>",
                )
            val ordinary = response("/dav/ordinary", "200 OK", property)
            server.enqueue(MockResponse().setResponseCode(207).setBody(envelope(collection + vault + ordinary)))
            val failure =
                org.junit.Assert.assertThrows(OpenCloudException::class.java) {
                    client.folderSnapshot(server.url("dav/").toString(), "/", "Bearer test")
                }
            assertEquals(OpenCloudError.InvalidResponse, failure.error)
        }
    }

    @Test fun `snapshot retains validated vault paths separately from ordinary files`() {
        val collection = response("/dav/", "200 OK", "<d:resourcetype><d:collection/></d:resourcetype>")
        val vault = response("/dav/secret", "200 OK", "<v:integrity-id xmlns:v=\"ocrclone\">key</v:integrity-id>")
        val suffix = response("/dav/Other.vault", "200 OK", "")
        val visible = response("/dav/ordinary.txt", "200 OK", "")
        server.enqueue(MockResponse().setResponseCode(207).setBody(envelope(collection + vault + suffix + visible)))
        val snapshot = client.folderSnapshot(server.url("dav/").toString(), "/", "Bearer test")
        assertEquals(setOf("/secret", "/Other.vault"), snapshot.excludedVaultPaths)
        assertEquals(listOf("ordinary.txt"), snapshot.resources.map { it.name })
    }

    @Test fun `malformed vault names cannot become cleanup paths`() {
        val collection = response("/dav/", "200 OK", "<d:resourcetype><d:collection/></d:resourcetype>")
        val vault =
            response("/dav/secret", "200 OK", """<oc:name xmlns:oc="http://owncloud.org/ns">../Other.vault</oc:name>""")
        server.enqueue(MockResponse().setResponseCode(207).setBody(envelope(collection + vault)))
        org.junit.Assert.assertThrows(OpenCloudException::class.java) {
            client.folderSnapshot(server.url("dav/").toString(), "/", "Bearer test")
        }
    }

    @Test fun `direct vault paths and descendants are rejected before requesting bytes`() {
        listOf("/Secret.vault", "/Secret.VAULT/child").forEach { path ->
            val failure =
                org.junit.Assert.assertThrows(OpenCloudException::class.java) {
                    client.folder(server.url("dav/").toString(), path, "Bearer test")
                }
            assertEquals(OpenCloudError.Unsupported, failure.error)
        }
        org.junit.Assert.assertThrows(OpenCloudException::class.java) {
            client.folder(server.url("dav/Secret%2Evault").toString(), "/", "Bearer test")
        }
        assertEquals(0, server.requestCount)
    }

    @Test fun `collection metadata prevents cached direct navigation into a newly encrypted folder`() {
        listOf(
            "<v:integrity-id xmlns:v=\"ocrclone\">key</v:integrity-id>",
            "<d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype>",
        ).forEach { marker ->
            val collection =
                response("/dav/folder/", "200 OK", "<d:resourcetype><d:collection/></d:resourcetype>$marker")
            val child = response("/dav/folder/ciphertext", "200 OK", "<d:getcontentlength>12</d:getcontentlength>")
            server.enqueue(MockResponse().setResponseCode(207).setBody(envelope(collection + child)))
            val failure =
                org.junit.Assert.assertThrows(OpenCloudException::class.java) {
                    client.folder(server.url("dav/").toString(), "/folder", "Bearer test")
                }
            assertEquals(OpenCloudError.Unsupported, failure.error)
        }
    }

    @Test fun `shared snapshot reports encrypted requested collections with relative self href`() {
        listOf("/" to "./", "/nested" to "nested").forEach { (path, href) ->
            val collection =
                response(
                    href,
                    "200 OK",
                    "<d:resourcetype><d:collection/></d:resourcetype>" +
                        "<d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype>",
                )
            val childHref = if (path == "/") "child" else "nested/child"
            val child = response(childHref, "200 OK", "<d:getcontentlength>9</d:getcontentlength>")
            server.enqueue(MockResponse().setResponseCode(207).setBody(envelope(collection + child)))
            val snapshot = client.sharedFolderSnapshot(server.url("dav/").toString(), path, "Bearer test")
            assertEquals(emptyList<RemoteResource>(), snapshot.resources)
            assertEquals(setOf(path), snapshot.excludedVaultPaths)
            assertEquals(false, snapshot.plainCollectionConfirmed)
        }
    }

    @Test fun `shared snapshot confirms plain root only from successful explicit marker properties`() {
        val collection =
            response(
                "./",
                "200 OK",
                "<d:resourcetype><d:collection/></d:resourcetype>" +
                    "<d:getcontenttype>httpd/unix-directory</d:getcontenttype>" +
                    "<v:integrity-id xmlns:v=\"ocrclone\"></v:integrity-id>",
            )
        server.enqueue(MockResponse().setResponseCode(207).setBody(envelope(collection)))
        val snapshot = client.sharedFolderSnapshot(server.url("dav/").toString(), "/", "Bearer test")
        assertEquals(true, snapshot.plainCollectionConfirmed)
        assertEquals(emptySet<String>(), snapshot.excludedVaultPaths)

        val unmarkedCollection = response("./", "200 OK", "<d:resourcetype><d:collection/></d:resourcetype>")
        server.enqueue(MockResponse().setResponseCode(207).setBody(envelope(unmarkedCollection)))
        val unmarked = client.sharedFolderSnapshot(server.url("dav/").toString(), "/", "Bearer test")
        assertEquals(false, unmarked.plainCollectionConfirmed)
    }

    @Test fun `depth zero collection validation also rejects encrypted metadata`() {
        val collection =
            response(
                "/dav/folder/",
                "200 OK",
                "<d:resourcetype><d:collection/></d:resourcetype><d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype>",
            )
        server.enqueue(MockResponse().setResponseCode(207).setBody(envelope(collection)))
        org.junit.Assert.assertThrows(OpenCloudException::class.java) {
            client.requireCollection(server.url("dav/folder/").toString(), "Bearer test")
        }
    }

    @Test fun `encrypted folders do not enter a directory snapshot`() {
        val collection = response("/dav/", "200 OK", "<d:resourcetype><d:collection/></d:resourcetype>")
        val vault =
            response(
                "/dav/Secret.vault",
                "200 OK",
                "<d:resourcetype><d:collection/></d:resourcetype><v:integrity-id xmlns:v=\"ocrclone\">key</v:integrity-id>",
            )
        server.enqueue(MockResponse().setResponseCode(207).setBody(envelope(collection + vault)))
        assertEquals(emptyList<RemoteResource>(), client.folder(server.url("dav/").toString(), "/", "Bearer test"))
    }

    private lateinit var server: MockWebServer
    private lateinit var client: RemoteDiscoveryClient

    @Before fun setUp() {
        server = MockWebServer().also { it.start() }
        client = RemoteDiscoveryClient(OkHttpClient())
    }

    @After fun tearDown() = server.shutdown()

    @Test fun `oversized listing fails before parsing or publishing`() {
        server.enqueue(MockResponse().setBody("x".repeat(65)))
        val bounded = RemoteDiscoveryClient(OkHttpClient(), maxResponseBytes = 64)
        org.junit.Assert.assertThrows(OpenCloudException::class.java) {
            bounded.folder(server.url("dav/").toString(), "/", "Bearer secret")
        }
    }

    @Test fun `streamed discovery preserves a shorter caller deadline`() {
        val collection = response("/dav/", "200 OK", "<d:resourcetype><d:collection/></d:resourcetype>")
        server.enqueue(
            MockResponse().setBody(envelope(collection)).setHeadersDelay(1, java.util.concurrent.TimeUnit.SECONDS),
        )
        val bounded =
            RemoteDiscoveryClient(
                OkHttpClient.Builder().callTimeout(100, java.util.concurrent.TimeUnit.MILLISECONDS).build(),
            )
        org.junit.Assert.assertThrows(java.io.InterruptedIOException::class.java) {
            bounded.folder(server.url("dav/").toString(), "/", "Bearer test")
        }
    }

    @Test fun `failed resources and incomplete XML never become deletion snapshots`() {
        val collection = response("/dav/", "200 OK", "<d:resourcetype><d:collection/></d:resourcetype>")
        val invalid =
            listOf(
                "<html/>",
                "<d:multistatus xmlns:d=\"DAV:\"/>",
                envelope(collection + response("/dav/private", "403 Forbidden", "")),
                envelope(collection + response("/outside/file", "200 OK", "")),
                "<!DOCTYPE d:multistatus [<!ENTITY secret SYSTEM 'file:///private'>]>" + envelope(collection),
            )
        invalid.forEach { xml ->
            server.enqueue(MockResponse().setResponseCode(207).setBody(xml))
            org.junit.Assert.assertThrows(OpenCloudException::class.java) {
                client.folder(server.url("dav/").toString(), "/", "Bearer secret")
            }
        }
    }

    @Test fun `failed property values are ignored and plus signs remain literal`() {
        val collection = response("/dav/", "200 OK", "<d:resourcetype><d:collection/></d:resourcetype>")
        val child = """<d:response><d:href>/dav/a+b.txt</d:href>
            <d:propstat><d:prop><d:getetag>wrong</d:getetag></d:prop><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>
            <d:propstat><d:prop><d:getetag>correct</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>
            </d:response>"""
        server.enqueue(MockResponse().setResponseCode(207).setBody(envelope(collection + child)))
        val item = client.folder(server.url("dav/").toString(), "/", "Bearer secret").single()
        assertEquals("a+b.txt", item.name)
        assertEquals("correct", item.eTag)
    }

    @Test fun `multistatus descriptions and foreign extensions do not contribute resources`() {
        val collection = response("/dav/", "200 OK", "<d:resourcetype><d:collection/></d:resourcetype>")
        val extension = "<x:extra xmlns:x=\"urn:example\">${response("/dav/hidden", "200 OK", "")}</x:extra>"
        val description = "<d:responsedescription>Folder listing</d:responsedescription>"
        server.enqueue(MockResponse().setBody(envelope(extension + collection + description)))
        assertEquals(emptyList<RemoteResource>(), client.folder(server.url("dav/").toString(), "/", "Bearer test"))
    }

    @Test fun `large streamed listing keeps all children and validates final collection`() {
        val children =
            buildString {
                repeat(12_000) { append(response("/dav/file-$it", "200 OK", "")) }
            }
        val collection = response("/dav/", "200 OK", "<d:resourcetype><d:collection/></d:resourcetype>")
        server.enqueue(MockResponse().setBody(envelope(children + collection)))
        val result = client.folderSnapshot(server.url("dav/").toString(), "/", "Bearer test")
        assertEquals(12_000, result.resources.size)
        assertEquals("file-11999", result.resources.last().name)
    }

    @Test fun `collection may appear last without publishing encrypted children`() {
        val child = response("/dav/child", "200 OK", "")
        val collection =
            response(
                "/dav/",
                "200 OK",
                "<d:resourcetype><d:collection/></d:resourcetype>" +
                    "<d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype>",
            )
        server.enqueue(MockResponse().setResponseCode(207).setBody(envelope(child + collection)))
        val result = client.sharedFolderSnapshot(server.url("dav/").toString(), "/", "Bearer test")
        assertEquals(emptyList<RemoteResource>(), result.resources)
        assertEquals(setOf("/"), result.excludedVaultPaths)
    }

    @Test fun `malformed ending after valid entries never returns a partial snapshot`() {
        val collection = response("/dav/", "200 OK", "<d:resourcetype><d:collection/></d:resourcetype>")
        val child = response("/dav/child", "200 OK", "")
        server.enqueue(MockResponse().setBody(envelope(collection + child).dropLast(5)))
        org.junit.Assert.assertThrows(OpenCloudException::class.java) {
            client.folderSnapshot(server.url("dav/").toString(), "/", "Bearer test")
        }
    }

    private fun envelope(responses: String) = """<d:multistatus xmlns:d="DAV:">$responses</d:multistatus>"""

    private fun response(
        href: String,
        status: String,
        properties: String,
    ) = """<d:response><d:href>$href</d:href><d:propstat><d:prop>$properties</d:prop>
            <d:status>HTTP/1.1 $status</d:status></d:propstat></d:response>"""

    @Test fun `folder parses depth one multistatus and excludes collection itself`() {
        server.enqueue(
            MockResponse()
                .setResponseCode(
                    207,
                ).setBody(
                    """<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>${server.url(
                        "dav/spaces/drive/",
                    )}</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response><d:response><d:href>/dav/spaces/drive/Photo.jpg</d:href><d:propstat><d:prop><oc:fileid>photo</oc:fileid><oc:name>Photo.jpg</oc:name><d:getcontenttype>image/jpeg</d:getcontenttype><d:getcontentlength>12</d:getcontentlength><d:getetag>etag</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>""",
                ),
        )
        val result = client.folder(server.url("dav/spaces/drive").toString(), "/", "Basic value").single()
        assertEquals("photo", result.id)
        assertEquals("/Photo.jpg", result.path)
        assertEquals("1", server.takeRequest().getHeader("Depth"))
    }
}
