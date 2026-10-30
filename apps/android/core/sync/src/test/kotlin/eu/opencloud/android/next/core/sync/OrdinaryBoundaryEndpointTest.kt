package eu.opencloud.android.next.core.sync

import androidx.room.Room
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.VaultExclusion
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.ByteArrayOutputStream

@RunWith(RobolectricTestRunner::class)
class OrdinaryBoundaryEndpointTest {
    private lateinit var server: MockWebServer
    private lateinit var database: FileBrowserDatabase
    private lateinit var endpoint: OrdinaryBoundaryEndpoint
    private lateinit var location: VaultLocation
    private lateinit var access: VaultAccess

    @Before fun prepare() {
        server = MockWebServer().also { it.start() }
        database =
            Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), FileBrowserDatabase::class.java).build()
        val account = AccountEntity("account", server.url("/").toString(), "user", "User", "BASIC", true)
        location =
            VaultLocation(
                "account",
                "Personal",
                VaultLocationKind.PERSONAL,
                "drive",
                "root",
                "root",
                account.serverUrl,
                server.url("dav/").toString(),
                "",
                false,
            )
        access = VaultAccess(account, account.serverUrl, "Bearer synthetic", OkHttpClient(), { true }, { account })
        endpoint = OrdinaryBoundaryEndpoint(access, location, database.vaultExclusionDao(), {}, EndpointPolicy(true))
    }

    @After fun close() {
        database.close()
        server.shutdown()
    }

    @Test fun `ordinary sibling file remains readable when parent contains a known encrypted folder`() =
        runBlocking {
            database.vaultExclusionDao().record(VaultExclusion("account", "drive", "/Secret.vault"))
            server.enqueue(
                listing(
                    "/dav/",
                    "root",
                    true,
                    "root",
                    response("/dav/note.txt", "note", false, "v1", 3) +
                        response("/dav/Secret.vault/", "vault", true, "vault"),
                ),
            )
            server.enqueue(MockResponse().setHeader("ETag", "\"v1\"").setBody("one"))
            val output = ByteArrayOutputStream()
            endpoint.read(BoundaryEntry("note", "note.txt", "note.txt", false, 3, "\"v1\"", null), output)
            assertEquals("one", output.toString(Charsets.UTF_8.name()))
            assertEquals("PROPFIND", server.takeRequest().method)
            assertEquals("GET", server.takeRequest().method)
        }

    @Test fun `recursive source listing refuses an encrypted child rather than omit it`() {
        server.enqueue(listing("/dav/", "root", true, "root", response("/dav/Secret.vault/", "vault", true, "vault")))
        val error = assertThrows(OpenCloudException::class.java) { runBlocking { endpoint.list("") } }
        assertEquals(OpenCloudError.AccessDenied, error.error)
    }

    @Test fun `directory delete retains version captured before empty listing despite racing addition`() {
        server.enqueue(listing("/dav/", "root", true, "root", response("/dav/Folder/", "folder", true, "before")))
        server.enqueue(listing("/dav/Folder/", "folder", true, "before"))
        server.enqueue(MockResponse().setResponseCode(412))
        val error =
            assertThrows(OpenCloudException::class.java) {
                runBlocking {
                    endpoint.delete(
                        BoundaryEntry("folder", "Folder", "Folder", true, 0, "\"before\"", null),
                    )
                }
            }
        assertEquals(OpenCloudError.Conflict, error.error)
        server.takeRequest()
        server.takeRequest()
        val deletion = server.takeRequest()
        assertEquals("DELETE", deletion.method)
        assertEquals("\"before\"", deletion.getHeader("If-Match"))
        assertEquals(3, server.requestCount)
    }

    @Test fun `accepted delete with source still present fails without deleting again`() {
        val child = response("/dav/note.txt", "file", false, "before")
        val parent = listing("/dav/", "root", true, "root", child)
        server.enqueue(parent)
        server.enqueue(MockResponse().setResponseCode(202))
        server.enqueue(listing("/dav/", "root", true, "root", response("/dav/note.txt", "new-file", false, "after")))
        val error =
            assertThrows(OpenCloudException::class.java) {
                runBlocking {
                    endpoint.delete(
                        BoundaryEntry("file", "note.txt", "note.txt", false, 0, "\"before\"", null),
                    )
                }
            }
        assertEquals(OpenCloudError.PreconditionFailed, error.error)
        assertEquals("PROPFIND", server.takeRequest().method)
        assertEquals("DELETE", server.takeRequest().method)
        assertEquals("PROPFIND", server.takeRequest().method)
        assertEquals(3, server.requestCount)
    }

    @Test fun `bounded ordinary lookup reads the exact target near a large parent tail`() =
        runBlocking {
            val siblings =
                (0 until 1500).joinToString("") { number ->
                    response("/dav/sibling-$number", "sibling-$number", false, "s-$number", 3)
                }
            server.enqueue(
                listing(
                    "/dav/",
                    "root",
                    true,
                    "root",
                    siblings + response("/dav/note.txt", "note", false, "v1", 3),
                ),
            )
            server.enqueue(MockResponse().setHeader("ETag", "\"v1\"").setBody("one"))
            val output = ByteArrayOutputStream()
            endpoint.read(BoundaryEntry("note", "note.txt", "note.txt", false, 3, "\"v1\""), output)
            assertEquals("one", output.toString(Charsets.UTF_8.name()))
            assertEquals(2, server.requestCount)
        }

    @Test fun `late duplicate in ordinary lookup prevents exposing an earlier target`() {
        val siblings =
            (0 until 1500).joinToString("") { number ->
                response("/dav/sibling-$number", "sibling-$number", false, "s-$number", 3)
            }
        val target = response("/dav/note.txt", "note", false, "v1", 3)
        val duplicate = response("/dav/duplicate", "sibling-0", false, "v2", 3)
        server.enqueue(listing("/dav/", "root", true, "root", target + siblings + duplicate))
        val failure =
            assertThrows(OpenCloudException::class.java) {
                runBlocking {
                    endpoint.read(
                        BoundaryEntry("note", "note.txt", "note.txt", false, 3, "\"v1\""),
                        ByteArrayOutputStream(),
                    )
                }
            }
        assertEquals(OpenCloudError.InvalidResponse, failure.error)
        assertEquals(1, server.requestCount)
    }

    @Test fun `bounded ordinary lookup never rebinds a changed file version`() {
        server.enqueue(listing("/dav/", "root", true, "root", response("/dav/note.txt", "note", false, "v2", 3)))
        val failure =
            assertThrows(OpenCloudException::class.java) {
                runBlocking {
                    endpoint.read(
                        BoundaryEntry("note", "note.txt", "note.txt", false, 3, "\"v1\""),
                        ByteArrayOutputStream(),
                    )
                }
            }
        assertEquals(OpenCloudError.PreconditionFailed, failure.error)
        assertEquals(1, server.requestCount)
    }

    @Test fun `wrong requested ordinary collection is rejected before target publication`() {
        server.enqueue(listing("/other/", "wrong", true, "root", response("/dav/note.txt", "note", false, "v1", 3)))
        assertThrows(OpenCloudException::class.java) { runBlocking { endpoint.containsName("", "note.txt") } }
        assertEquals(1, server.requestCount)
    }

    @Test fun `bounded name presence includes a live encrypted sibling marker`() =
        runBlocking {
            server.enqueue(listing("/dav/", "root", true, "root", response("/dav/Secret.vault/", "vault", true, "v1")))
            assertTrue(endpoint.containsName("", "Secret.vault"))
        }

    @Test fun `post-delete encrypted replacement is present and never deleted as owned cleanup`() {
        server.enqueue(listing("/dav/", "root", true, "root", response("/dav/note.txt", "note", false, "v1", 3)))
        server.enqueue(MockResponse().setResponseCode(204))
        val encrypted =
            response("/dav/note.txt/", "replacement", true, "v2").replace(
                "</d:prop>",
                "<d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype></d:prop>",
            )
        server.enqueue(listing("/dav/", "root", true, "root", encrypted))
        val failure =
            assertThrows(OpenCloudException::class.java) {
                runBlocking { endpoint.delete(BoundaryEntry("note", "note.txt", "note.txt", false, 3, "\"v1\"")) }
            }
        assertEquals(OpenCloudError.PreconditionFailed, failure.error)
        assertEquals(listOf("PROPFIND", "DELETE", "PROPFIND"), List(3) { server.takeRequest().method })
    }

    @Test fun `production recursive snapshot refuses a late encrypted marker after plain descriptors`() {
        val ordinary =
            (0 until 257).joinToString("") { number ->
                response("/dav/file-$number", "file-$number", false, "v1", 3)
            }
        server.enqueue(
            listing("/dav/", "root", true, "root", ordinary + response("/dav/Late.vault/", "late", true, "v1")),
        )
        val failure =
            assertThrows(OpenCloudException::class.java) {
                runBlocking { endpoint.openDirectory(RuntimeEnvironment.getApplication(), "") }
            }
        assertEquals(OpenCloudError.AccessDenied, failure.error)
        assertEquals(1, server.requestCount)
    }

    @Test fun `production recursive snapshot rejects malformed final XML before publication`() {
        val ordinary =
            (0 until 257).joinToString("") { number ->
                response("/dav/file-$number", "file-$number", false, "v1", 3)
            }
        server.enqueue(
            MockResponse().setResponseCode(207).setBody(
                "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\">" +
                    response("/dav/", "root", true, "v1") + ordinary + "<d:response>",
            ),
        )
        assertThrows(OpenCloudException::class.java) {
            runBlocking { endpoint.openDirectory(RuntimeEnvironment.getApplication(), "") }
        }
        assertEquals(1, server.requestCount)
    }

    @Test fun `names-only capture includes a late encrypted marker without readable descriptors`() =
        runBlocking {
            val ordinary =
                (0 until 257).joinToString("") { number ->
                    response("/dav/file-$number", "file-$number", false, "v1", 3)
                }
            server.enqueue(
                listing(
                    "/dav/",
                    "root",
                    true,
                    "root",
                    ordinary + response("/dav/Late.vault/", "late", true, "v1"),
                ),
            )
            endpoint.openNameIndex(RuntimeEnvironment.getApplication(), "").use { names ->
                val requests = server.requestCount
                assertTrue(!names.reserve("Late.vault"))
                assertTrue(!names.reserve("file-256"))
                assertTrue(names.reserve("new-name"))
                assertTrue(!names.reserve("new-name"))
                assertEquals(requests, server.requestCount)
            }
        }

    @Test fun `late ordinary wire duplicate rejects the entire names-only capture`() {
        val ordinary =
            (0 until 257).joinToString("") { number ->
                response("/dav/file-$number", "file-$number", false, "v1", 3)
            }
        server.enqueue(
            listing(
                "/dav/",
                "root",
                true,
                "root",
                ordinary + response("/dav/late", "file-0", false, "v1", 3),
            ),
        )
        val failure =
            assertThrows(OpenCloudException::class.java) {
                runBlocking { endpoint.openNameIndex(RuntimeEnvironment.getApplication(), "") }
            }
        assertEquals(OpenCloudError.InvalidResponse, failure.error)
        assertEquals(1, server.requestCount)
    }

    @Test fun `folder chooser filters files before counting and retains a late explicit vault marker`() =
        runBlocking {
            val folders =
                (0 until 300).joinToString("") { number ->
                    val name = "folder-${number.toString().padStart(3, '0')}"
                    response("/dav/$name/", "folder-$number", true, "v1")
                }
            val files =
                (0 until 257).joinToString("") { number ->
                    response("/dav/file-$number", "file-$number", false, "v1", 1)
                }
            val marker =
                response("/dav/zz-secret/", "vault", true, "v1").replace(
                    "</d:prop>",
                    "<d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype></d:prop>",
                )
            server.enqueue(listing("/dav/", "root", true, "root", folders + files + marker))
            endpoint.openDestinationFolders(RuntimeEnvironment.getApplication(), "").use { snapshot ->
                assertEquals(301L, snapshot.totalCount)
                assertEquals(128, snapshot.page().size)
                val tail = snapshot.page(256)
                assertEquals(45, tail.size)
                assertEquals(BoundaryDestinationFolder("vault", "zz-secret", "zz-secret", true), tail.last())
                assertTrue(snapshot.page(301).isEmpty())
            }
            assertEquals(1, server.requestCount)
        }

    @Test fun `folder chooser validates late ignored file sizes and all raw identities`() {
        val folder = response("/dav/Folder/", "folder", true, "v1")
        listOf(
            response("/dav/invalid-file", "file", false, "v1", -1),
            response("/dav/duplicate", "folder", false, "v1", 1),
            response("/dav/Folder", "different-id", false, "v1", 1),
        ).forEach { invalid ->
            server.enqueue(listing("/dav/", "root", true, "root", folder + invalid))
            val failure =
                assertThrows(OpenCloudException::class.java) {
                    runBlocking { endpoint.openDestinationFolders(RuntimeEnvironment.getApplication(), "") }
                }
            assertEquals(OpenCloudError.InvalidResponse, failure.error)
        }
    }

    @Test fun `folder chooser rejects substituted ordinary root and encrypted requested collection`() {
        server.enqueue(listing("/dav/", "wrong-root", true, "root"))
        val failure =
            assertThrows(OpenCloudException::class.java) {
                runBlocking { endpoint.openDestinationFolders(RuntimeEnvironment.getApplication(), "") }
            }
        assertEquals(OpenCloudError.PreconditionFailed, failure.error)
        val encryptedSelf =
            response("/dav/Secret/", "vault", true, "root").replace(
                "</d:prop>",
                "<d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype></d:prop>",
            )
        server.enqueue(
            MockResponse().setResponseCode(207).setBody(
                "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\">$encryptedSelf</d:multistatus>",
            ),
        )
        val marker =
            assertThrows(OpenCloudException::class.java) {
                runBlocking { endpoint.openDestinationFolders(RuntimeEnvironment.getApplication(), "Secret") }
            }
        assertEquals(OpenCloudError.AccessDenied, marker.error)
    }

    @Test fun `folder chooser retains ordinary encrypted ancestor URL refusal`() {
        val failure =
            assertThrows(OpenCloudException::class.java) {
                runBlocking {
                    endpoint.openDestinationFolders(
                        RuntimeEnvironment.getApplication(),
                        "Secret.VAULT/inside",
                    )
                }
            }
        assertEquals(OpenCloudError.Unsupported, failure.error)
        assertEquals(0, server.requestCount)
    }

    @Test fun `folder chooser retains existing shortened Graph root to DAV identity compatibility`() =
        runBlocking {
            val shortened = location.copy(sourceRootId = "storage\$space")
            val compatible =
                OrdinaryBoundaryEndpoint(
                    access,
                    shortened,
                    database.vaultExclusionDao(),
                    {},
                    EndpointPolicy(true),
                )
            server.enqueue(listing("/dav/", "storage\$space!space", true, "root"))
            compatible.openDestinationFolders(RuntimeEnvironment.getApplication(), "").use { snapshot ->
                assertEquals(0L, snapshot.totalCount)
                assertTrue(snapshot.page().isEmpty())
            }
        }

    private fun listing(
        path: String,
        id: String,
        folder: Boolean,
        version: String,
        children: String = "",
    ): MockResponse =
        MockResponse()
            .setResponseCode(
                207,
            ).setBody(
                "<d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\">${response(
                    path,
                    id,
                    folder,
                    version,
                )}$children</d:multistatus>",
            )

    private fun response(
        path: String,
        id: String,
        folder: Boolean,
        version: String,
        size: Long = 0,
    ): String =
        "<d:response><d:href>$path</d:href><d:propstat><d:prop>" +
            "<d:resourcetype>${if (folder) "<d:collection/>" else ""}</d:resourcetype>" +
            "<d:getcontentlength>$size</d:getcontentlength>" +
            "<d:getetag>\"$version\"</d:getetag><oc:fileid>$id</oc:fileid>" +
            "</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
}
