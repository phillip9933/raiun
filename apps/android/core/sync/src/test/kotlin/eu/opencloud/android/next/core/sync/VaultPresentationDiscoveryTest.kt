package eu.opencloud.android.next.core.sync

import androidx.room.Room
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
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

@RunWith(RobolectricTestRunner::class)
class VaultPresentationDiscoveryTest {
    private lateinit var server: MockWebServer
    private lateinit var database: FileBrowserDatabase
    private lateinit var store: FileBrowserStore
    private lateinit var account: AccountEntity

    @Before
    fun setUp() {
        server = MockWebServer().also { it.start() }
        database =
            Room
                .inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), FileBrowserDatabase::class.java)
                .allowMainThreadQueries()
                .build()
        store = FileBrowserStore(database)
        account = AccountEntity("account", server.url("/").toString().trimEnd('/'), "user", "User", "BASIC", false)
        runBlocking { database.accountDao().upsert(account) }
    }

    @After
    fun tearDown() {
        database.close()
        server.shutdown()
    }

    @Test
    fun presentationEncryptedSpaceIsVerifiedAndSeparate() =
        runTest {
            val graphRoot = "storage\$space"
            val davRoot = "$graphRoot!space"
            server.enqueue(graphVaultPage(graphRoot, "dav/spaces/" + graphRoot + "/"))
            server.enqueue(davListing(DavListingFixture("/dav/spaces/" + graphRoot + "/", davRoot, "Archive")))
            val locations = repository().encryptedSpaces(account.id)
            assertEquals(1, locations.size)
            assertEquals(VaultLocationKind.SPACE_VAULT, locations.single().kind)
            assertEquals("vault-drive", locations.single().driveId)
            assertEquals(graphRoot, locations.single().sourceRootId)
            assertEquals(davRoot, locations.single().remoteVaultId)
            assertTrue(locations.single().isVaultRoot)
            assertEquals("/graph/v1.0/me/drives", server.takeRequest().path)
            assertEquals("PROPFIND", server.takeRequest().method)
            assertTrue(store.spaces(account.id).isEmpty())
        }

    @Test
    fun encryptedFolderApiReturnsImmediateMarkedFoldersOnly() =
        runTest {
            server.enqueue(graphPage())
            server.enqueue(davListing(DavListingFixture("/dav/files/", "root", "files")))
            val children =
                listOf(
                    entry(
                        DavEntryFixture(
                            "/dav/files/projects/Marked",
                            "marked-id",
                            "Marked",
                            marker = "<d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype>",
                        ),
                    ),
                    entry(DavEntryFixture("/dav/files/projects/Plain", "plain-id", "Plain")),
                )
            server.enqueue(davListing(DavListingFixture("/dav/files/projects/", "projects-id", "projects", children)))
            val folders = repository().encryptedFolders(account.id, "drive", "projects")
            assertEquals(1, folders.size)
            assertEquals(VaultLocationKind.FOLDER_VAULT, folders.single().kind)
            assertEquals("marked-id", folders.single().remoteVaultId)
            assertEquals("projects/Marked", folders.single().vaultPath)
            assertEquals("Marked", folders.single().title)
            assertTrue(folders.single().isVaultRoot)
            assertEquals("/graph/v1.0/me/drives", server.takeRequest().path)
            assertEquals("PROPFIND", server.takeRequest().method)
            assertEquals("PROPFIND", server.takeRequest().method)
        }

    @Test
    fun vaultPathCannotBeTraversedAsOrdinaryFolder() =
        runTest {
            assertThrows(OpenCloudException::class.java) {
                runBlocking { repository().encryptedFolders(account.id, "drive", "Secret.vault") }
            }
            assertEquals(0, server.requestCount)
        }

    @Test
    fun markedDavParentCannotBeTraversedAsOrdinaryFolder() =
        runTest {
            server.enqueue(graphPage())
            server.enqueue(davListing(DavListingFixture("/dav/files/", "root", "files")))
            server.enqueue(
                davListing(
                    DavListingFixture(
                        "/dav/files/sealed/",
                        "sealed-id",
                        "sealed",
                        marker = "<d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype>",
                    ),
                ),
            )
            assertThrows(OpenCloudException::class.java) {
                runBlocking { repository().encryptedFolders(account.id, "drive", "sealed") }
            }
            assertEquals(3, server.requestCount)
        }

    private fun repository() =
        VaultRepository(
            store = store,
            authorizationFor = { "Bearer test" },
            clientFor = { OkHttpClient() },
            endpointPolicy = EndpointPolicy(true),
            permitFor = { { true } },
        )

    private fun graphPage(): MockResponse {
        val url = server.url("dav/files/")
        return MockResponse().setBody(
            """{"value":[{"id":"drive","name":"Personal","driveType":"personal","root":{"id":"root","webDavUrl":"$url"}}]}""",
        )
    }

    private fun graphVaultPage(
        rootId: String,
        path: String,
    ): MockResponse {
        val url = server.url(path)
        return MockResponse().setBody(
            """{"value":[{"id":"vault-drive","name":"Archive","driveType":"project","@libre.graph.contentType":"application/vnd.opencloud.vault","root":{"id":"$rootId","webDavUrl":"$url"}}]}""",
        )
    }

    private fun davListing(fixture: DavListingFixture): MockResponse {
        val href = if (fixture.path.endsWith('/')) fixture.path else fixture.path + "/"
        return MockResponse().setResponseCode(207).setBody(
            """<?xml version="1.0"?><d:multistatus """ +
                """xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:ocrclone="ocrclone">""" +
                davEntry(href, fixture.id, fixture.name, fixture.marker) +
                fixture.children.joinToString("") + "</d:multistatus>",
        )
    }

    private fun entry(fixture: DavEntryFixture): String {
        val href = if (fixture.folder) fixture.path.trimEnd('/') + "/" else fixture.path
        val collection = if (fixture.folder) "<d:collection/>" else ""
        return """<d:response><d:href>$href</d:href><d:propstat><d:prop>
            <d:resourcetype>$collection</d:resourcetype><d:getcontentlength>0</d:getcontentlength>
            <oc:fileid>${fixture.id}</oc:fileid><oc:name>${fixture.name}</oc:name>${fixture.marker}
            </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"""
    }

    private fun davEntry(
        href: String,
        id: String,
        name: String,
        marker: String,
    ) = """<d:response><d:href>$href</d:href><d:propstat><d:prop>
            <d:resourcetype><d:collection/></d:resourcetype><d:getcontentlength>0</d:getcontentlength>
            <oc:fileid>$id</oc:fileid><oc:name>$name</oc:name>$marker
            </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"""

    private data class DavListingFixture(
        val path: String,
        val id: String,
        val name: String,
        val children: List<String> = emptyList(),
        val marker: String = "",
    )

    private data class DavEntryFixture(
        val path: String,
        val id: String,
        val name: String,
        val folder: Boolean = true,
        val marker: String = "",
    )
}
