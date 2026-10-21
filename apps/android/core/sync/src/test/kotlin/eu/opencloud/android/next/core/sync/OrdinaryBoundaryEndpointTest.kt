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

    @Before fun prepare() {
        server = MockWebServer().also { it.start() }
        database =
            Room.inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), FileBrowserDatabase::class.java).build()
        val account = AccountEntity("account", server.url("/").toString(), "user", "User", "BASIC", true)
        val location =
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
        val access = VaultAccess(account, account.serverUrl, "Bearer synthetic", OkHttpClient(), { true }, { account })
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
