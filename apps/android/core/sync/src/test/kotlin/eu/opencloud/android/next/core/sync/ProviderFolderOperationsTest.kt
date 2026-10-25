package eu.opencloud.android.next.core.sync

import androidx.room.Room
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.util.concurrent.TimeUnit

@RunWith(RobolectricTestRunner::class)
class ProviderFolderOperationsTest {
    private val context = RuntimeEnvironment.getApplication()
    private val database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
    private val store = FileBrowserStore(database)
    private val server = MockWebServer()
    private var leaseValid = true
    private val accountLease: () -> Boolean = { leaseValid }
    private val http =
        OkHttpClient
            .Builder()
            .addInterceptor { chain ->
                // Only this injected test client downgrades the synthetic HTTPS endpoint to loopback HTTP.
                chain.proceed(
                    chain
                        .request()
                        .newBuilder()
                        .url(
                            chain
                                .request()
                                .url
                                .newBuilder()
                                .scheme("http")
                                .build(),
                        ).build(),
                )
            }.build()
    private val operations =
        ProviderFolderOperations(
            context,
            store,
            { "Bearer fixture" },
            { http },
            { accountLease },
        )

    @Before fun seed() =
        runBlocking {
            server.start()
            val base = server.url("/").toString().replace("http:", "https:")
            database.accountDao().upsert(AccountEntity("a", base, "u", "User", "BASIC", false))
            database.spaceDao().insert(
                SpaceEntity("a", "s", "Personal", "personal", null, null, "root", "${base}dav", null, null),
            )
        }

    @After fun close() {
        database.close()
        server.shutdown()
    }

    @Test fun `create folder then backup file returns confirmed identities without overwriting`() =
        runBlocking<Unit> {
            server.enqueue(listing("/dav/"))
            server.enqueue(MockResponse().setResponseCode(201))
            server.enqueue(listing("/dav/", item("/dav/Backups", "folder-id", true)))
            val folder = operations.create("a", "s", null, "Backups", "vnd.android.document/directory") { true }
            assertEquals("folder-id", folder.remoteId)
            assertEquals("/Backups", folder.path)
            assertEquals("PROPFIND", nextRequest().method)
            assertEquals("MKCOL", nextRequest().method)
            assertEquals("PROPFIND", nextRequest().method)

            server.enqueue(listing("/dav/Backups/"))
            server.enqueue(MockResponse().setResponseCode(404))
            server.enqueue(MockResponse().setResponseCode(201).setHeader("ETag", "\"v1\""))
            server.enqueue(listing("/dav/Backups/", item("/dav/Backups/backup.json", "file-id", false)))
            val file = operations.create("a", "s", folder.remoteId, "backup.json", "application/json") { true }
            assertEquals("file-id", file.remoteId)
            assertEquals("folder-id", file.parentId)
            assertEquals("/Backups/backup.json", file.path)
            nextRequest()
            assertEquals("HEAD", nextRequest().method)
            val put = nextRequest()
            assertEquals("PUT", put.method)
            assertEquals("*", put.getHeader("If-None-Match"))
            assertEquals(0L, put.bodySize)
            nextRequest()
        }

    @Test fun `existing file and invalid names never trigger a write`() {
        server.enqueue(listing("/dav/", item("/dav/backup.json", "file-id", false)))
        assertThrows(IllegalStateException::class.java) {
            runBlocking { operations.create("a", "s", null, "backup.json", "application/json") { true } }
        }
        assertEquals("PROPFIND", nextRequest().method)
        listOf("../file", "folder/file", "..", "bad\\name").forEach { name ->
            assertThrows(IllegalArgumentException::class.java) {
                runBlocking { operations.create("a", "s", null, name, "application/json") { true } }
            }
        }
        assertEquals(1, server.requestCount)
    }

    @Test fun `rename and retention deletion use conditional server operations`() =
        runBlocking {
            server.enqueue(listing("/dav/", item("/dav/backup.tmp", "file-id", false)))
            operations.refresh("a", "s", null) { true }
            nextRequest()
            val file = store.children("a", "s", null).single()
            server.enqueue(MockResponse().setResponseCode(201))
            server.enqueue(listing("/dav/", item("/dav/backup.json", "file-id", false)))
            val renamed = operations.rename(file, "backup.json") { true }
            val move = nextRequest()
            assertEquals("MOVE", move.method)
            assertEquals("F", move.getHeader("Overwrite"))
            assertEquals("\"v1\"", move.getHeader("If-Match"))
            assertTrue(requireNotNull(move.getHeader("Destination")).endsWith("/backup.json"))
            nextRequest()
            server.enqueue(MockResponse().setResponseCode(204))
            operations.delete(renamed) { true }
            val delete = nextRequest()
            assertEquals("DELETE", delete.method)
            assertEquals("\"v1\"", delete.getHeader("If-Match"))
            assertTrue(store.children("a", "s", null).isEmpty())
        }

    @Test fun `locked creation sends no network request`() {
        assertThrows(IllegalStateException::class.java) {
            runBlocking { operations.create("a", "s", null, "backup.json", "application/json") { false } }
        }
        assertEquals(0, server.requestCount)
    }

    @Test fun `revoked account lease prevents refresh request`() {
        leaseValid = false
        val failure =
            assertThrows(OpenCloudException::class.java) {
                runBlocking { operations.refresh("a", "s", null) { true } }
            }
        assertEquals(OpenCloudError.AccessDenied, failure.error)
        assertEquals(0, server.requestCount)
    }

    private fun nextRequest(): RecordedRequest = requireNotNull(server.takeRequest(2, TimeUnit.SECONDS))

    private fun listing(
        path: String,
        children: String = "",
    ) = MockResponse().setResponseCode(207).setBody(
        """<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">${item(
            path,
            "root",
            true,
        )}$children</d:multistatus>""",
    )

    private fun item(
        path: String,
        id: String,
        folder: Boolean,
    ): String =
        """<d:response><d:href>$path</d:href><d:propstat><d:prop><oc:fileid>$id</oc:fileid><d:getetag>"v1"</d:getetag><d:getcontentlength>0</d:getcontentlength><d:resourcetype>${if (folder) "<d:collection/>" else ""}</d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"""
}
