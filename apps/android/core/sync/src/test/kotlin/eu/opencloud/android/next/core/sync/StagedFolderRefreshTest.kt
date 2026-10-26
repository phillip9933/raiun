package eu.opencloud.android.next.core.sync

import android.database.sqlite.SQLiteDatabase
import androidx.room.Room
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.RemoteDiscoveryClient
import eu.opencloud.android.next.core.network.RemoteFolderEntry
import eu.opencloud.android.next.core.network.RemoteResource
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File

@RunWith(RobolectricTestRunner::class)
class StagedFolderRefreshTest {
    private val context = RuntimeEnvironment.getApplication()
    private lateinit var database: FileBrowserDatabase
    private lateinit var store: FileBrowserStore
    private lateinit var server: MockWebServer
    private lateinit var cache: File
    private lateinit var space: SpaceEntity

    @Before fun setUp() =
        runTest {
            database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
            store = FileBrowserStore(database)
            server = MockWebServer().also { it.start() }
            cache = File(context.cacheDir, "staged-folder-test-${System.nanoTime()}").apply { mkdirs() }
            space =
                SpaceEntity(
                    "account",
                    "drive",
                    "Personal",
                    "personal",
                    null,
                    null,
                    "root",
                    "https://cloud.example/dav/",
                    null,
                    null,
                )
            database.accountDao().upsert(
                AccountEntity("account", "https://cloud.example", "user", "User", "BASIC", false),
            )
            database.spaceDao().upsertAll(listOf(space))
        }

    @After fun tearDown() {
        database.close()
        server.shutdown()
        cache.deleteRecursively()
    }

    @Test fun rootLastSnapshotPublishesAtomicallyAndRemovesStaleChildren() =
        runTest {
            val old =
                ResourceEntity("account", "drive", "old", null, "/old", "old", ResourceKind.FILE, null, 1, null, 0, 0)
            store.replaceFolderSnapshot("account", "drive", null, listOf(old))
            server.enqueue(MockResponse().setResponseCode(207).setBody(envelope(child("new") + root())))
            refresh()
            assertNull(store.resource("account", "drive", "old"))
            assertEquals("new", store.resource("account", "drive", "new")?.name)
        }

    @Test fun malformedLateXmlAndDuplicateIdentityPreserveThePreviousSnapshot() =
        runTest {
            val old =
                ResourceEntity("account", "drive", "old", null, "/old", "old", ResourceKind.FILE, null, 1, null, 0, 0)
            store.replaceFolderSnapshot("account", "drive", null, listOf(old))
            listOf(
                envelope(child("new") + root()).dropLast(5),
                envelope(root() + child("new") + child("new")),
            ).forEach { body ->
                server.enqueue(MockResponse().setResponseCode(207).setBody(body))
                assertThrows(Exception::class.java) { kotlinx.coroutines.runBlocking { refresh() } }
                assertNotNull(store.resource("account", "drive", "old"))
                assertNull(store.resource("account", "drive", "new"))
            }
        }

    @Test fun encryptedCollectionLastCannotPublishOrLeavePlaintextStage() =
        runTest {
            val old =
                ResourceEntity("account", "drive", "old", null, "/old", "old", ResourceKind.FILE, null, 1, null, 0, 0)
            store.replaceFolderSnapshot("account", "drive", null, listOf(old))
            val encryptedRoot =
                root("<d:getcontenttype>application/vnd.opencloud.vault</d:getcontenttype>")
            server.enqueue(MockResponse().setResponseCode(207).setBody(envelope(child("secret-name") + encryptedRoot)))
            assertThrows(Exception::class.java) { kotlinx.coroutines.runBlocking { refresh() } }
            assertNotNull(store.resource("account", "drive", "old"))
            assertNull(store.resource("account", "drive", "secret-name"))
            assertTrue(File(cache, "discovery-stage").listFiles().isNullOrEmpty())
        }

    @Test fun collectionIdAppearingLastCannotClobberCachedResource() =
        runTest {
            val old =
                ResourceEntity("account", "drive", "old", null, "/old", "old", ResourceKind.FILE, null, 1, null, 0, 0)
            store.replaceFolderSnapshot("account", "drive", null, listOf(old))
            val sameId = "<oc:fileid xmlns:oc=\"http://owncloud.org/ns\">root-remote-id</oc:fileid>"
            val child = response("/dav/child", sameId)
            val collection = root(sameId)
            server.enqueue(MockResponse().setResponseCode(207).setBody(envelope(child + collection)))
            assertThrows(Exception::class.java) { kotlinx.coroutines.runBlocking { refresh() } }
            assertNotNull(store.resource("account", "drive", "old"))
            assertNull(store.resource("account", "drive", "root-remote-id"))
        }

    @Test fun revokedAccountLeasePreservesPriorSnapshotAndRemovesStage() =
        runTest {
            val old =
                ResourceEntity("account", "drive", "old", null, "/old", "old", ResourceKind.FILE, null, 1, null, 0, 0)
            store.replaceFolderSnapshot("account", "drive", null, listOf(old))
            server.enqueue(MockResponse().setResponseCode(207).setBody(envelope(child("new") + root())))
            var checks = 0
            val failure =
                assertThrows(OpenCloudException::class.java) {
                    kotlinx.coroutines.runBlocking { refresh { ++checks <= 4 } }
                }
            assertEquals(OpenCloudError.AccessDenied, failure.error)
            assertNotNull(store.resource("account", "drive", "old"))
            assertNull(store.resource("account", "drive", "new"))
            assertTrue(File(cache, "discovery-stage").listFiles().isNullOrEmpty())
        }

    @Test fun moreThanOneHundredThousandEntriesStayPagedAndEncryptedOnDisk() {
        StagedRemoteFolder.create(cache).use { stage ->
            repeat(100_001) { index ->
                val name = "private-child-$index"
                assertTrue(stage.registerCanonicalPath("dav/$name"))
                stage.add(
                    RemoteFolderEntry(
                        name,
                        "/$name",
                        RemoteResource(name, "/$name", name, false, null, 1, null, 0, 0),
                    ),
                )
            }
            stage.finish()
            val reader = stage.reader("account", "drive", null, 0)
            var after = 0L
            var count = 0
            while (true) {
                val page = reader.page(after)
                if (page.isEmpty()) break
                assertTrue(page.size <= 128)
                count += page.size
                after = page.last().sequence
            }
            assertEquals(100_001, count)
            assertTrue(reader.containsRemoteId("private-child-100000"))
            assertFalse(reader.containsRemoteId("absent"))
            assertFalse(
                File(cache, "discovery-stage").listFiles().orEmpty().any {
                    it.containsAscii("private-child-100000")
                },
            )
        }
    }

    @Test fun corruptedIndexCannotDriveStaleDeletionAndCloseRemovesStageFiles() {
        val stage = StagedRemoteFolder.create(cache)
        val path = File(cache, "discovery-stage").listFiles().orEmpty().single { it.name.endsWith(".sqlite") }
        try {
            stage.add(
                RemoteFolderEntry("id", "/name", RemoteResource("id", "/name", "name", false, null, 1, null, 0, 0)),
            )
            stage.finish()
            SQLiteDatabase.openDatabase(path.path, null, SQLiteDatabase.OPEN_READWRITE).use { other ->
                other.execSQL("UPDATE entries SET idDigest = 'forged' WHERE seq = 1")
            }
            assertThrows(IllegalArgumentException::class.java) { stage.page(0) }
        } finally {
            stage.close()
            stage.close()
        }
        assertFalse(path.exists())
    }

    @Test fun pageStopsAtByteLimitEvenWhenFewerThan128RowsExist() {
        StagedRemoteFolder.create(cache).use { stage ->
            val longName = "s".repeat(500_000)
            repeat(3) { index ->
                val id = "large-$index"
                stage.add(
                    RemoteFolderEntry(id, "/$id", RemoteResource(id, "/$id", longName, false, null, 0, null, 0, 0)),
                )
            }
            stage.finish()
            val first = stage.page(0)
            assertTrue(first.size < 3)
            assertEquals(3, first.size + stage.page(first.last().sequence).size)
        }
    }

    @Test fun oversizedStagedFieldReportsDirectoryLimitAndRemovesTemporaryFile() {
        val path = File(cache, "discovery-stage")
        StagedRemoteFolder.create(cache).use { stage ->
            val longName = "private-sentinel-" + "x".repeat(512 * 1024)
            val failure =
                assertThrows(OpenCloudException::class.java) {
                    stage.add(
                        RemoteFolderEntry(
                            "large",
                            "/large",
                            RemoteResource("large", "/large", longName, false, null, 0, null, 0, 0),
                        ),
                    )
                }
            assertEquals(OpenCloudError.DirectoryListingTooLarge, failure.error)
        }
        assertTrue(path.listFiles().isNullOrEmpty())
    }

    @Test fun stalePurgePreservesAnotherActiveRefresh() {
        StagedRemoteFolder.create(cache).use { first ->
            val path = File(cache, "discovery-stage").listFiles().orEmpty().single { it.name.endsWith(".sqlite") }
            path.setLastModified(0)
            StagedRemoteFolder.create(cache).use { assertTrue(path.exists()) }
            first.finish()
        }
    }

    private suspend fun refresh(accountLease: () -> Boolean = { true }) {
        // Keep the production endpoint policy and DAV origin checks on an HTTPS URL while
        // routing only the fixture's transport to the local plain-HTTP MockWebServer.
        val localDavUrl = server.url("dav/")
        val localClient =
            OkHttpClient
                .Builder()
                .addInterceptor { chain ->
                    chain.proceed(
                        chain
                            .request()
                            .newBuilder()
                            .url(localDavUrl)
                            .build(),
                    )
                }.build()
        refreshFolder(
            FolderRefresh(
                store,
                RemoteDiscoveryClient(localClient),
                "account",
                space,
                null,
                "/",
                "Bearer synthetic",
                cache,
                accountLease,
            ),
        )
    }

    private fun envelope(responses: String) = "<d:multistatus xmlns:d=\"DAV:\">$responses</d:multistatus>"

    private fun root(extra: String = "") = response("/dav/", "<d:resourcetype><d:collection/></d:resourcetype>$extra")

    private fun child(name: String) =
        response(
            "/dav/$name",
            "<oc:fileid xmlns:oc=\"http://owncloud.org/ns\">$name</oc:fileid>" +
                "<d:getcontentlength>1</d:getcontentlength>",
        )

    private fun response(
        href: String,
        properties: String,
    ) = "<d:response><d:href>$href</d:href><d:propstat><d:prop>$properties</d:prop>" +
        "<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"

    private fun File.containsAscii(text: String): Boolean {
        val needle = text.toByteArray(Charsets.US_ASCII)
        inputStream().buffered().use { input ->
            val buffer = ByteArray(64 * 1024)
            var matched = 0
            while (true) {
                val count = input.read(buffer)
                if (count < 0) return false
                repeat(count) { index ->
                    matched =
                        if (buffer[index] == needle[matched]) {
                            matched + 1
                        } else if (buffer[index] == needle[0]) {
                            1
                        } else {
                            0
                        }
                    if (matched == needle.size) return true
                }
            }
        }
    }
}
