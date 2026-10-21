package eu.opencloud.android.next.core.sync

import androidx.room.Room
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.IncomingShareStore
import eu.opencloud.android.next.core.network.IncomingSharedItem
import eu.opencloud.android.next.core.network.SharedRemoteItem
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class IncomingShareRepositoryTest {
    private val database =
        Room
            .inMemoryDatabaseBuilder(
                RuntimeEnvironment.getApplication(),
                FileBrowserDatabase::class.java,
            ).build()
    private val store = IncomingShareStore(database)
    private val item =
        IncomingSharedItem("share", SharedRemoteItem("remote", "Folder", folder = JsonObject(emptyMap())))

    @Before fun seed() =
        runBlocking {
            database.accountDao().upsert(
                AccountEntity("account", "https://example.test", "user", "User", "BASIC", false),
            )
        }

    @After fun close() {
        database.close()
    }

    @Test fun cleanupAfterCompletePublication() =
        runBlocking {
            val calls = mutableListOf<String>()
            val repository =
                IncomingShareRepository(store, afterPublication = { account ->
                    assertEquals(listOf("share"), store.list(account).map { it.id })
                    calls.add(account)
                }) { listOf(item) }
            assertEquals(true, repository.refresh("account"))
            assertEquals(listOf("account"), calls)
            val failed = IncomingShareRepository(store, afterPublication = { calls.add(it) }) { error("unavailable") }
            assertThrows(IllegalStateException::class.java) { runBlocking { failed.refresh("account") } }
            val cancelled =
                IncomingShareRepository(store, afterPublication = { calls.add(it) }) {
                    throw CancellationException()
                }
            assertThrows(CancellationException::class.java) { runBlocking { cancelled.refresh("account") } }
            assertEquals(listOf("account"), calls)
        }

    @Test fun supersededPublicationDoesNotScheduleCleanup() =
        runBlocking {
            val calls = mutableListOf<String>()
            val repository =
                IncomingShareRepository(store, afterPublication = { calls.add(it) }) {
                    IncomingShareRepository(store) { emptyList() }.refresh("account")
                    listOf(item)
                }
            assertEquals(false, repository.refresh("account"))
            assertEquals(emptyList<String>(), calls)
            assertEquals(emptyList<Any>(), store.list("account"))
        }

    @Test fun `failed discovery and cancellation preserve the previous complete snapshot`() =
        runBlocking {
            IncomingShareRepository(store) { listOf(item) }.refresh("account")
            val original = store.list("account")
            assertThrows(IllegalStateException::class.java) {
                runBlocking { IncomingShareRepository(store) { error("network failure") }.refresh("account") }
            }
            assertThrows(CancellationException::class.java) {
                runBlocking { IncomingShareRepository(store) { throw CancellationException() }.refresh("account") }
            }
            assertEquals(original, store.list("account"))
        }

    @Test fun `unresolved roots and missing effective access remain unresolved in storage`() =
        runBlocking {
            IncomingShareRepository(store) { listOf(item) }.refresh("account")
            val saved = store.list("account").single()
            assertEquals("remote", saved.remoteId)
            assertEquals(true, saved.isFolder)
            assertNull(saved.webDavUrl)
            val decoded =
                kotlinx.serialization.json.Json
                    .decodeFromString<IncomingSharedItem>(saved.metadataJson)
            assertEquals(item, decoded)
            assertNull(decoded.effectiveActions)
        }
}
