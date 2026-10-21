package eu.opencloud.android.next.core.sync

import androidx.room.Room
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.IncomingShareStore
import eu.opencloud.android.next.core.network.IncomingSharedItem
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.SharedFolderAccess
import eu.opencloud.android.next.core.network.SharedFolderResolution
import eu.opencloud.android.next.core.network.SharedRemoteItem
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class IncomingShareAccessRepositoryTest {
    private val database =
        Room
            .inMemoryDatabaseBuilder(
                RuntimeEnvironment.getApplication(),
                FileBrowserDatabase::class.java,
            ).build()
    private val store = IncomingShareStore(database)
    private val account = AccountEntity("a", "https://example.test", "user", "User", "BASIC", false)
    private val item =
        IncomingSharedItem("share", SharedRemoteItem("remote", "Folder", folder = JsonObject(emptyMap())))
    private val discovery = IncomingShareRepository(store) { listOf(item) }

    @Before fun seed() =
        runBlocking {
            database.accountDao().upsert(account)
            discovery.refresh(account.id)
            Unit
        }

    @After fun close() {
        database.close()
    }

    @Test fun `fresh access retains its share identity and independent server permissions`() =
        runBlocking {
            val resolved =
                SharedFolderResolution.Resolved(
                    "drive",
                    "remote",
                    "https://example.test/dav/shared/",
                    SharedFolderAccess(setOf("libre.graph/driveItem/children/read")),
                )
            val repository =
                IncomingShareAccessRepository(store) { captured, incoming ->
                    assertEquals(account, captured)
                    assertEquals(item, incoming)
                    resolved
                }
            val access = requireNotNull(repository.resolve(account.id, item.id))
            assertEquals(item.id, access.share.id)
            assertEquals(resolved, access.resolution)
            assertTrue(repository.isCurrent(access))
        }

    @Test fun `damaged or mismatched saved metadata fails safely without a network request`() =
        runBlocking {
            val row = store.list(account.id).single()
            val repository = IncomingShareAccessRepository(store) { _, _ -> error("must not fetch") }
            for (metadata in listOf("private invalid payload", row.metadataJson.replace("\"remote\"", "\"wrong\""))) {
                store.replace(account.id, store.beginRefresh(account.id), listOf(row.copy(metadataJson = metadata)))
                val failure =
                    assertThrows(OpenCloudException::class.java) {
                        runBlocking { repository.resolve(account.id, item.id) }
                    }
                assertEquals(OpenCloudError.InvalidResponse, failure.error)
                assertNull(failure.cause)
            }
        }

    @Test fun `removing and readding identical account and inventory invalidates suspended access`() =
        runBlocking {
            val started = CompletableDeferred<Unit>()
            val finish = CompletableDeferred<Unit>()
            val repository =
                IncomingShareAccessRepository(store) { _, _ ->
                    started.complete(Unit)
                    finish.await()
                    SharedFolderResolution.Unavailable
                }
            val pending = async { repository.resolve(account.id, item.id) }
            started.await()
            FileBrowserStore(database).removeAccount(account.id)
            database.accountDao().upsert(account)
            discovery.refresh(account.id)
            finish.complete(Unit)
            assertNull(pending.await())
        }

    @Test fun `refresh start and identical completed refresh both invalidate prior access`() =
        runBlocking {
            val repository = IncomingShareAccessRepository(store) { _, _ -> SharedFolderResolution.Unavailable }
            val first = requireNotNull(repository.resolve(account.id, item.id))
            assertTrue(repository.isCurrent(first))
            val refresh = store.beginRefresh(account.id)
            assertFalse(repository.isCurrent(first))
            val during = requireNotNull(repository.resolve(account.id, item.id))
            store.replace(account.id, refresh, store.list(account.id))
            assertFalse(repository.isCurrent(during))
        }

    @Test fun `other account refresh leaves access valid while local account changes invalidate it`() =
        runBlocking {
            val repository = IncomingShareAccessRepository(store) { _, _ -> SharedFolderResolution.Unavailable }
            val access = requireNotNull(repository.resolve(account.id, item.id))
            database.accountDao().upsert(account.copy(id = "other"))
            discovery.refresh("other")
            assertTrue(repository.isCurrent(access))
            database.accountDao().upsert(account.copy(serverUrl = "https://changed.example"))
            assertFalse(repository.isCurrent(access))
        }

    @Test fun `missing accounts or shares skip network and server unavailability stays distinct from staleness`() =
        runBlocking {
            var calls = 0
            val repository =
                IncomingShareAccessRepository(store) { _, _ ->
                    calls++
                    SharedFolderResolution.Unavailable
                }
            assertNull(repository.resolve("missing", item.id))
            assertNull(repository.resolve(account.id, "missing"))
            assertEquals(0, calls)
            assertEquals(SharedFolderResolution.Unavailable, repository.resolve(account.id, item.id)?.resolution)
            assertEquals(1, calls)
        }

    @Test fun `cancellation remains cancellation and does not change saved discovery`() =
        runBlocking {
            val before = store.list(account.id)
            val repository = IncomingShareAccessRepository(store) { _, _ -> throw CancellationException() }
            assertThrows(CancellationException::class.java) {
                runBlocking { repository.resolve(account.id, item.id) }
            }
            assertEquals(before, store.list(account.id))
        }
}
