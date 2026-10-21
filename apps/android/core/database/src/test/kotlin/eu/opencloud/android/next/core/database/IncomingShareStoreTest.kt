package eu.opencloud.android.next.core.database

import androidx.room.Room
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class IncomingShareStoreTest {
    private val context = RuntimeEnvironment.getApplication()
    private val database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
    private val store = IncomingShareStore(database)
    private val account = AccountEntity("account", "https://example.test", "user", "User", "BASIC", false)

    @Before fun seed() = runBlocking { database.accountDao().upsert(account) }

    @After fun close() {
        database.close()
    }

    @Test fun `newest completed inventory wins and tokens cannot be replayed`() =
        runBlocking {
            val old = store.beginRefresh(account.id)
            val current = store.beginRefresh(account.id)
            assertTrue(store.replace(account.id, current, listOf(row("new"))))
            assertFalse(store.replace(account.id, old, listOf(row("old"))))
            assertFalse(store.replace(account.id, current, emptyList()))
            assertEquals(listOf("new"), store.list(account.id).map { it.id })
        }

    @Test fun `invalid replacement preserves inventory and valid empty snapshot clears it`() =
        runBlocking {
            store.replace(account.id, store.beginRefresh(account.id), listOf(row("kept")))
            val token = store.beginRefresh(account.id)
            assertThrows(IllegalArgumentException::class.java) {
                runBlocking { store.replace(account.id, token, listOf(row("duplicate"), row("duplicate"))) }
            }
            assertEquals("kept", store.list(account.id).single().id)
            assertTrue(store.replace(account.id, token, emptyList()))
            assertTrue(store.list(account.id).isEmpty())
        }

    @Test fun `removal cascades inventory and invalidates old refresh even if account ID is reused`() =
        runBlocking {
            store.replace(account.id, store.beginRefresh(account.id), listOf(row("kept")))
            val token = store.beginRefresh(account.id)
            FileBrowserStore(database).removeAccount(account.id)
            assertTrue(store.list(account.id).isEmpty())
            database.accountDao().upsert(account)
            assertFalse(store.replace(account.id, token, listOf(row("stale"))))
        }

    @Test fun `refresh cannot overwrite another account or inactive account`() =
        runBlocking {
            database.accountDao().upsert(account.copy(id = "other"))
            val token = store.beginRefresh(account.id)
            assertThrows(IllegalArgumentException::class.java) {
                runBlocking { store.replace(account.id, token, listOf(row("wrong").copy(accountId = "other"))) }
            }
            database.accountDao().upsert(account.copy(isActive = false))
            assertFalse(store.replace(account.id, token, listOf(row("inactive"))))
            assertTrue(store.list("other").isEmpty())
        }

    private fun row(id: String) = IncomingShareEntity(account.id, id, "remote-$id", id, true, null, "{}")

    @Test fun `inventory and refresh generations survive reopening the database`() =
        runBlocking {
            val name = "incoming-reopen.db"
            context.deleteDatabase(name)
            var disk = Room.databaseBuilder(context, FileBrowserDatabase::class.java, name).build()
            try {
                disk.accountDao().upsert(account)
                val initial = IncomingShareStore(disk)
                initial.replace(account.id, initial.beginRefresh(account.id), listOf(row("kept")))
                val pending = initial.beginRefresh(account.id)
                disk.close()
                disk = Room.databaseBuilder(context, FileBrowserDatabase::class.java, name).build()
                val reopened = IncomingShareStore(disk)
                assertEquals("kept", reopened.list(account.id).single().id)
                val newer = reopened.beginRefresh(account.id)
                assertFalse(reopened.replace(account.id, pending, listOf(row("stale"))))
                assertTrue(reopened.replace(account.id, newer, listOf(row("new"))))
            } finally {
                disk.close()
                context.deleteDatabase(name)
            }
        }

    @Test fun `ordinary account updates preserve the inventory and active refresh`() =
        runBlocking {
            store.replace(account.id, store.beginRefresh(account.id), listOf(row("kept")))
            val token = store.beginRefresh(account.id)
            database.accountDao().upsert(account.copy(displayName = "Updated name"))
            assertEquals("kept", store.list(account.id).single().id)
            assertTrue(store.replace(account.id, token, listOf(row("new"))))
        }
}
