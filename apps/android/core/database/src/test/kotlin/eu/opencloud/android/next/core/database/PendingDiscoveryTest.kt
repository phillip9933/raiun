package eu.opencloud.android.next.core.database

import androidx.room.Room
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class PendingDiscoveryTest {
    @Test fun `pending discovery survives reopen and old acknowledgement cannot discard a newer request`() =
        runTest {
            val context = RuntimeEnvironment.getApplication()
            val name = "discovery-reopen.db"
            context.deleteDatabase(name)

            fun open() =
                Room
                    .databaseBuilder(context, FileBrowserDatabase::class.java, name)
                    .setJournalMode(androidx.room.RoomDatabase.JournalMode.TRUNCATE)
                    .build()

            suspend fun withDatabase(block: suspend (FileBrowserDatabase) -> Unit) {
                val database = open()
                try {
                    block(database)
                } finally {
                    database.close()
                }
            }
            withDatabase { database ->
                val store = FileBrowserStore(database)
                database.accountDao().upsert(AccountEntity("a", "https://example.test", "user", "User", "BASIC", false))
                database.spaceDao().insert(
                    SpaceEntity(
                        "a",
                        "s",
                        "Space",
                        "project",
                        null,
                        null,
                        "root",
                        "https://example.test/dav",
                        null,
                        null,
                    ),
                )
                store.queueFolderRefresh("a", "s", null)
                val old = store.pendingDiscoveries().single()
                store.queueFolderRefresh("a", "s", null)
                store.acknowledgeDiscovery(old.revision)
                assertEquals(1, store.pendingDiscoveries().size)
                assertTrue(old.revision != store.pendingDiscoveries().single().revision)
            }
            withDatabase { database ->
                val store = FileBrowserStore(database)
                assertEquals("", store.pendingDiscoveries().single().folderKey)
                store.removeAccount("a")
                assertTrue(store.pendingDiscoveries().isEmpty())
                store.queueFolderRefresh("a", "s", null)
                assertTrue(store.pendingDiscoveries().isEmpty())
            }
            context.deleteDatabase(name)
        }
}
