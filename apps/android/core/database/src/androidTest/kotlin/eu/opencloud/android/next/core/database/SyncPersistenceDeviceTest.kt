package eu.opencloud.android.next.core.database

import android.os.SystemClock
import android.util.Log
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import eu.opencloud.android.next.core.model.ResourceKind
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.time.Duration.Companion.minutes

@RunWith(AndroidJUnit4::class)
class SyncPersistenceDeviceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var database: FileBrowserDatabase
    private val root =
        ResourceEntity(
            "a",
            "s",
            "root",
            null,
            "/root",
            "root",
            ResourceKind.FOLDER,
            null,
            0,
            null,
            0,
            0,
            offlinePinned = true,
        )

    @Before fun openDatabase() {
        context.deleteDatabase(NAME)
        database = open()
    }

    @After fun closeDatabase() {
        database.close()
        context.deleteDatabase(NAME)
    }

    private fun open() =
        Room
            .databaseBuilder(context, FileBrowserDatabase::class.java, NAME)
            .setJournalMode(RoomDatabase.JournalMode.WRITE_AHEAD_LOGGING)
            .build()

    @Test fun walReopenRetainsTraversalAndFavoriteCursor() =
        runTest {
            val store = FileBrowserStore(database)
            database.accountDao().upsert(AccountEntity("a", "https://cloud.example", "user", "User", "BASIC", false))
            database.resourceDao().insert(root)
            database.resourceDao().insertAll((1..258).map { file(root, it) })
            val queue = OfflineTraversalStore(database)
            val run = queue.start(root)
            queue.expand(run, OfflineNodeEntity(run.id, root.remoteId, "DISCOVERED"))
            val node = requireNotNull(queue.dao.next(run.id))
            val cursor = store.advanceFavoriteCursor("a", "s", "file", null)
            database.openHelper.writableDatabase.query("PRAGMA journal_mode").use {
                assertTrue(it.moveToFirst())
                assertEquals("wal", it.getString(0))
            }
            database.close()
            database = open()
            val reopened = OfflineTraversalStore(database)
            assertEquals(cursor, FileBrowserStore(database).favoriteCursor("a"))
            assertEquals(129, reopened.dao.count(run.id))
            reopened.expand(run, node)
            assertEquals(257, reopened.dao.count(run.id))
        }

    @Test fun hundredThousandItemsUseBoundedChildPages() =
        runTest(timeout = 5.minutes) {
            val started = SystemClock.elapsedRealtime()
            database.resourceDao().insert(root)
            val folders =
                (1..100).map { index ->
                    root.copy(
                        remoteId = "dir-$index",
                        parentId = "root",
                        path = "/root/dir-$index",
                        name = "dir-$index",
                        offlinePinned = false,
                    )
                }
            database.resourceDao().insertAll(folders)
            folders.forEach { folder -> database.resourceDao().insertAll((1..999).map { file(folder, it) }) }
            val queue = OfflineTraversalStore(database)
            val run = queue.start(root)
            var pages = 0
            (listOf(root) + folders).forEach { folder ->
                var node = OfflineNodeEntity(run.id, folder.remoteId, "DISCOVERED")
                do {
                    val children = queue.dao.children("a", "s", folder.remoteId, node.lastChildId)
                    assertTrue(children.size <= 128)
                    queue.expand(run, node)
                    pages++
                    node = node.copy(lastChildId = children.lastOrNull()?.remoteId ?: node.lastChildId)
                } while (children.isNotEmpty())
            }
            assertEquals(100_001, queue.dao.count(run.id))
            Log.i(
                "OpenCloudDeviceTests",
                "100000-item queue: pages=$pages elapsedMs=${SystemClock.elapsedRealtime() - started}",
            )
        }

    private fun file(
        parent: ResourceEntity,
        index: Int,
    ) = parent.copy(
        remoteId = "${parent.remoteId}-file-$index",
        parentId = parent.remoteId,
        path = "${parent.path}/file-$index",
        name = "file-$index",
        kind = ResourceKind.FILE,
        offlinePinned = false,
    )

    private companion object {
        const val NAME = "sync-device-test.db"
    }
}
