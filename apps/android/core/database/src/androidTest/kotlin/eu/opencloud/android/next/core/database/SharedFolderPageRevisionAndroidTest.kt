package eu.opencloud.android.next.core.database

import androidx.room.Room
import androidx.room.withTransaction
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Exercises temporary revision triggers against the device SQLite engine. */
@RunWith(AndroidJUnit4::class)
class SharedFolderPageRevisionAndroidTest {
    private lateinit var database: FileBrowserDatabase
    private val account = AccountEntity("revision", "https://example.test", "synthetic", "Synthetic", "BASIC", false)
    private val scope =
        SharedFolderScopeEntity("revision", "scope", "share", "drive", "root", "https://example.test/dav/")
    private val share = IncomingShareEntity("revision", "share", "root", "Shared", true, null, "{}")

    @Before fun open() =
        runBlocking {
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
            database.accountDao().upsert(account)
            database.incomingShareDao().insert(listOf(share))
            database.sharedFolderCacheDao().saveScope(scope)
        }

    @After fun close() = database.close()

    @Test fun sameCountReorderingInvalidatesPinnedRevisionAndRollbackPreservesIt() =
        runBlocking {
            val dao = database.sharedFolderCacheDao()
            val initial = listOf(entry("one", "alpha"), entry("two", "beta"))
            database.withTransaction {
                ensureSharedFolderPageRevisionTracking(database.openHelper.writableDatabase)
                dao.insert(initial)
                dao.markPage(SharedFolderCachedPage(scope.accountId, scope.scopeId, "/"))
            }
            val first = readSnapshot()
            assertEquals(2, first.first)
            val firstRevision = first.second
            val lease = requireNotNull(IncomingShareStore(database).beginAccess(account.id, share.id))
            val cache = SharedFolderCacheStore(database)
            val pinned = requireNotNull(cache.captureDisplaySnapshot(lease, scope, "/"))
            assertEquals(first.first, pinned.total)
            assertEquals(firstRevision, pinned.revision)

            database.withTransaction {
                ensureSharedFolderPageRevisionTracking(database.openHelper.writableDatabase)
                dao.clearChildren(scope.accountId, scope.scopeId, "/")
                dao.insert(listOf(entry("one", "zeta"), entry("two", "eta")))
                dao.markPage(SharedFolderCachedPage(scope.accountId, scope.scopeId, "/"))
            }
            val reordered = readSnapshot()
            assertEquals(2, reordered.first)
            assertNotEquals(firstRevision, reordered.second)
            assertEquals(listOf("eta", "zeta"), dao.displayPage(scope.accountId, scope.scopeId, "/", 0).map { it.name })
            assertNull(cache.readDisplayPageAtRevision(lease, scope, "/", 0, pinned.revision))

            try {
                database.withTransaction {
                    ensureSharedFolderPageRevisionTracking(database.openHelper.writableDatabase)
                    dao.markPage(SharedFolderCachedPage(scope.accountId, scope.scopeId, "/"))
                    assertEquals(reordered.second + 1, currentRevision())
                    error("synthetic rollback")
                }
            } catch (_: IllegalStateException) {
                // Expected: the marker insert and TEMP-trigger counter update roll back together.
            }
            assertEquals(reordered.second, readSnapshot().second)
            assertNull(readRevision("missing"))
            assertTrue(reordered.second > firstRevision)
        }

    private suspend fun readSnapshot(): Pair<Int, Long> =
        database.withTransaction {
            val sql = database.openHelper.writableDatabase
            ensureSharedFolderPageRevision(sql, scope.accountId, scope.scopeId, "/")
            database.sharedFolderCacheDao().childCount(scope.accountId, scope.scopeId, "/") to
                requireNotNull(readSharedFolderPageRevision(sql, scope.accountId, scope.scopeId, "/"))
        }

    private suspend fun currentRevision(): Long =
        requireNotNull(
            readSharedFolderPageRevision(database.openHelper.writableDatabase, scope.accountId, scope.scopeId, "/"),
        )

    private suspend fun readRevision(path: String): Long? =
        database.withTransaction {
            val sql = database.openHelper.writableDatabase
            ensureSharedFolderPageRevision(sql, scope.accountId, scope.scopeId, path)
            readSharedFolderPageRevision(sql, scope.accountId, scope.scopeId, path)
        }

    private fun entry(
        remoteId: String,
        name: String,
    ) = SharedFolderEntry(
        scope.accountId,
        scope.scopeId,
        remoteId,
        "/",
        "/$name",
        name,
        false,
        "text/plain",
        1,
        null,
        0,
        0,
    )
}
