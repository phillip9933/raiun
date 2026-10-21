package eu.opencloud.android.next.core.sync

import androidx.room.Room
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.IOException

@RunWith(RobolectricTestRunner::class)
class ExternalFileFreshnessTest {
    private val context = RuntimeEnvironment.getApplication()
    private val database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
    private val store = FileBrowserStore(database)
    private val file =
        ResourceEntity(
            "a",
            "s",
            "r",
            null,
            "/notes",
            "notes",
            ResourceKind.FILE,
            "text/plain",
            10,
            "\"old\"",
            0,
            0,
            hasLocalCopy = true,
            localPath = "/cached",
        )

    @Before fun seed() =
        runBlocking {
            database.accountDao().upsert(AccountEntity("a", "https://example.test", "u", "User", "BASIC", false))
            database.spaceDao().insert(
                SpaceEntity(
                    "a",
                    "s",
                    "Personal",
                    "personal",
                    null,
                    null,
                    "root",
                    "https://example.test/remote.php/dav/spaces/s",
                    null,
                    null,
                ),
            )
            database.resourceDao().insert(file)
        }

    @After fun close() = database.close()

    @Test fun `online open uses changed server metadata even when old bytes are cached`() =
        runBlocking {
            val freshness =
                ExternalFileFreshness(context, store, { true }) { _, _ ->
                    database.resourceDao().upsert(file.copy(eTag = "\"new\"", hasLocalCopy = false, localPath = null))
                }
            val current = freshness.current(file) { true }
            assertEquals("\"new\"", current.eTag)
            assertFalse(current.hasLocalCopy)
        }

    @Test fun `online refresh failure never silently returns old cached content`() {
        val freshness = ExternalFileFreshness(context, store, { true }) { _, _ -> throw IOException("offline server") }
        assertThrows(IOException::class.java) { runBlocking { freshness.current(file) { true } } }
    }

    @Test fun `offline open keeps downloaded copy without a network attempt`() =
        runBlocking {
            val freshness =
                ExternalFileFreshness(context, store, { false }) { _, _ -> error("must not refresh offline") }
            assertEquals(file, freshness.current(file) { true })
        }

    @Test fun `revoked app access stops before network access`() {
        val freshness = ExternalFileFreshness(context, store, { true }) { _, _ -> error("must not refresh locked") }
        assertThrows(IllegalStateException::class.java) { runBlocking { freshness.current(file) { false } } }
    }

    @Test fun `online copies without strong validators are invalidated`() =
        runBlocking {
            for (tag in listOf(null, "W/\"weak\"")) {
                val cached = file.copy(eTag = tag, offlinePinned = true)
                database.resourceDao().upsert(cached)
                val freshness = ExternalFileFreshness(context, store, { true }) { _, _ -> }
                val current = freshness.current(cached) { true }
                assertFalse(current.hasLocalCopy)
                assertEquals(null, current.localPath)
                assertEquals(true, current.offlinePinned)
            }
        }
}
