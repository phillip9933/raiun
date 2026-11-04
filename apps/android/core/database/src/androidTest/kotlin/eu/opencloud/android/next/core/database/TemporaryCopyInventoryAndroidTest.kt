package eu.opencloud.android.next.core.database

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import eu.opencloud.android.next.core.model.ResourceKind
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID

/** Exercises Android's real SQLite file/transaction/cursor behavior rather than a host SQLite substitute. */
@RunWith(AndroidJUnit4::class)
class TemporaryCopyInventoryAndroidTest {
    @Test fun fileBackedOriginalInventoryTraverses390RowsAndClosesItsOwnStage() =
        runBlocking {
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            val suffix = UUID.randomUUID().toString()
            val sourceName = "temporary-copy-source-$suffix.sqlite"
            val directory = File(context.cacheDir, "temporary-copy-inventory-$suffix")
            val database = Room.databaseBuilder(context, FileBrowserDatabase::class.java, sourceName).build()
            try {
                val store = FileBrowserStore(database)
                database.accountDao().upsert(AccountEntity("a", "https://example.test", "u", "U", "BASIC", false))
                database.spaceDao().upsertAll(listOf(space("one"), space("two")))
                val originals =
                    (0 until 390).map { index ->
                        ResourceEntity(
                            accountId = "a",
                            spaceId = if (index % 2 == 0) "one" else "two",
                            remoteId = (index / 2).toString().padStart(4, '0'),
                            parentId = "root",
                            path = "/file$index",
                            name = "東京$index",
                            kind = ResourceKind.FILE,
                            mimeType = "text/plain",
                            sizeBytes = index.toLong(),
                            eTag = "etag-$index",
                            modifiedAtEpochMillis = index.toLong(),
                            createdAtEpochMillis = 42,
                            hasLocalCopy = true,
                            localPath = File(context.cacheDir, "synthetic-$index").path,
                        )
                    }
                database.resourceDao().insertAll(originals)
                val late = originals.first().copy(remoteId = "000-late", path = "/late", name = "Late")
                requireNotNull(store.temporaryCopies().capture("a", directory)).use { scope ->
                    assertTrue(directory.listFiles().orEmpty().any { it.extension == "sqlite" && it.length() > 0 })
                    database.resourceDao().insert(late)
                    var after: TemporaryCopyKey? = null
                    val seen = mutableListOf<ResourceEntity>()
                    var count = 0
                    while (true) {
                        val page = store.temporaryCopies().page(scope, after)
                        if (page.isEmpty()) break
                        assertTrue(page.size <= 128)
                        seen += page
                        page.forEach { expected ->
                            assertTrue(store.temporaryCopies().expire(scope, expected) { true })
                            count++
                        }
                        after = page.last().let { TemporaryCopyKey(it.spaceId, it.remoteId) }
                    }
                    assertEquals(390, count)
                    assertEquals(
                        originals.sortedWith(compareBy<ResourceEntity> { it.spaceId }.thenBy { it.remoteId }),
                        seen,
                    )
                    assertEquals(late, store.resource("a", "one", late.remoteId))
                }
                assertTrue(directory.listFiles().orEmpty().isEmpty())
            } finally {
                database.close()
                context.deleteDatabase(sourceName)
                directory.deleteRecursively()
            }
        }

    private fun space(id: String) = SpaceEntity("a", id, id, "personal", null, null, "root", null, null, null)

    @Test fun nativeOwnerLeasePreservesOldLiveStageAndUnlockedCrashFixtureIsReclaimed() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val directory = File(context.noBackupFilesDir, "temporary-copy-owner-${UUID.randomUUID()}")
        try {
            TemporaryCopyStage.create(directory).use { live ->
                assertTrue(live.file.setLastModified(1))
                assertTrue(File(live.file.path + ".owner").setLastModified(1))
                val abandoned = File(directory, "ordinary-inventory-${UUID.randomUUID()}.sqlite")
                abandoned.writeText("synthetic abandoned metadata")
                val owner = File(abandoned.path + ".owner")
                owner.writeText(TEMPORARY_COPY_OWNER_MARKER)
                assertTrue(abandoned.setLastModified(1))
                assertTrue(owner.setLastModified(1))
                cleanupStaleTemporaryCopyStages(directory)
                assertTrue(live.file.exists())
                assertTrue(File(live.file.path + ".owner").exists())
                assertFalse(abandoned.exists())
                assertFalse(owner.exists())
            }
            assertTrue(directory.listFiles().orEmpty().isEmpty())
        } finally {
            directory.deleteRecursively()
        }
    }
}
