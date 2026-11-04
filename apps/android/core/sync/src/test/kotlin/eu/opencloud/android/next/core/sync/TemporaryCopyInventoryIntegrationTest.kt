package eu.opencloud.android.next.core.sync

import android.content.Context
import android.content.ContextWrapper
import androidx.room.Room
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.database.temporaryCopies
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.model.resourceCacheDirectory
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File

@RunWith(RobolectricTestRunner::class)
class TemporaryCopyInventoryIntegrationTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun clearingAcrossSpacesDoesNotSkipRowsAfterDeletingEarlierPagesAndRetainsProtectedCopies() =
        runTest {
            fixture {
                val all = seedCopies()
                val pinned = all.first { it.spaceId == "sA" && it.remoteId == "r001" }.copy(offlinePinned = true)
                val child = all.first { it.spaceId == "sA" && it.remoteId == "r002" }.copy(path = "/kept/file")
                db.resourceDao().update(pinned)
                db.resourceDao().update(child)
                db.resourceDao().insert(
                    pinned.copy(
                        remoteId = "kept",
                        name = "kept",
                        path = "/kept",
                        kind = ResourceKind.FOLDER,
                        hasLocalCopy = false,
                        localPath = null,
                    ),
                )
                val downloading = all.first { it.spaceId == "sB" && it.remoteId == "r000" }
                db.transferDao().insert(
                    TransferEntity(
                        "download",
                        "a",
                        downloading.spaceId,
                        downloading.remoteId,
                        "DOWNLOAD",
                        null,
                        downloading.path,
                        downloading.name,
                        null,
                        4,
                        createdAtEpochMillis = 0,
                        updatedAtEpochMillis = 0,
                    ),
                )
                val reading = all.first { it.spaceId == "sB" && it.remoteId == "r128" }
                val external = File(temporary.root, "unrelated-data").apply { writeText("data") }
                val outside = cached("sC", "outside").copy(localPath = external.absolutePath)
                val wrongSize = cached("sC", "wrong-size").copy(sizeBytes = 5)
                db.resourceDao().update(outside)
                db.resourceDao().update(wrongSize)
                val held = LocalCopyLease.acquire(File(requireNotNull(reading.localPath)))
                try {
                    assertEquals(389, clearTemporaryCopies(context, store))
                    val preserved = setOf(pinned.key(), child.key(), downloading.key(), reading.key())
                    all.forEach { original ->
                        assertCopy(original, original.key() in preserved)
                    }
                    assertCopy(outside, true)
                    assertCopy(wrongSize, true)
                    listOf(pinned, child, downloading, reading, outside, wrongSize).forEach { expected ->
                        assertEquals(expected, store.resource("a", expected.spaceId, expected.remoteId))
                        assertEquals("data", File(requireNotNull(expected.localPath)).readText())
                    }
                    assertEquals("data", external.readText())
                    assertEquals(emptySet<String>(), inventoryFiles())
                } finally {
                    held.close()
                }
                assertEquals(1, clearTemporaryCopies(context, store))
                assertCopy(reading, false)
                listOf(pinned, child, downloading, outside, wrongSize).forEach { assertCopy(it, true) }
                assertEquals(emptySet<String>(), inventoryFiles())
            }
        }

    @Test fun expirationVisitsEverySpaceAndPreservesExactCutoffUntilExplicitClear() =
        runTest {
            fixture {
                val now = 100_000_000L
                val cutoff = now - 3_600_000L
                val all = seedCopies()
                val retained = all.filter { it.remoteId in setOf("r050", "r051") }
                retained.forEach { row ->
                    assertTrue(
                        File(requireNotNull(row.localPath)).setLastModified(
                            if (row.remoteId ==
                                "r050"
                            ) {
                                now
                            } else {
                                cutoff
                            },
                        ),
                    )
                }
                expireTemporaryCopies(context, store, 0, now)
                all.forEach { assertCopy(it, true) }
                assertEquals(emptySet<String>(), inventoryFiles())

                expireTemporaryCopies(context, store, 1, now)
                all.forEach { assertCopy(it, it in retained) }
                assertEquals(emptySet<String>(), inventoryFiles())
                assertEquals(6, clearTemporaryCopies(context, store))
                all.forEach { assertCopy(it, false) }
                assertEquals(emptySet<String>(), inventoryFiles())
            }
        }

    @Test fun maintenanceClosesOnlyItsSnapshotAndOldDescriptorsCannotDeleteANewerCopy() =
        runTest {
            fixture {
                val original = cached("sA", "original")
                val sentinel =
                    File(
                        inventoryDirectory.apply { mkdirs() },
                        "foreign-recovery.txt",
                    ).apply { writeText("preserve") }
                val captured = requireNotNull(store.temporaryCopies().capture("a", inventoryDirectory))
                try {
                    val before = inventoryFiles()
                    assertTrue(before.size > 1)
                    assertEquals(listOf(original), store.temporaryCopies().page(captured))
                    assertEquals(1, clearTemporaryCopies(context, store))
                    assertCopy(original, false)
                    assertEquals(before, inventoryFiles())
                    assertEquals("preserve", sentinel.readText())
                    assertEquals(listOf(original), store.temporaryCopies().page(captured))

                    val replacementFile =
                        File(
                            resourceCacheDirectory(context.filesDir, "a", "sA"),
                            "new-version",
                        ).apply { writeText("next") }
                    val replacement = original.copy(eTag = "v2", localPath = replacementFile.absolutePath)
                    db.resourceDao().update(replacement)
                    var deleteCalled = false
                    assertFalse(
                        store.temporaryCopies().expire(captured, original) {
                            deleteCalled = true
                            replacementFile.delete()
                        },
                    )
                    assertFalse(deleteCalled)
                    assertCopy(replacement, true)
                    assertEquals("next", replacementFile.readText())
                } finally {
                    captured.close()
                    captured.close()
                }
                assertEquals(setOf(sentinel.name), inventoryFiles())
                assertEquals("preserve", sentinel.readText())
            }
        }

    private suspend fun fixture(block: suspend Fixture.() -> Unit) {
        val files = temporary.newFolder("files")
        val noBackup = temporary.newFolder("no-backup")
        val context =
            object : ContextWrapper(RuntimeEnvironment.getApplication()) {
                override fun getFilesDir(): File = files

                override fun getNoBackupFilesDir(): File = noBackup
            }
        val db = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
        try {
            db.accountDao().upsert(AccountEntity("a", "https://cloud.example", "u", "User", "BASIC", false))
            listOf("sA", "sB", "sC").forEach { space ->
                db.spaceDao().insert(
                    SpaceEntity("a", space, space, "personal", null, null, "root-$space", null, null, null),
                )
            }
            Fixture(context, db).block()
        } finally {
            db.close()
        }
    }

    private class Fixture(
        val context: Context,
        val db: FileBrowserDatabase,
    ) {
        val store = FileBrowserStore(db)
        val inventoryDirectory = File(context.noBackupFilesDir, "ordinary-temp-inventory")

        suspend fun seedCopies(): List<ResourceEntity> =
            buildList {
                for (space in listOf("sA", "sB", "sC")) {
                    repeat(131) { index -> add(cached(space, "r${index.toString().padStart(3, '0')}")) }
                }
            }

        suspend fun cached(
            space: String,
            id: String,
        ): ResourceEntity {
            val file =
                File(resourceCacheDirectory(context.filesDir, "a", space).apply { mkdirs() }, id).apply {
                    writeText("data")
                    check(setLastModified(1L))
                }
            val row =
                ResourceEntity(
                    "a",
                    space,
                    id,
                    null,
                    "/$id",
                    id,
                    ResourceKind.FILE,
                    null,
                    4,
                    "v1",
                    0,
                    0,
                    hasLocalCopy = true,
                    localPath = file.absolutePath,
                )
            db.resourceDao().insert(row)
            return row
        }

        suspend fun assertCopy(
            original: ResourceEntity,
            retained: Boolean,
        ) {
            val current = requireNotNull(store.resource(original.accountId, original.spaceId, original.remoteId))
            assertEquals("${original.spaceId}/${original.remoteId}", retained, current.hasLocalCopy)
            val file = File(requireNotNull(original.localPath))
            assertEquals(file.path, retained, file.exists())
            if (retained) {
                assertEquals(original.localPath, current.localPath)
                assertEquals(4L, file.length())
            } else {
                assertEquals(original.copy(hasLocalCopy = false, localPath = null), current)
            }
        }

        fun inventoryFiles(): Set<String> =
            inventoryDirectory
                .listFiles()
                .orEmpty()
                .map { it.name }
                .toSet()
    }
}

private fun ResourceEntity.key(): Pair<String, String> = spaceId to remoteId
