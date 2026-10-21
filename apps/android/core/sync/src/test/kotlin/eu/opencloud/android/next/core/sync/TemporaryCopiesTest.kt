package eu.opencloud.android.next.core.sync

import androidx.room.Room
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.model.resourceCacheDirectory
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File

@RunWith(RobolectricTestRunner::class)
class TemporaryCopiesTest {
    @Test fun expiryPreservesPinsDescendantsRecentCopiesAndActiveDownloads() =
        runTest {
            val context = RuntimeEnvironment.getApplication()
            val db = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
            val store = FileBrowserStore(db)
            val now = 100_000_000L
            try {
                db.accountDao().upsert(AccountEntity("a", "https://cloud.example", "u", "User", "BASIC", false))

                db.spaceDao().insert(
                    eu.opencloud.android.next.core.database.SpaceEntity(
                        "a",
                        "s",
                        "Personal",
                        "personal",
                        null,
                        null,
                        "root",
                        null,
                        null,
                        null,
                    ),
                )

                suspend fun cached(
                    id: String,
                    path: String = "/$id",
                    pinned: Boolean = false,
                    used: Long = 1L,
                ): ResourceEntity {
                    val folder = resourceCacheDirectory(context.filesDir, "a", "s").apply { mkdirs() }
                    val file =
                        File(folder, id).apply {
                            writeText("data")
                            setLastModified(used)
                        }
                    val resource =
                        ResourceEntity(
                            "a",
                            "s",
                            id,
                            null,
                            path,
                            id,
                            ResourceKind.FILE,
                            null,
                            4,
                            "v1",
                            0,
                            0,
                            hasLocalCopy = true,
                            localPath = file.absolutePath,
                            offlinePinned = pinned,
                        )
                    db.resourceDao().insert(resource)
                    return resource
                }
                val expired = cached("expired")
                val pinned = cached("pin", pinned = true)
                db.resourceDao().insert(
                    pinned.copy(
                        accountId = "other",
                        remoteId = "root",
                        path = "/",
                        kind = ResourceKind.FOLDER,
                        localPath = null,
                        hasLocalCopy = false,
                    ),
                )
                val recent = cached("recent", used = now)
                val child = cached("child", path = "/folder/child")
                val similar = cached("similar", path = "/folder-other/file")
                val active = cached("active")
                val reading = cached("reading")
                val readingFile = File(requireNotNull(reading.localPath))
                val reader = LocalCopyLease.acquire(readingFile)
                db.resourceDao().insert(
                    pinned.copy(
                        remoteId = "folder",
                        name = "folder",
                        path = "/folder",
                        kind = ResourceKind.FOLDER,
                        hasLocalCopy = false,
                        localPath = null,
                    ),
                )
                db.transferDao().insert(
                    TransferEntity(
                        "t",
                        "a",
                        "s",
                        active.remoteId,
                        "DOWNLOAD",
                        null,
                        active.path,
                        active.name,
                        null,
                        4,
                        createdAtEpochMillis = 0,
                        updatedAtEpochMillis = 0,
                    ),
                )
                expireTemporaryCopies(context, store, 0, now)
                assertTrue(File(requireNotNull(expired.localPath)).exists())
                expireTemporaryCopies(context, store, 1, now)
                listOf(expired, similar).forEach {
                    assertFalse(File(requireNotNull(it.localPath)).exists())
                    assertFalse(requireNotNull(store.resource("a", "s", it.remoteId)).hasLocalCopy)
                }
                listOf(pinned, recent, child, active, reading).forEach {
                    assertTrue(File(requireNotNull(it.localPath)).exists())
                    assertTrue(requireNotNull(store.resource("a", "s", it.remoteId)).hasLocalCopy)
                }
                org.junit.Assert.assertEquals(1, clearTemporaryCopies(context, store))
                assertFalse(File(requireNotNull(recent.localPath)).exists())
                listOf(pinned, child, active, reading).forEach {
                    assertTrue(File(requireNotNull(it.localPath)).exists())
                    assertTrue(requireNotNull(store.resource("a", "s", it.remoteId)).hasLocalCopy)
                }
                reader.close()
                reader.close()
                org.junit.Assert.assertEquals(1, clearTemporaryCopies(context, store))
                assertFalse(readingFile.exists())
            } finally {
                db.close()
            }
        }
}
