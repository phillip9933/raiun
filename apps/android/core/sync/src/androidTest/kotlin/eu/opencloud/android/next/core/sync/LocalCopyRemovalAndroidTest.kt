package eu.opencloud.android.next.core.sync

import android.content.ContextWrapper
import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.work.Configuration
import androidx.work.WorkManager
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.LocalCopyRemovalDecision
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.database.localCopyRemovals
import eu.opencloud.android.next.core.database.vaultOfflineGroups
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.model.resourceCacheDirectory
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.nio.file.Files
import java.util.UUID

/** Actual Android Room/private staging/canonical file leases; no server or production account is involved. */
@RunWith(AndroidJUnit4::class)
class LocalCopyRemovalAndroidTest {
    @Test fun nativeSingleReaderAndBulkPagesKeepLeasedBytesUntilExplicitRetry() {
        runBlocking {
            fixture { f ->
                val originals =
                    (0 until 130).map { number ->
                        f.cached(
                            "r${number / 2}",
                            if (number % 2 == 0) "one" else "two",
                        )
                    }
                val busy = originals.last().copy(offlinePinned = true)
                f.db.resourceDao().update(busy)
                val folder =
                    busy.copy(
                        remoteId = "folder",
                        path = "/folder",
                        name = "folder",
                        kind = ResourceKind.FOLDER,
                        hasLocalCopy = false,
                        localPath = null,
                    )
                f.db.resourceDao().insert(folder)
                val file = File(busy.localPath!!)
                // /data/data is a bind mount on newer Android, not a canonical-path alias.
                // Use an actual private symlink to exercise the reader's canonical lease key on both APIs.
                val aliased = File(f.context.noBackupFilesDir, "reader-alias")
                Files.createSymbolicLink(aliased.toPath(), file.toPath())
                assertEquals(file.canonicalFile, aliased.canonicalFile)
                val lease = LocalCopyLease.acquire(aliased)
                try {
                    val single =
                        assertThrows(OpenCloudException::class.java) { runBlocking { f.operations.remove(busy) } }
                    assertEquals(OpenCloudError.LocalCopiesRetained, single.error)
                    assertEquals(busy, f.store.resource("a", busy.spaceId, busy.remoteId))
                    val bulk =
                        assertThrows(OpenCloudException::class.java) { runBlocking { f.operations.removeAll("a") } }
                    assertEquals(OpenCloudError.LocalCopiesRetained, bulk.error)
                    originals.dropLast(1).forEach { assertFalse(File(it.localPath!!).exists()) }
                    assertEquals(busy.copy(offlinePinned = false), f.store.resource("a", busy.spaceId, busy.remoteId))
                    assertEquals("data", file.readText())
                    assertFalse(f.store.resource("a", folder.spaceId, "folder")!!.offlinePinned)
                } finally {
                    lease.close()
                }
                f.operations.remove(busy)
                assertFalse(file.exists())
                assertFalse(f.store.resource("a", busy.spaceId, busy.remoteId)!!.hasLocalCopy)
                assertTrue(
                    File(f.context.noBackupFilesDir, "ordinary-removal-inventory").listFiles().orEmpty().isEmpty(),
                )
            }
        }
    }

    @Test fun nativeNewAncestorAndIdenticalReplacementAccountRefuseOldDeletionAuthority() {
        runBlocking {
            fixture { f ->
                val original = f.cached("file").copy(path = "/outer/inner/file")
                f.db.resourceDao().update(original)
                val outer =
                    original.copy(
                        remoteId = "outer",
                        path = "/outer",
                        name = "outer",
                        kind = ResourceKind.FOLDER,
                        hasLocalCopy = false,
                        localPath = null,
                        offlinePinned = true,
                    )
                f.db.resourceDao().insert(outer)
                val service = f.store.localCopyRemovals()
                service.captureOne(original, true, f.stages)!!.use { scope ->
                    val row = service.page(scope).single()
                    f.db.resourceDao().insert(
                        outer.copy(
                            remoteId = "inner",
                            path = "/outer/inner",
                            name = "inner",
                            parentId = outer.remoteId,
                        ),
                    )
                    var calls = 0
                    assertEquals(
                        LocalCopyRemovalDecision.Changed,
                        service.remove(scope, row) {
                            calls++
                            true
                        },
                    )
                    assertEquals(0, calls)
                    assertEquals("data", File(original.localPath!!).readText())
                }
                val prior = f.store.vaultOfflineGroups().captureOwner("a")!!
                service.captureOne(original, true, f.stages)!!.use { scope ->
                    val row = service.page(scope).single()
                    val second = f.open()
                    try {
                        FileBrowserStore(second).removeAccount("a")
                        second.accountDao().upsert(f.account)
                        second.spaceDao().upsertAll(listOf(f.space("one")))
                        second.resourceDao().insert(original)
                        assertNotEquals(prior, FileBrowserStore(second).vaultOfflineGroups().captureOwner("a"))
                    } finally {
                        second.close()
                    }
                    assertEquals(original, f.store.resource("a", "one", "file"))
                    assertEquals(LocalCopyRemovalDecision.Changed, service.remove(scope, row) { error("old account") })
                    assertEquals("data", File(original.localPath!!).readText())
                }
                service.captureOne(original, true, f.stages)!!.use { scope ->
                    val row = service.page(scope).single()
                    val completed =
                        TransferEntity(
                            UUID.randomUUID().toString(),
                            "a",
                            "one",
                            original.remoteId,
                            "DOWNLOAD",
                            null,
                            original.path,
                            original.name,
                            null,
                            original.sizeBytes,
                            state = "SUCCEEDED",
                            createdAtEpochMillis = 1,
                            updatedAtEpochMillis = 1,
                        )
                    f.db.transferDao().insert(completed)
                    assertEquals(original, f.store.resource("a", "one", "file"))
                    var calls = 0
                    assertEquals(
                        LocalCopyRemovalDecision.Changed,
                        service.remove(scope, row) {
                            calls++
                            true
                        },
                    )
                    f.store.clearTransferHistory("a")
                    assertEquals(null, f.store.transfer(completed.id))
                    assertEquals(
                        LocalCopyRemovalDecision.Changed,
                        service.remove(scope, row) {
                            calls++
                            true
                        },
                    )
                    assertEquals(0, calls)
                    assertEquals("data", File(original.localPath!!).readText())
                }
                assertTrue(
                    f.stages
                        .listFiles()
                        .orEmpty()
                        .isEmpty(),
                )
            }
        }
    }

    private suspend fun fixture(action: suspend (Fixture) -> Unit) {
        val f = Fixture()
        try {
            f.seed()
            action(f)
        } finally {
            f.close()
        }
    }

    private class Fixture : AutoCloseable {
        private val app = InstrumentationRegistry.getInstrumentation().targetContext
        private val name = "local-removal-${UUID.randomUUID()}.db"
        private val root = File(app.noBackupFilesDir, "local-removal-${UUID.randomUUID()}").apply { mkdirs() }
        val context =
            object : ContextWrapper(app) {
                override fun getFilesDir() = File(root, "files").apply { mkdirs() }

                override fun getNoBackupFilesDir() = File(root, "no-backup").apply { mkdirs() }
            }
        val db = open()
        val store = FileBrowserStore(db)
        val stages = File(context.noBackupFilesDir, "direct-stages")
        val account = AccountEntity("a", "https://example.test/", "u", "User", "BASIC", false)
        private val work: WorkManager =
            try {
                WorkManager.getInstance(app)
            } catch (_: IllegalStateException) {
                WorkManager.initialize(app, Configuration.Builder().build())
                WorkManager.getInstance(app)
            }
        val operations = LocalCopyOperations(context, store, work)

        fun open(): FileBrowserDatabase = Room.databaseBuilder(app, FileBrowserDatabase::class.java, name).build()

        fun space(id: String) = SpaceEntity("a", id, id, "personal", null, null, "root", null, null, null)

        suspend fun seed() {
            db.accountDao().upsert(account)
            db.spaceDao().upsertAll(listOf(space("one"), space("two")))
        }

        suspend fun cached(
            id: String,
            space: String = "one",
        ): ResourceEntity {
            val directory = resourceCacheDirectory(context.filesDir, "a", space).apply { mkdirs() }
            val file = File(directory, id).apply { writeText("data") }
            val row =
                ResourceEntity(
                    "a",
                    space,
                    id,
                    "root",
                    "/$id",
                    id,
                    ResourceKind.FILE,
                    "text/plain",
                    4,
                    "etag",
                    1,
                    1,
                    hasLocalCopy = true,
                    localPath = file.path,
                )
            db.resourceDao().insert(row)
            return row
        }

        override fun close() {
            db.close()
            app.deleteDatabase(name)
            root.deleteRecursively()
        }
    }
}
