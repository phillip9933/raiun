package eu.opencloud.android.next.core.sync

import android.content.ContextWrapper
import androidx.room.Room
import androidx.work.Configuration
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkInfo
import androidx.work.WorkManager
import androidx.work.testing.SynchronousExecutor
import androidx.work.testing.WorkManagerTestInitHelper
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.model.resourceCacheDirectory
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.util.UUID
import java.util.concurrent.TimeUnit

@RunWith(RobolectricTestRunner::class)
class LocalCopyRemovalIntegrationTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun busySingleKeepsPinBytesAndWorkerThenExplicitRetryRemovesOnlyTheSelectedCopy() {
        runBlocking {
            fixture { f ->
                val original = f.cached("file").copy(offlinePinned = true, isFavorite = true)
                f.db.resourceDao().update(original)
                val transfer = f.download(original)
                f.db.transferDao().insert(transfer)
                val lease = LocalCopyLease.acquire(File(original.localPath!!))
                try {
                    val failure =
                        assertThrows(OpenCloudException::class.java) { runBlocking { f.remove.remove(original) } }
                    assertEquals(OpenCloudError.LocalCopiesRetained, failure.error)
                    assertEquals(original, f.store.resource("a", "one", "file"))
                    assertEquals(transfer, f.store.transfer(transfer.id))
                    assertEquals("data", File(original.localPath).readText())
                    assertTrue(f.stages().isEmpty())
                } finally {
                    lease.close()
                }
                f.remove.remove(original)
                assertEquals(
                    original.copy(hasLocalCopy = false, localPath = null, offlinePinned = false),
                    f.store.resource("a", "one", "file"),
                )
                assertFalse(File(original.localPath).exists())
                assertEquals("CANCELLED", f.store.transfer(transfer.id)!!.state)
                assertTrue(f.stages().isEmpty())
            }
        }
    }

    @Test fun bulkPagesPastBusyRowsUnpinsNoCopyFoldersAndRetainsDisabledAndOtherAccountBytes() {
        runBlocking {
            fixture { f ->
                val copies =
                    (0 until 386).map { number ->
                        f.cached((number / 2).toString().padStart(4, '0'), if (number % 2 == 0) "one" else "two")
                    }
                val busy = copies.last().copy(offlinePinned = true)
                f.db.resourceDao().update(busy)
                val disabled = f.cached("disabled", "disabled").copy(offlinePinned = true)
                f.db.resourceDao().update(disabled)
                val folders =
                    (0 until 130).map { number ->
                        copies.first().copy(
                            remoteId = "pin-$number",
                            path = "/pin-$number",
                            name = "pin-$number",
                            kind = ResourceKind.FOLDER,
                            offlinePinned = true,
                            hasLocalCopy = false,
                            localPath = null,
                        )
                    }
                f.db.resourceDao().insertAll(folders)
                val otherFile = File(f.context.filesDir, "other-account").apply { writeText("keep") }
                val other = copies.first().copy(accountId = "other", localPath = otherFile.path, offlinePinned = true)
                f.db.resourceDao().insert(other)
                PrivateCacheUse.hold(listOf(File(busy.localPath!!))) {
                    val failure =
                        assertThrows(OpenCloudException::class.java) { runBlocking { f.remove.removeAll("a") } }
                    assertEquals(OpenCloudError.LocalCopiesRetained, failure.error)
                    copies.dropLast(1).forEach { original ->
                        assertFalse(File(original.localPath!!).exists())
                        assertFalse(f.store.resource("a", original.spaceId, original.remoteId)!!.hasLocalCopy)
                    }
                    assertEquals(busy.copy(offlinePinned = false), f.store.resource("a", busy.spaceId, busy.remoteId))
                    assertEquals("data", File(busy.localPath).readText())
                }
                folders.forEach { assertFalse(f.store.resource("a", "one", it.remoteId)!!.offlinePinned) }
                assertEquals(disabled.copy(offlinePinned = false), f.store.resource("a", "disabled", "disabled"))
                assertEquals("data", File(disabled.localPath!!).readText())
                assertEquals(other, f.store.resource("other", "one", other.remoteId))
                assertEquals("keep", otherFile.readText())
                assertTrue(f.stages().isEmpty())
                f.remove.removeAll("a")
                assertFalse(File(busy.localPath!!).exists())
            }
        }
    }

    @Test fun exactWorkerUuidCancellationDoesNotCancelNewWorkReusingTheUniqueTransferName() {
        runBlocking {
            fixture { f ->
                val original = f.cached("file")
                val old = f.download(original)
                f.db.transferDao().insert(old)
                val replacement = OneTimeWorkRequestBuilder<DownloadWorker>().setInitialDelay(1, TimeUnit.DAYS).build()
                f.work
                    .enqueueUniqueWork("transfer-${old.id}", ExistingWorkPolicy.REPLACE, replacement)
                    .result
                    .get()
                f.remove.remove(original)
                assertEquals("CANCELLED", f.store.transfer(old.id)!!.state)
                assertEquals(
                    WorkInfo.State.ENQUEUED,
                    f.work
                        .getWorkInfoById(replacement.id)
                        .get()!!
                        .state,
                )
                assertFalse(File(original.localPath!!).exists())
            }
        }
    }

    @Test fun outsideSymlinkAndWrongSizedPathsAreKeptWhileAnAlreadyMissingOwnedCopyCanBeDetached() {
        runBlocking {
            fixture { f ->
                val external = File(temporary.root, "external").apply { writeText("data") }
                val outside = f.cached("outside").copy(localPath = external.path, offlinePinned = true)
                f.db.resourceDao().update(outside)
                val wrong = f.cached("wrong").copy(offlinePinned = true)
                f.db.resourceDao().update(wrong)
                File(wrong.localPath!!).writeText("newer-sized-data")
                val linked = f.cached("linked").copy(offlinePinned = true)
                f.db.resourceDao().update(linked)
                File(linked.localPath!!).delete()
                Files.createSymbolicLink(File(linked.localPath).toPath(), external.toPath())
                for (resource in listOf(outside, wrong, linked)) {
                    val failure =
                        assertThrows(OpenCloudException::class.java) { runBlocking { f.remove.remove(resource) } }
                    assertEquals(OpenCloudError.LocalCopiesRetained, failure.error)
                    assertEquals(resource, f.store.resource("a", "one", resource.remoteId))
                }
                assertEquals("data", external.readText())
                assertEquals("newer-sized-data", File(wrong.localPath).readText())
                assertTrue(Files.isSymbolicLink(File(linked.localPath).toPath()))
                val missing = f.cached("missing").copy(offlinePinned = true)
                f.db.resourceDao().update(missing)
                assertTrue(File(missing.localPath!!).delete())
                f.remove.remove(missing)
                assertEquals(
                    missing.copy(hasLocalCopy = false, localPath = null, offlinePinned = false),
                    f.store.resource("a", "one", missing.remoteId),
                )
                assertTrue(f.stages().isEmpty())
            }
        }
    }

    @Test fun replacementAfterCaptureKeepsSameSizedBytesAndAllChangedMetadataAndNewDownload() {
        runBlocking {
            fixture { f ->
                val original = f.cached("file").copy(offlinePinned = true)
                f.db.resourceDao().update(original)
                val replacement = original.copy(path = "/moved/file", name = "Moved", isFavorite = true)
                val newerDownload = f.download(replacement)
                f.beforeCacheLookup = {
                    File(original.localPath!!).writeText("new!")
                    runBlocking {
                        f.db.resourceDao().update(replacement)
                        f.db.transferDao().insert(newerDownload)
                    }
                }
                val failure = assertThrows(OpenCloudException::class.java) { runBlocking { f.remove.remove(original) } }
                assertEquals(OpenCloudError.LocalCopiesRetained, failure.error)
                assertEquals("new!", File(original.localPath!!).readText())
                assertEquals(replacement, f.store.resource("a", "one", "file"))
                assertEquals(newerDownload, f.store.transfer(newerDownload.id))
                assertTrue(f.stages().isEmpty())
            }
        }
    }

    @Test fun staleExportAndStorageFailureHaveDistinctSafeOutcomesWithoutCancellingNewerDownload() {
        runBlocking {
            fixture { f ->
                val exported = f.cached("file")
                val newer = exported.copy(eTag = "new-version")
                f.db.resourceDao().update(newer)
                val transfer = f.download(newer)
                f.db.transferDao().insert(transfer)
                val changed =
                    assertThrows(OpenCloudException::class.java) {
                        runBlocking { f.remove.remove(exported, requireSameCopy = true) }
                    }
                assertEquals(OpenCloudError.LocalCopiesRetained, changed.error)
                assertEquals(newer, f.store.resource("a", "one", "file"))
                assertEquals(transfer, f.store.transfer(transfer.id))
                f.failStorage = true
                val failed = assertThrows(OpenCloudException::class.java) { runBlocking { f.remove.remove(newer) } }
                assertEquals(OpenCloudError.LocalCopyRemovalFailed, failed.error)
                assertEquals("data", File(newer.localPath!!).readText())
                assertEquals(transfer, f.store.transfer(transfer.id))
            }
        }
    }

    private suspend fun fixture(action: suspend (Fixture) -> Unit) {
        val f = Fixture(temporary.newFolder())
        try {
            f.seed()
            action(f)
        } finally {
            f.db.close()
            WorkManagerTestInitHelper.closeWorkDatabase()
        }
    }

    private class Fixture(
        root: File,
    ) {
        var failStorage = false
        var beforeCacheLookup: (() -> Unit)? = null
        private val app = RuntimeEnvironment.getApplication()
        val context =
            object : ContextWrapper(app) {
                override fun getFilesDir(): File {
                    val hook = beforeCacheLookup
                    beforeCacheLookup = null
                    hook?.invoke()
                    return File(root, "files").apply { mkdirs() }
                }

                override fun getNoBackupFilesDir(): File {
                    if (failStorage) throw IOException("Synthetic private storage failure")
                    return File(root, "no-backup").apply { mkdirs() }
                }
            }
        val db = Room.inMemoryDatabaseBuilder(app, FileBrowserDatabase::class.java).build()
        val store = FileBrowserStore(db)
        val work: WorkManager
        val remove: LocalCopyOperations

        init {
            WorkManagerTestInitHelper.initializeTestWorkManager(
                app,
                Configuration.Builder().setExecutor(SynchronousExecutor()).build(),
            )
            work = WorkManager.getInstance(app)
            remove = LocalCopyOperations(context, store, work)
        }

        suspend fun seed() {
            val account = AccountEntity("a", "https://example.test/", "u", "User", "BASIC", false)
            db.accountDao().upsert(account)
            db.accountDao().upsert(account.copy(id = "other"))
            val space = SpaceEntity("a", "one", "One", "personal", null, null, "root", null, null, null)
            db.spaceDao().upsertAll(
                listOf(
                    space,
                    space.copy(driveId = "two"),
                    space.copy(driveId = "disabled", isDisabled = true),
                ),
            )
        }

        suspend fun cached(
            id: String,
            space: String = "one",
        ): ResourceEntity {
            val directory = resourceCacheDirectory(context.filesDir, "a", space).apply { mkdirs() }
            val file = File(directory, "copy-$id").apply { writeText("data") }
            val resource =
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
            db.resourceDao().insert(resource)
            return resource
        }

        fun download(row: ResourceEntity) =
            TransferEntity(
                UUID.randomUUID().toString(),
                row.accountId,
                row.spaceId,
                row.remoteId,
                "DOWNLOAD",
                null,
                row.path,
                row.name,
                null,
                4,
                createdAtEpochMillis = 1,
                updatedAtEpochMillis = 1,
                workId = UUID.randomUUID().toString(),
            )

        fun stages(): List<File> =
            File(context.noBackupFilesDir, "ordinary-removal-inventory").listFiles().orEmpty().toList()
    }
}
