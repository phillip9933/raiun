package eu.opencloud.android.next.core.sync

import androidx.room.Room
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.model.ResourceKind
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File

@RunWith(RobolectricTestRunner::class)
class DownloadAttemptCleanupTest {
    @Test fun `cleanup removes unpublished target but preserves database published bytes`() =
        runTest {
            val context = RuntimeEnvironment.getApplication()
            val database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
            try {
                val store = FileBrowserStore(database)
                val directory = File(context.filesDir, "resources-v2/cleanup-published").apply { mkdirs() }
                val files = attemptFiles(directory)
                files.target.writeText("published")
                files.partial.writeText("partial")
                files.validator.writeText("validator")
                database.transferDao().insert(transfer(state = "CANCELLED"))
                database.resourceDao().insert(
                    ResourceEntity(
                        "account",
                        "space",
                        "resource",
                        null,
                        "/file",
                        "file",
                        ResourceKind.FILE,
                        null,
                        9,
                        null,
                        0,
                        0,
                        hasLocalCopy = true,
                        localPath = files.target.absolutePath,
                    ),
                )

                cleanupUnpublishedDownloadAttempt(store, transfer(), files.target, files.partial, files.validator)

                assertTrue(files.target.exists())
                assertFalse(files.partial.exists())
                assertFalse(files.validator.exists())
            } finally {
                database.close()
            }
        }

    @Test fun `cleanup removes failed unpublished target and keeps retry checkpoint`() =
        runTest {
            val context = RuntimeEnvironment.getApplication()
            val database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
            try {
                val directory = File(context.filesDir, "resources-v2/cleanup-retry").apply { mkdirs() }
                val files = attemptFiles(directory)
                files.target.writeText("unpublished")
                files.partial.writeText("resumable bytes")
                files.validator.writeText("resume identity")
                val retry = transfer(state = "RETRY")
                database.transferDao().insert(retry)

                cleanupUnpublishedDownloadAttempt(
                    FileBrowserStore(database),
                    retry,
                    files.target,
                    files.partial,
                    files.validator,
                )

                assertFalse(files.target.exists())
                assertTrue(files.partial.exists())
                assertTrue(files.validator.exists())
            } finally {
                database.close()
            }
        }

    @Test fun `cleanup defers active writer files and removes them after its lease closes`() =
        runTest {
            val context = RuntimeEnvironment.getApplication()
            val database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
            try {
                val store = FileBrowserStore(database)
                val directory = File(context.filesDir, "resources-v2/cleanup-active").apply { mkdirs() }
                val files = attemptFiles(directory)
                files.target.writeText("unpublished")
                files.partial.writeText("partial")
                files.validator.writeText("validator")
                val cancelled = transfer()
                database.transferDao().insert(cancelled)

                PrivateCacheUse.hold(listOf(files.target, files.partial, files.validator)) {
                    cleanupUnpublishedDownloadAttempt(store, cancelled, files.target, files.partial, files.validator)

                    assertTrue(files.target.exists())
                    assertTrue(files.partial.exists())
                    assertTrue(files.validator.exists())
                }

                cleanupUnpublishedDownloadAttempt(store, cancelled, files.target, files.partial, files.validator)

                assertFalse(files.target.exists())
                assertFalse(files.partial.exists())
                assertFalse(files.validator.exists())
            } finally {
                database.close()
            }
        }

    private fun attemptFiles(directory: File) =
        AttemptFiles(
            File(directory, "target-unique"),
            File(directory, "transfer.part"),
            File(directory, "transfer.validator"),
        )

    private fun transfer(state: String = "CANCELLED") =
        TransferEntity(
            id = "transfer",
            accountId = "account",
            spaceId = "space",
            resourceId = "resource",
            direction = "DOWNLOAD",
            sourceUri = null,
            destinationPath = "/file",
            displayName = "file",
            mimeType = null,
            bytesTotal = 9,
            state = state,
            workId = "worker",
            createdAtEpochMillis = 0,
            updatedAtEpochMillis = 0,
        )

    private data class AttemptFiles(
        val target: File,
        val partial: File,
        val validator: File,
    )
}
