package eu.opencloud.android.next.core.sync

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.provider.DocumentsContract
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.shadows.ShadowContentResolver

@RunWith(RobolectricTestRunner::class)
class BackupTreeTest {
    @Test fun `nested duplicate filenames keep their parents and trash entries are excluded`() {
        register(TreeProvider())
        val files = queryBackupTree(RuntimeEnvironment.getApplication(), tree)
        assertEquals(listOf("Camera", "Edited"), files.map { it.relativeParent })
        assertEquals(listOf("image.jpg", "image.jpg"), files.map { it.name })
        assertEquals(listOf(0L, 0L), files.map { it.modified })
    }

    @Test fun `provider query failure and cycles do not become successful empty scans`() {
        listOf(TreeProvider(fail = true), TreeProvider(cycle = true)).forEach { provider ->
            register(provider)
            assertThrows(OpenCloudException::class.java) { queryBackupTree(RuntimeEnvironment.getApplication(), tree) }
        }
    }

    @Test fun `excluded directories are never queried and allowed siblings remain`() {
        val provider = TreeProvider(exclusionFixture = true)
        register(provider)
        val files =
            queryBackupTree(
                RuntimeEnvironment.getApplication(),
                tree,
                exclusions = BackupExclusions.parse("Private/\n*.tmp"),
            )
        assertEquals(listOf("root", "public"), provider.queriedIds)
        assertEquals(listOf("Public"), files.map { it.relativeParent })
        assertEquals(listOf("photo.jpg"), files.map { it.name })
    }

    @Test fun `more than one hundred thousand files stream in bounded batches`() =
        runBlocking {
            val provider = TreeProvider(fileCount = 100_001)
            register(provider)
            var total = 0
            var batches = 0
            scanBackupTree(RuntimeEnvironment.getApplication(), tree) { files ->
                assertTrue(files.isNotEmpty() && files.size <= BACKUP_BATCH_SIZE)
                assertEquals("file-$total.jpg", files.first().name)
                total += files.size
                batches++
            }
            assertEquals(100_001, total)
            assertEquals(391, batches)
            assertTrue(provider.lastCursor!!.isClosed)
        }

    @Test fun `consumer failure closes cursor and stops traversal`() {
        val provider = TreeProvider(fileCount = BACKUP_BATCH_SIZE * 2)
        register(provider)
        var delivered = 0
        assertThrows(IllegalStateException::class.java) {
            runBlocking {
                scanBackupTree(RuntimeEnvironment.getApplication(), tree) {
                    delivered += it.size
                    error("Consumer stopped")
                }
            }
        }
        assertEquals(BACKUP_BATCH_SIZE, delivered)
        assertTrue(provider.lastCursor!!.isClosed)
        assertTrue(traversalFiles().isEmpty())
    }

    @Test fun `later provider failure propagates after earlier batches`() {
        val provider = TreeProvider(fileCount = BACKUP_BATCH_SIZE, failAfterFiles = true)
        register(provider)
        var delivered = 0
        assertThrows(OpenCloudException::class.java) {
            runBlocking {
                scanBackupTree(RuntimeEnvironment.getApplication(), tree) { delivered += it.size }
            }
        }
        assertEquals(BACKUP_BATCH_SIZE, delivered)
        assertTrue(provider.lastCursor!!.isClosed)
        assertEquals(listOf("root", "unavailable"), provider.queriedIds)
    }

    @Test fun `cancellation closes source cursor and removes spill files`() {
        val provider = TreeProvider(fileCount = BACKUP_BATCH_SIZE * 2)
        register(provider)
        val initial = traversalFiles()
        assertThrows(java.util.concurrent.CancellationException::class.java) {
            runBlocking {
                scanBackupTree(RuntimeEnvironment.getApplication(), tree) {
                    throw java.util.concurrent.CancellationException("Cancelled synthetic scan")
                }
            }
        }
        assertTrue(provider.lastCursor!!.isClosed)
        assertEquals(initial, traversalFiles())
    }

    @Test fun `directory queue exceeds former ceiling and preserves order`() {
        val context = RuntimeEnvironment.getApplication()
        val initial = traversalFiles()
        BackupDirectoryQueue(context).use { queue ->
            repeat(100_001) { index -> queue.add("directory-$index", "Folder-$index") }
            repeat(100_001) { index ->
                assertEquals("directory-$index" to "Folder-$index", queue.take())
            }
            assertEquals(null, queue.take())
        }
        assertEquals(initial, traversalFiles())
    }

    @Test fun `disk queue detects duplicates after dequeue and cleans up on failure`() {
        val initial = traversalFiles()
        assertThrows(OpenCloudException::class.java) {
            BackupDirectoryQueue(RuntimeEnvironment.getApplication()).use { queue ->
                queue.add("root", "")
                assertEquals("root" to "", queue.take())
                queue.add("root", "Cycle")
                queue.take()
            }
        }
        assertEquals(initial, traversalFiles())
    }

    @Test fun `stale traversal cleanup preserves locked active files`() {
        val context = RuntimeEnvironment.getApplication()
        val initial = traversalFiles()
        BackupTraversalFile(context).use { active ->
            active.file.setLastModified(1L)
            val stale = java.io.File(context.noBackupFilesDir, "backup-traversal-stale.db")
            stale.writeText("Synthetic stale state")
            stale.setLastModified(1L)
            BackupTraversalFile(context).use {
                assertTrue(active.file.exists())
                assertTrue(!stale.exists())
            }
        }
        assertEquals(initial, traversalFiles())
    }

    private fun traversalFiles(): Set<String> =
        RuntimeEnvironment
            .getApplication()
            .noBackupFilesDir
            .listFiles()
            .orEmpty()
            .filter { it.name.startsWith("backup-traversal-") }
            .map { it.name }
            .toSet()

    @Test fun `provider declared partial or failed cursor never becomes a completed scan`() {
        listOf(DocumentsContract.EXTRA_LOADING, DocumentsContract.EXTRA_ERROR).forEach { flag ->
            val provider = TreeProvider(partialFlag = flag)
            register(provider)
            assertThrows(OpenCloudException::class.java) {
                queryBackupTree(RuntimeEnvironment.getApplication(), tree)
            }
            assertTrue(provider.lastCursor!!.isClosed)
        }
    }

    private fun queryBackupTree(
        context: android.content.Context,
        tree: Uri,
        exclusions: BackupExclusions = BackupExclusions.parse(""),
    ): List<BackupDocument> =
        runBlocking {
            val files = mutableListOf<BackupDocument>()
            scanBackupTree(context, tree, exclusions = exclusions) { files.addAll(it) }
            files
        }

    private val tree = DocumentsContract.buildTreeDocumentUri("backup.test", "root")

    private fun register(provider: TreeProvider) {
        provider.attachInfo(
            RuntimeEnvironment.getApplication(),
            android.content.pm.ProviderInfo().apply {
                authority = "backup.test"
            },
        )
        ShadowContentResolver.registerProviderInternal("backup.test", provider)
    }

    private class TreeProvider(
        private val fail: Boolean = false,
        private val cycle: Boolean = false,
        private val exclusionFixture: Boolean = false,
        private val fileCount: Int? = null,
        private val failAfterFiles: Boolean = false,
        private val partialFlag: String? = null,
    ) : ContentProvider() {
        val queriedIds = mutableListOf<String>()
        var lastCursor: Cursor? = null

        override fun onCreate() = true

        override fun getType(uri: Uri) = DocumentsContract.Document.MIME_TYPE_DIR

        @Suppress("CyclomaticComplexMethod") // Independent synthetic provider modes.
        override fun query(
            uri: Uri,
            projection: Array<out String>?,
            selection: String?,
            selectionArgs: Array<out String>?,
            sortOrder: String?,
        ): Cursor? {
            val id = DocumentsContract.getDocumentId(uri)
            queriedIds += id
            if (fail || (failAfterFiles && id == "unavailable")) return null
            return MatrixCursor(projection).also { lastCursor = it }.apply {
                partialFlag?.let { flag ->
                    setExtras(
                        android.os.Bundle().apply {
                            if (flag ==
                                DocumentsContract.EXTRA_LOADING
                            ) {
                                putBoolean(flag, true)
                            } else {
                                putString(flag, "Synthetic provider failure")
                            }
                        },
                    )
                }
                if (fileCount != null) {
                    repeat(fileCount) { index ->
                        addRow(arrayOf("file-$index", "file-$index.jpg", "image/jpeg", 1L, 5L))
                    }
                    if (failAfterFiles) addRow(arrayOf("unavailable", "Unavailable", getType(uri), 0L, null))
                    return@apply
                }
                if (exclusionFixture) {
                    when (id) {
                        "root" -> {
                            addRow(arrayOf("private", "Private", getType(uri), 0L, null))
                            addRow(arrayOf("public", "Public", getType(uri), 0L, null))
                            addRow(arrayOf("root-temp", "notes.tmp", "text/plain", 0L, 5L))
                        }
                        "public" -> {
                            addRow(arrayOf("public-file", "photo.jpg", "image/jpeg", 0L, 5L))
                            addRow(arrayOf("public-temp", "draft.tmp", "text/plain", 0L, 5L))
                        }
                        "private" -> addRow(arrayOf("private-file", "secret.jpg", "image/jpeg", 0L, 5L))
                    }
                    return@apply
                }
                if (id == "root") {
                    addRow(arrayOf(if (cycle) "root" else "camera", "Camera", getType(uri), 0L, null))
                    addRow(arrayOf("edited", "Edited", getType(uri), 0L, null))
                } else {
                    addRow(arrayOf("$id-file", "image.jpg", "image/jpeg", null, 5L))
                    addRow(arrayOf("$id-trash", ".trashed-image.jpg", "image/jpeg", null, 5L))
                }
            }
        }

        override fun insert(
            uri: Uri,
            values: ContentValues?,
        ): Uri? = null

        override fun delete(
            uri: Uri,
            selection: String?,
            selectionArgs: Array<out String>?,
        ) = 0

        override fun update(
            uri: Uri,
            values: ContentValues?,
            selection: String?,
            selectionArgs: Array<out String>?,
        ) = 0
    }
}
