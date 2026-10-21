package eu.opencloud.android.next.core.sync

import androidx.room.Room
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.model.cacheIdentity
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
class CacheMaintenanceTest {
    @Test fun `retained entries rotate behind later batches`() =
        runTest {
            val context = RuntimeEnvironment.getApplication()
            val database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
            try {
                val sql = database.openHelper.writableDatabase
                repeat(513) { index ->
                    sql.execSQL("INSERT INTO excluded_cache(path) VALUES (?)", arrayOf("file-$index"))
                }
                val queue = database.excludedCacheDao()
                val first = queue.pending()
                assertTrue(first.size == 512)
                first.forEach { queue.defer(it.path) }
                assertTrue(queue.pending().first().path == "file-512")
                queue.forget("file-512")
                queue.defer("file-512")
                assertFalse(queue.pending().any { it.path == "file-512" })
            } finally {
                database.close()
            }
        }

    @Test fun `excluded cache survives lease and removes only captured bytes after metadata deletion`() =
        runTest {
            val context = RuntimeEnvironment.getApplication()
            val database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
            try {
                val directory = resourceCacheDirectory(context.filesDir, "a", "s").apply { mkdirs() }
                val excluded = File(directory, "excluded").apply { writeText("recent") }
                val neighbor = File(directory, "neighbor").apply { writeText("keep") }
                val outside = File(context.filesDir, "unrelated").apply { writeText("keep") }
                val resource =
                    ResourceEntity(
                        "a",
                        "s",
                        "file",
                        null,
                        "/vault/file",
                        "file",
                        ResourceKind.FILE,
                        null,
                        6,
                        null,
                        0,
                        0,
                        hasLocalCopy = true,
                        localPath = excluded.absolutePath,
                    )
                database.resourceDao().insert(resource)
                database.resourceDao().insert(
                    resource.copy(remoteId = "neighbor", path = "/vault-other/file", localPath = neighbor.absolutePath),
                )
                database.resourceDao().insert(
                    resource.copy(remoteId = "outside", path = "/vault/outside", localPath = outside.absolutePath),
                )
                database.excludedCacheDao().capture("a", "s", "/vault")
                database.resourceDao().delete(resource)
                val lease = LocalCopyLease.acquire(excluded)
                try {
                    reclaimExcludedCache(database, context.filesDir)
                    assertTrue(excluded.exists())
                    assertTrue(database.excludedCacheDao().pending().any { it.path == excluded.absolutePath })
                } finally {
                    lease.close()
                }
                reclaimExcludedCache(database, context.filesDir)
                assertFalse(excluded.exists())
                assertTrue(neighbor.exists())
                assertTrue(outside.exists())
                assertTrue(database.excludedCacheDao().pending().isEmpty())
            } finally {
                database.close()
            }
        }

    @Test fun `sweep preserves saved and recoverable intake batches regardless of age`() =
        runTest {
            val context = RuntimeEnvironment.getApplication()
            val database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
            try {
                val root = File(context.noBackupFilesDir, "incoming-shares")
                val retained =
                    listOf("saved" to "manifest.json", "recovery" to "manifest.json.bak").flatMap { (id, name) ->
                        val batch = File(root, id).apply { mkdirs() }
                        val payload =
                            File(batch, "0/payload").apply {
                                parentFile!!.mkdirs()
                                writeText("retained")
                            }
                        listOf(File(batch, name).apply { writeText("unparsed draft") }, payload)
                    }
                val orphan =
                    File(root, "unfinished/0/partial").apply {
                        parentFile!!.mkdirs()
                        writeText("abandoned")
                    }
                (retained + orphan).forEach { it.setLastModified(1) }
                maintainPrivateCache(context, FileBrowserStore(database), System.currentTimeMillis())
                retained.forEach { assertTrue(it.exists()) }
                assertFalse(orphan.exists())
            } finally {
                database.close()
            }
        }

    @Test fun `orphan sweep preserves upload staging and sealed bytes until worker releases them`() =
        runTest {
            val context = RuntimeEnvironment.getApplication()
            val database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
            try {
                val directory = File(context.noBackupFilesDir, "upload-sources/fixture/worker").apply { mkdirs() }
                val files = uploadSourceFiles(directory)
                files.forEach {
                    it.writeText("bytes")
                    it.setLastModified(1)
                }
                val store = FileBrowserStore(database)
                val cutoff = System.currentTimeMillis() - 60_000
                PrivateCacheUse.hold(files) {
                    maintainPrivateCache(context, store, cutoff)
                    files.forEach { assertTrue(it.exists()) }
                }
                maintainPrivateCache(context, store, cutoff)
                files.forEach { assertFalse(it.exists()) }
            } finally {
                database.close()
            }
        }

    @Test fun `sweep keeps referenced and recent bytes while removing expired orphans`() =
        runTest {
            val context = RuntimeEnvironment.getApplication()
            val database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
            try {
                val directory = resourceCacheDirectory(context.filesDir, "a", "s").apply { mkdirs() }
                val referenced =
                    File(directory, "referenced").apply {
                        writeText("safe")
                        setLastModified(1)
                    }
                val orphan =
                    File(directory, "orphan").apply {
                        writeText("old")
                        setLastModified(1)
                    }
                val recent = File(directory, "recent").apply { writeText("new") }
                database.resourceDao().insert(
                    ResourceEntity(
                        "a",
                        "s",
                        "file",
                        null,
                        "/file",
                        "file",
                        ResourceKind.FILE,
                        null,
                        4,
                        null,
                        0,
                        0,
                        hasLocalCopy = true,
                        localPath = referenced.absolutePath,
                    ),
                )
                maintainPrivateCache(context, FileBrowserStore(database), System.currentTimeMillis() - 60_000)
                assertTrue(referenced.isFile)
                assertTrue(recent.isFile)
                assertFalse(orphan.exists())
            } finally {
                database.close()
            }
        }

    @Test fun freshAttemptOrphanIsReclaimedAndProtectedFilesSurvive() =
        runTest {
            val context = RuntimeEnvironment.getApplication()
            val database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
            try {
                val account = "attempt-account"
                val space = "attempt-space"
                val root = File(context.filesDir, "resources-v2")
                val directory = File(root, cacheIdentity(account) + "/" + cacheIdentity(space)).apply { mkdirs() }
                val orphan = File(directory, downloadAttemptTargetName("orphan-transfer")).apply { writeText("orphan") }
                val leased = File(directory, downloadAttemptTargetName("leased-transfer")).apply { writeText("leased") }
                val referenced =
                    File(directory, downloadAttemptTargetName("referenced-transfer")).apply {
                        writeText("saved")
                    }
                val unrelated = File(directory, "unrelated-fresh-file").apply { writeText("keep") }
                database.resourceDao().insert(
                    ResourceEntity(
                        account,
                        space,
                        "published",
                        null,
                        "/published",
                        "published",
                        ResourceKind.FILE,
                        null,
                        5,
                        null,
                        0,
                        0,
                        hasLocalCopy = true,
                        localPath = referenced.absolutePath,
                    ),
                )
                val store = FileBrowserStore(database)
                resetCacheCursor(context, root.name)
                PrivateCacheUse.hold(listOf(leased)) {
                    maintainPrivateCache(context, store, 0)
                    assertTrue(leased.exists())
                    assertTrue(referenced.exists())
                    assertFalse(orphan.exists())
                    assertTrue(unrelated.exists())
                }
                resetCacheCursor(context, root.name)
                maintainPrivateCache(context, store, 0)
                assertFalse(leased.exists())
                assertTrue(referenced.exists())
                assertTrue(unrelated.exists())
            } finally {
                database.close()
            }
        }

    @Test fun freshMissingCheckpointIsReclaimedOnlyInCanonicalResourcePath() =
        runTest {
            val context = RuntimeEnvironment.getApplication()
            val database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
            try {
                val root = File(context.filesDir, "resources-v2")
                val account = cacheIdentity("missing-account")
                val space = cacheIdentity("missing-space")
                val directory = File(root, account + "/" + space).apply { mkdirs() }
                val partial =
                    File(directory, cacheIdentity("missing-transfer") + ".part").apply {
                        writeText("partial")
                    }
                val validator =
                    File(directory, cacheIdentity("missing-transfer") + ".validator").apply {
                        writeText("validator")
                    }
                val malformed =
                    File(directory, "download-attempt-id-invalid.not-a-uuid").apply {
                        writeText("keep")
                    }
                val wrongDepth =
                    File(File(root, account), "download-attempt-id-invalid.not-a-uuid").apply {
                        parentFile!!.mkdirs()
                        writeText("keep")
                    }
                resetCacheCursor(context, root.name)
                maintainPrivateCache(context, FileBrowserStore(database), 0)
                assertFalse(partial.exists())
                assertFalse(validator.exists())
                assertTrue(malformed.exists())
                assertTrue(wrongDepth.exists())
            } finally {
                database.close()
            }
        }

    @Test fun agedRetryAndRunningCheckpointsRemainAvailable() =
        runTest {
            val context = RuntimeEnvironment.getApplication()
            val database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
            try {
                val account = "checkpoint-account"
                val space = "checkpoint-space"
                val root = File(context.filesDir, "resources-v2")
                val directory = File(root, cacheIdentity(account) + "/" + cacheIdentity(space)).apply { mkdirs() }
                val store = FileBrowserStore(database)
                listOf("RETRY", "RUNNING").forEachIndexed { index, state ->
                    val transferId = "checkpoint-transfer-" + index
                    File(directory, cacheIdentity(transferId) + ".part").apply {
                        writeText("resume")
                        setLastModified(1)
                    }
                    File(directory, cacheIdentity(transferId) + ".validator").apply {
                        writeText("validator")
                        setLastModified(1)
                    }
                    store.createTransfer(
                        eu.opencloud.android.next.core.database.TransferEntity(
                            id = transferId,
                            accountId = account,
                            spaceId = space,
                            resourceId = "resource-" + index,
                            direction = "DOWNLOAD",
                            sourceUri = null,
                            destinationPath = "/resource-" + index,
                            displayName = "resource-" + index,
                            mimeType = null,
                            bytesTotal = 10,
                            state = state,
                            createdAtEpochMillis = 1,
                            updatedAtEpochMillis = 1,
                        ),
                    )
                }
                val legacyRoot = File(context.filesDir, "resources")
                val legacyDirectory = File(legacyRoot, "old-account/old-space").apply { mkdirs() }
                val legacyTransferId = "legacy-running-transfer"
                File(legacyDirectory, cacheIdentity(legacyTransferId) + ".part").apply {
                    writeText("legacy resume")
                    setLastModified(1)
                }
                store.createTransfer(
                    eu.opencloud.android.next.core.database.TransferEntity(
                        id = legacyTransferId,
                        accountId = account,
                        spaceId = space,
                        resourceId = "legacy-resource",
                        direction = "DOWNLOAD",
                        sourceUri = null,
                        destinationPath = "/legacy",
                        displayName = "legacy",
                        mimeType = null,
                        bytesTotal = 10,
                        state = "RUNNING",
                        createdAtEpochMillis = 1,
                        updatedAtEpochMillis = 1,
                    ),
                )
                resetCacheCursor(context, root.name)
                resetCacheCursor(context, legacyRoot.name)
                maintainPrivateCache(context, store, System.currentTimeMillis())
                assertTrue(File(legacyDirectory, cacheIdentity(legacyTransferId) + ".part").exists())
                listOf(0, 1).forEach { index ->
                    val encoded = cacheIdentity("checkpoint-transfer-" + index)
                    assertTrue(File(directory, encoded + ".part").exists())
                    assertTrue(File(directory, encoded + ".validator").exists())
                }
            } finally {
                database.close()
            }
        }

    private fun resetCacheCursor(
        context: android.content.Context,
        rootName: String,
    ) {
        context
            .getSharedPreferences("cache-maintenance", android.content.Context.MODE_PRIVATE)
            .edit()
            .putInt(rootName, 0)
            .apply()
    }
}
