package eu.opencloud.android.next.core.sync

import androidx.room.Room
import androidx.work.Configuration
import androidx.work.WorkManager
import androidx.work.testing.SynchronousExecutor
import androidx.work.testing.WorkManagerTestInitHelper
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
class TransferRecoveryTest {
    private val context = RuntimeEnvironment.getApplication()
    private lateinit var database: FileBrowserDatabase
    private lateinit var store: FileBrowserStore
    private lateinit var workManager: WorkManager
    private lateinit var manager: TransferManager

    @Before fun setUp() {
        database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
        store = FileBrowserStore(database)
        WorkManagerTestInitHelper.initializeTestWorkManager(
            context,
            Configuration
                .Builder()
                .setExecutor(SynchronousExecutor())
                .setWorkerFactory(
                    object : androidx.work.WorkerFactory() {
                        override fun createWorker(
                            appContext: android.content.Context,
                            workerClassName: String,
                            workerParameters: androidx.work.WorkerParameters,
                        ): androidx.work.ListenableWorker =
                            object : androidx.work.Worker(appContext, workerParameters) {
                                override fun doWork(): Result = Result.retry()
                            }
                    },
                ).build(),
        )
        workManager = WorkManager.getInstance(context)
        manager = TransferManager(context, store, workManager)
    }

    @After fun tearDown() {
        WorkManagerTestInitHelper.closeWorkDatabase()
        database.close()
    }

    @Test fun `reconciliation schedules the accepted retry instead of adopting the obsolete worker`() =
        runTest {
            seedAccount()
            store.createTransfer(intent())
            manager.reconcile()
            val original = requireNotNull(store.transfer("transfer"))
            val failed = original.copy(state = "FAILED")
            store.updateTransfer(failed)
            val replacementId = UUID.randomUUID().toString()
            val retry = failed.copy(state = "QUEUED", workId = replacementId)
            assertNotNull(store.retryTransfer(failed, retry))
            manager.reconcile()
            manager.retry(failed) // Stale UI action must not change the replacement or schedule another attempt.
            manager.reconcile()
            assertEquals(replacementId, store.transfer("transfer")?.workId)
            val jobs = workManager.getWorkInfosForUniqueWork("transfer-transfer").get()
            assertEquals(listOf(replacementId), jobs.filterNot { it.state.isFinished }.map { it.id.toString() })
            val obsolete = workManager.getWorkInfoById(UUID.fromString(original.workId)).get()
            org.junit.Assert.assertTrue(obsolete == null || obsolete.state == androidx.work.WorkInfo.State.CANCELLED)
        }

    @Test fun `bulk upload retry skips conflicts and failures requiring human action`() =
        runTest {
            seedAccount()
            val transient = intent().copy(state = "FAILED", errorCode = "CONNECTIVITY")
            val permission = intent().copy(id = "permission", state = "FAILED", errorCode = "SOURCE_PERMISSION")
            val conflict = intent().copy(id = "conflict", state = "CONFLICT", errorCode = "CONFLICT")
            val download =
                intent().copy(
                    id = "download",
                    direction = "DOWNLOAD",
                    state = "FAILED",
                    errorCode = "TIMEOUT",
                )
            val waiting = intent().copy(id = "waiting", state = "RETRY", errorCode = "REMOTE_NOT_READY")
            val unknown = intent().copy(id = "unknown", state = "FAILED", errorCode = null)
            val cancelled = intent().copy(id = "cancelled", state = "CANCELLED", errorCode = "CONNECTIVITY")
            listOf(
                transient,
                permission,
                conflict,
                download,
                waiting,
                unknown,
                cancelled,
            ).forEach { store.createTransfer(it) }

            val result = manager.retryFailedUploads("account")
            assertEquals(2, result.retried)
            assertEquals(3, result.needsAttention)
            assertEquals("QUEUED", store.transfer("transfer")?.state)
            assertEquals("FAILED", store.transfer("permission")?.state)
            assertEquals("CONFLICT", store.transfer("conflict")?.state)
            assertEquals("FAILED", store.transfer("download")?.state)
            assertEquals("QUEUED", store.transfer("waiting")?.state)
            assertEquals("FAILED", store.transfer("unknown")?.state)
            assertEquals("CANCELLED", store.transfer("cancelled")?.state)
        }

    @Test fun `bulk upload retry continues after one candidate can no longer be retried`() =
        runTest {
            seedAccount()
            val inaccessible =
                intent().copy(
                    id = "inaccessible",
                    locationKind = "SHARED_FOLDER",
                    resourceId = "old-shared-parent",
                    state = "FAILED",
                    errorCode = "CONNECTIVITY",
                    createdAtEpochMillis = 2,
                )
            val eligible =
                intent().copy(
                    id = "eligible",
                    state = "FAILED",
                    errorCode = "CONNECTIVITY",
                    createdAtEpochMillis = 1,
                )
            store.createTransfer(inaccessible)
            store.createTransfer(eligible)

            val result = manager.retryFailedUploads("account")

            assertEquals(1, result.retried)
            assertEquals(1, result.needsAttention)
            assertEquals("FAILED", store.transfer("inaccessible")?.state)
            assertEquals("QUEUED", store.transfer("eligible")?.state)
        }

    @Test fun `keep both clears the previous resumable address and stale actions cannot reset the new intent`() =
        runTest {
            seedAccount()
            val conflict =
                intent().copy(
                    state = "CONFLICT",
                    tusUrl = "https://example.test/old-session",
                    tusOffset = 100,
                    bytesTransferred = 100,
                    verificationPending = true,
                    expectedETag = "\"old\"",
                    verifiedETag = "\"old\"",
                )
            store.createTransfer(conflict)
            manager.retryConflict(conflict, overwrite = false, keepBoth = true)
            val accepted = requireNotNull(store.transfer("transfer"))
            manager.retryConflict(conflict, overwrite = true)
            assertEquals(accepted, store.transfer("transfer"))
            assertEquals(null, accepted.tusUrl)
            assertEquals(0L, accepted.tusOffset)
            assertEquals(0L, accepted.bytesTransferred)
            assertFalse(accepted.verificationPending)
            assertEquals(null, accepted.expectedETag)
            assertEquals(null, accepted.verifiedETag)
            assertNotNull(accepted.workId)
            assertFalse(accepted.overwrite)
        }

    @Test fun `keep both advances numbered copy names after each destination conflict`() =
        runTest {
            seedAccount()
            val conflict = intent().copy(destinationPath = "/folder/report.final.txt", state = "CONFLICT")
            store.createTransfer(conflict)

            manager.retryConflict(conflict, overwrite = false, keepBoth = true)
            val first = requireNotNull(store.transfer("transfer"))
            assertEquals("/folder/report.final (1).txt", first.destinationPath)

            val secondConflict = first.copy(state = "CONFLICT")
            store.updateTransfer(secondConflict)
            manager.retryConflict(secondConflict, overwrite = false, keepBoth = true)
            assertEquals("/folder/report.final (2).txt", store.transfer("transfer")?.destinationPath)
        }

    private suspend fun seedAccount() {
        database.accountDao().upsert(
            eu.opencloud.android.next.core.database.AccountEntity(
                "account",
                "https://example.test",
                "user",
                "User",
                "BASIC",
                false,
            ),
        )
        database.spaceDao().insert(
            SpaceEntity(
                "account",
                "space",
                "Space",
                "project",
                null,
                null,
                "root",
                "https://example.test/dav",
                null,
                null,
            ),
        )
    }

    @Test fun `recovery schedules persisted intent and preserves the accepted work ID`() =
        runTest {
            val persistedId = UUID.randomUUID().toString()
            store.createTransfer(intent().copy(workId = persistedId))
            manager.reconcile()
            manager.reconcile()
            assertEquals(persistedId, store.transfer("transfer")?.workId)
            assertNotNull(workManager.getWorkInfoById(UUID.fromString(persistedId)).get())
            assertEquals(1, workManager.getWorkInfosForUniqueWork("transfer-transfer").get().size)
        }

    @Test fun `recovery schedules journaled discovery once and retains it until successful refresh`() =
        runTest {
            database.pendingDiscoveryDao().save(
                eu.opencloud.android.next.core.database
                    .PendingDiscoveryEntity("account", "space", "", "revision"),
            )
            manager.reconcileDiscovery()
            manager.reconcileDiscovery()
            assertNotNull(store.pendingDiscovery("revision"))
            assertEquals(1, workManager.getWorkInfosForUniqueWork("confirmed-discovery-revision").get().size)
        }

    @Test fun `interrupted scheduler job is recovered without resetting durable upload progress`() =
        runTest {
            seedAccount()
            store.createTransfer(intent())
            manager.reconcile()
            val scheduled = requireNotNull(store.transfer("transfer"))
            store.updateTransfer(scheduled.copy(state = "RUNNING", bytesTransferred = 50, verificationPending = true))
            workManager.cancelUniqueWork("transfer-transfer").result.get()
            manager.reconcile()
            manager.reconcile()
            val recovered = requireNotNull(store.transfer("transfer"))
            assertEquals(50L, recovered.bytesTransferred)
            org.junit.Assert.assertTrue(recovered.verificationPending)
            assertFalse(scheduled.workId == recovered.workId)
            val active =
                workManager
                    .getWorkInfosForUniqueWork(
                        "transfer-transfer",
                    ).get()
                    .filterNot { it.state.isFinished }
            assertEquals(1, active.size)
            assertEquals(recovered.workId, active.single().id.toString())
        }

    @Test fun `cancelled work cannot be resurrected by stale progress or reconciliation`() =
        runTest {
            store.createTransfer(intent())
            val claimed = requireNotNull(store.claimTransfer("transfer", UUID.randomUUID().toString(), 100))
            store.cancelTransfer("transfer")
            assertFalse(store.updateActiveTransfer(claimed.copy(bytesTransferred = 50, state = "SUCCEEDED")))
            manager.reconcile()
            assertEquals("CANCELLED", store.transfer("transfer")?.state)
            assertEquals(0, workManager.getWorkInfosForUniqueWork("transfer-transfer").get().size)
        }

    @Test fun `offline intent recovery coalesces work and appends a blocked continuation`() =
        runTest {
            seedAccount()
            val queue =
                eu.opencloud.android.next.core.database
                    .OfflineTraversalStore(database)
            val root =
                eu.opencloud.android.next.core.database.ResourceEntity(
                    "account",
                    "space",
                    "root",
                    null,
                    "/root",
                    "root",
                    eu.opencloud.android.next.core.model.ResourceKind.FOLDER,
                    null,
                    0,
                    null,
                    0,
                    0,
                )
            store.replaceFolderSnapshot("account", "space", null, listOf(root))
            store.setOfflinePinned(root, true)
            val run = queue.start(root)
            reconcileOfflineTraversals(context)
            reconcileOfflineTraversals(context)
            assertEquals(1, workManager.getWorkInfosForUniqueWork("offline-maintenance-true").get().size)
            scheduleOfflineTraversal(context, run.id)
            assertEquals(1, workManager.getWorkInfosForUniqueWork("offline-run-${run.id}").get().size)
            scheduleOfflineTraversal(context, run.id, continuation = true)
            reconcileOfflineTraversals(context)
            val chain = workManager.getWorkInfosForUniqueWork("offline-run-${run.id}").get()
            assertEquals(2, chain.size)
            assertEquals(1, chain.count { it.state == androidx.work.WorkInfo.State.BLOCKED })
        }

    @Test fun `missing DAV roots fail instead of synthesizing a username path`() {
        val space = SpaceEntity("account", "space", "Space", "personal", null, null, "root", null, null, null)
        assertThrows(OpenCloudException::class.java) { webDavRoot(space) }
        assertThrows(OpenCloudException::class.java) { webDavRoot(space.copy(rootWebDavUrl = " ")) }
        assertEquals(
            "https://data.example/custom/root",
            webDavRoot(
                space.copy(
                    rootWebDavUrl = "https://data.example/custom/root",
                ),
            ),
        )
    }

    @Test fun `pin request reusing a provider download persists selection immediately`() =
        runTest {
            database.accountDao().upsert(
                eu.opencloud.android.next.core.database.AccountEntity(
                    "account",
                    "https://example.test",
                    "user",
                    "User",
                    "BASIC",
                    false,
                ),
            )
            database.spaceDao().insert(
                SpaceEntity(
                    "account",
                    "space",
                    "Space",
                    "project",
                    null,
                    null,
                    "root",
                    "https://example.test/dav",
                    null,
                    null,
                ),
            )
            val resource =
                ResourceEntity(
                    "account",
                    "space",
                    "file",
                    null,
                    "/file",
                    "file",
                    ResourceKind.FILE,
                    null,
                    100,
                    null,
                    0,
                    0,
                )
            store.replaceFolderSnapshot("account", "space", null, listOf(resource))
            store.createTransfer(intent().copy(direction = "DOWNLOAD", resourceId = "file", offlinePin = false))
            assertEquals("transfer", manager.enqueueDownload(resource, offlinePin = true))
            assertEquals(true, store.resource("account", "space", "file")?.offlinePinned)
            assertEquals("transfer", manager.enqueueDownload(resource, offlinePin = false))
            assertEquals(true, store.resource("account", "space", "file")?.offlinePinned)
            assertEquals(false, store.transfer("transfer")?.offlinePin)
            val workId = requireNotNull(store.transfer("transfer")?.workId)
            assertNotNull(workManager.getWorkInfoById(UUID.fromString(workId)).get())
            assertEquals(1, workManager.getWorkInfosForUniqueWork("transfer-transfer").get().size)
        }

    @Test fun `offline scans skip intact copies and preserve failed jobs for explicit retry`() =
        runTest {
            val resource = seedDownloadResource()
            val directory =
                eu.opencloud.android.next.core.model.resourceCacheDirectory(
                    context.filesDir,
                    "account",
                    "space",
                )
            directory.mkdirs()
            val cached = java.io.File(directory, "offline-test").apply { writeBytes(ByteArray(100)) }
            database.resourceDao().upsert(resource.copy(hasLocalCopy = true, localPath = cached.path))
            repeat(2) { manager.ensureOfflineDownload(resource) }
            assertEquals(0, store.pendingTransfers().size)
            cached.delete()
            store.createTransfer(intent().copy(direction = "DOWNLOAD", resourceId = "file", state = "FAILED"))
            repeat(2) { manager.ensureOfflineDownload(resource) }
            assertEquals(0, store.pendingTransfers().size)
            assertEquals("FAILED", store.transfer("transfer")?.state)
        }

    @Test fun `offline scan replaces missing cached bytes and coalesces repeated scans`() =
        runTest {
            val resource = seedDownloadResource()
            manager.ensureOfflineDownload(resource)
            manager.ensureOfflineDownload(resource)
            assertEquals(1, store.pendingTransfers().size)
        }

    @Test fun `completed transfers stay completed during startup reconciliation`() =
        runTest {
            store.createTransfer(intent().copy(state = "SUCCEEDED"))
            manager.reconcile()
            assertEquals("SUCCEEDED", store.transfer("transfer")?.state)
            assertEquals(0, workManager.getWorkInfosForUniqueWork("transfer-transfer").get().size)
        }

    private suspend fun seedDownloadResource(): ResourceEntity {
        database.accountDao().upsert(
            eu.opencloud.android.next.core.database.AccountEntity(
                "account",
                "https://example.test",
                "user",
                "User",
                "BASIC",
                false,
            ),
        )
        database.spaceDao().insert(
            SpaceEntity(
                "account",
                "space",
                "Space",
                "project",
                null,
                null,
                "root",
                "https://example.test/dav",
                null,
                null,
            ),
        )
        val resource =
            ResourceEntity(
                "account",
                "space",
                "file",
                null,
                "/file",
                "file",
                ResourceKind.FILE,
                null,
                100,
                "version",
                0,
                0,
            )
        store.replaceFolderSnapshot("account", "space", null, listOf(resource))
        return resource
    }

    @Test fun `remove all local copies unpins folders and keeps remote metadata and other accounts`() =
        runTest {
            val resource = seedDownloadResource()
            val directory =
                eu.opencloud.android.next.core.model.resourceCacheDirectory(
                    context.filesDir,
                    "account",
                    "space",
                )
            directory.mkdirs()
            val cached = java.io.File(directory, "bulk-remove").apply { writeBytes(ByteArray(100)) }
            val other =
                resource.copy(
                    accountId = "other",
                    hasLocalCopy = true,
                    localPath = "/other/private-file",
                    offlinePinned = true,
                )
            database.resourceDao().upsert(other)
            database.resourceDao().upsert(
                resource.copy(hasLocalCopy = true, localPath = cached.path, offlinePinned = true),
            )
            val folder = resource.copy(remoteId = "folder", kind = ResourceKind.FOLDER, offlinePinned = true)
            database.resourceDao().upsert(folder)
            val queue =
                eu.opencloud.android.next.core.database
                    .OfflineTraversalStore(database)
            val run = queue.start(folder)
            store.createTransfer(intent().copy(id = "download", direction = "DOWNLOAD", resourceId = resource.remoteId))
            store.createTransfer(intent())
            manager.removeAllLocalCopies("account")
            assertFalse(cached.exists())
            val remaining = requireNotNull(store.resource("account", "space", "file"))
            assertFalse(remaining.hasLocalCopy)
            assertFalse(remaining.offlinePinned)
            assertEquals(resource.path, remaining.path)
            assertEquals(resource.eTag, remaining.eTag)
            assertEquals("CANCELLED", store.transfer("download")?.state)
            assertEquals("QUEUED", store.transfer("transfer")?.state)
            assertEquals("CANCELLED", queue.dao.run(run.id)?.state)
            assertEquals(other, store.resource("other", "space", "file"))
        }

    private fun intent() =
        TransferEntity(
            id = "transfer",
            accountId = "account",
            spaceId = "space",
            resourceId = null,
            direction = "UPLOAD",
            sourceUri = "content://source",
            destinationPath = "/file",
            displayName = "file",
            mimeType = null,
            bytesTotal = 100,
            createdAtEpochMillis = 0,
            updatedAtEpochMillis = 0,
            notBeforeEpochMillis = Long.MAX_VALUE,
        )
}
