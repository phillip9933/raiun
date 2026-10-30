package eu.opencloud.android.next.core.sync

import android.content.Context
import androidx.room.Room
import androidx.work.Configuration
import androidx.work.ListenableWorker
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerFactory
import androidx.work.WorkerParameters
import androidx.work.testing.SynchronousExecutor
import androidx.work.testing.WorkManagerTestInitHelper
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.database.VAULT_GROUP_LOCATION_KIND
import eu.opencloud.android.next.core.database.VaultGroupDescriptor
import eu.opencloud.android.next.core.database.VaultGroupMemberAdmission
import eu.opencloud.android.next.core.database.VaultGroupSeal
import eu.opencloud.android.next.core.database.vaultOfflineGroups
import eu.opencloud.android.next.core.model.AppClock
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
class VaultOfflineGroupSchedulingTest {
    private val context = RuntimeEnvironment.getApplication()
    private lateinit var database: FileBrowserDatabase
    private lateinit var store: FileBrowserStore
    private lateinit var workManager: WorkManager
    private val workerTypes = mutableListOf<String>()
    private var now = 1_000L

    @Before fun setup() =
        runBlocking {
            database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
            store = FileBrowserStore(database)
            database.accountDao().upsert(
                AccountEntity("account", "https://example.test/", "user", "User", "BASIC", false),
            )
            WorkManagerTestInitHelper.initializeTestWorkManager(
                context,
                Configuration
                    .Builder()
                    .setExecutor(SynchronousExecutor())
                    .setWorkerFactory(
                        object : WorkerFactory() {
                            override fun createWorker(
                                appContext: Context,
                                workerClassName: String,
                                workerParameters: WorkerParameters,
                            ): ListenableWorker {
                                workerTypes.add(workerClassName)
                                return object : Worker(appContext, workerParameters) {
                                    override fun doWork(): Result = Result.retry()
                                }
                            }
                        },
                    ).build(),
            )
            workManager = WorkManager.getInstance(context)
        }

    @After fun close() {
        WorkManagerTestInitHelper.closeWorkDatabase()
        database.close()
    }

    @Test fun repeatedSchedulingUsesGroupWorkerAndDoesNotInvalidateItsRunningLease() =
        runBlocking {
            val groups = store.vaultOfflineGroups()
            val owner = requireNotNull(groups.captureOwner("account"))
            val id = UUID.randomUUID().toString()
            val hash = "a".repeat(64)
            val preparing =
                requireNotNull(
                    groups.beginPreparation(
                        owner,
                        VaultGroupDescriptor(id, "drive", "vault", hash, id, hash, hash, id),
                    ),
                )
            val populated =
                requireNotNull(
                    groups.appendMembers(
                        preparing,
                        0,
                        listOf(VaultGroupMemberAdmission(0, UUID.randomUUID().toString(), hash, "DIRECTORY")),
                        preparing.group.stagingChainDigest,
                        hash,
                    ),
                )
            val parent =
                TransferEntity(
                    id,
                    "account",
                    "drive",
                    null,
                    "DOWNLOAD",
                    "vault-offline-group:vault",
                    "Secret.vault",
                    "Encrypted folder",
                    "application/octet-stream",
                    0,
                    offlinePin = true,
                    locationKind = VAULT_GROUP_LOCATION_KIND,
                    createdAtEpochMillis = now,
                    updatedAtEpochMillis = now,
                )
            val queued =
                requireNotNull(groups.sealAndEnqueue(populated, VaultGroupSeal(id, hash, 1, 0, 0), parent) { true })
            val manager = TransferManager(context, store, workManager, AppClock { ++now })
            manager.scheduleVaultDownload(requireNotNull(queued.parent))
            val scheduled = requireNotNull(groups.find(id))
            val attempt = requireNotNull(groups.claim(scheduled, requireNotNull(scheduled.parent?.workId), ++now))
            val activeParent = requireNotNull(attempt.lease.parent)
            manager.scheduleVaultDownload(activeParent)
            assertEquals(activeParent, store.transfer(id))
            assertTrue(groups.isCurrent(attempt.lease))
            val request = workManager.getWorkInfosForUniqueWork("transfer-$id").get().single()
            assertEquals(activeParent.workId, request.id.toString())
            assertEquals(listOf(VaultOfflineGroupWorker::class.java.name), workerTypes)
        }
}
