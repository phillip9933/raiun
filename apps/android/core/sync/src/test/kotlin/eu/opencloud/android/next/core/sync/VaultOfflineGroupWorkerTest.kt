package eu.opencloud.android.next.core.sync

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import androidx.room.Room
import androidx.work.ListenableWorker
import androidx.work.WorkerFactory
import androidx.work.WorkerParameters
import androidx.work.testing.TestListenableWorkerBuilder
import androidx.work.workDataOf
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.database.VAULT_GROUP_LOCATION_KIND
import eu.opencloud.android.next.core.database.VaultGroupLease
import eu.opencloud.android.next.core.database.vaultOfflineGroups
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.VaultDavEntry
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File
import java.util.UUID
import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicInteger

@RunWith(RobolectricTestRunner::class)
class VaultOfflineGroupWorkerTest {
    private val context: Context = RuntimeEnvironment.getApplication()
    private val account = AccountEntity("account", "https://example.test/", "u", "U", "BASIC", false)
    private val root = File(context.cacheDir, "group-worker-${UUID.randomUUID()}")
    private lateinit var database: FileBrowserDatabase
    private lateinit var store: FileBrowserStore
    private val plans = VaultOfflineGroupPlanStore(root, jvmOfflineDurability(root))
    private var leaseValid = true
    private var downloads = 0
    private val ownershipReads = AtomicInteger()
    private var behavior: suspend (VaultDownloadJob, VaultDownloadStore, () -> Boolean, (Long) -> Unit) -> Long =
        { job, payloads, permit, progress ->
            assertTrue(permit())
            payloads.partial(job).writeBytes(ByteArray(job.source.size.toInt()))
            progress(job.source.size)
            job.source.size
        }
    private val execution =
        object : VaultDownloadExecution {
            override fun beginLease(accountId: String): () -> Boolean = { leaseValid }

            override suspend fun download(
                job: VaultDownloadJob,
                payloads: VaultDownloadStore,
                permit: () -> Boolean,
                progress: (Long) -> Unit,
            ): Long {
                downloads++
                return behavior(job, payloads, permit, progress)
            }
        }

    @Before fun setup() =
        runBlocking {
            database =
                Room
                    .inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java)
                    .setQueryCallback({ sql, _ ->
                        if (sql.contains(
                                "SELECT * FROM vault_offline_groups WHERE id",
                            )
                        ) {
                            ownershipReads.incrementAndGet()
                        }
                    }, Executor { it.run() })
                    .build()
            store = FileBrowserStore(database)
            database.accountDao().upsert(account)
        }

    @After fun close() {
        database.close()
        root.deleteRecursively()
    }

    @Test fun workManagerRetainsPublicTwoArgumentConstructor() {
        val constructor =
            VaultOfflineGroupWorker::class.java.getConstructor(Context::class.java, WorkerParameters::class.java)
        assertNotNull(constructor)
    }

    @Test fun moreThan128MembersEndAwaitingUnlockAndNeverClaimAuthenticatedOfflineSuccess() =
        runBlocking {
            val seed = seed(130)
            assertEquals(ListenableWorker.Result.success(), worker(seed.lease.group.id).doWork())
            assertEquals(130, downloads)
            val current = requireNotNull(store.vaultOfflineGroups().find(seed.lease.group.id))
            assertEquals("AWAITING_UNLOCK", current.group.state)
            assertEquals("AWAITING_UNLOCK", current.parent?.state)
            val parent = requireNotNull(current.parent)
            assertTrue(parent.verificationPending)
            assertEquals(130L * 64, parent.bytesTransferred)
            assertNull(current.group.pendingPublicationId)
            // Synthetic bytes intentionally have no rclone authentication; no offline publisher is called by this worker.
            assertEquals(
                0,
                database
                    .vaultOfflineGroupDao()
                    .publications(
                        seed.context.owner.accountId,
                        seed.context.owner.incarnation,
                        null,
                    ).size,
            )
        }

    @Test fun emptyDirectoryNeedsNoDownloadAndASecondWorkerDoesNotReenterAwaitingGroup() =
        runBlocking {
            val seed = seed(0)
            assertEquals(ListenableWorker.Result.success(), worker(seed.lease.group.id).doWork())
            assertEquals(ListenableWorker.Result.success(), worker(seed.lease.group.id).doWork())
            assertEquals(0, downloads)
            assertEquals("AWAITING_UNLOCK", store.transfer(seed.lease.group.id)?.state)
        }

    @Test fun replacementWorkAndCancelledGroupAreIgnoredBeforePrivatePayloadExecution() =
        runBlocking {
            val seed = seed(1)
            val stale = worker(seed.lease.group.id)
            assertTrue(store.recordScheduledWork(requireNotNull(seed.lease.parent), UUID.randomUUID().toString(), 2))
            assertEquals(ListenableWorker.Result.success(), stale.doWork())
            assertEquals(0, downloads)
            store.cancelTransfer(seed.lease.group.id)
            assertEquals(ListenableWorker.Result.success(), worker(seed.lease.group.id).doWork())
            assertEquals("CANCELLED", store.transfer(seed.lease.group.id)?.state)
            assertEquals(0, downloads)
        }

    @Test fun changedRoomMemberDescriptorRefusesTransportAndAwaitingState() =
        runBlocking {
            val seed = seed(1)
            val row = store.vaultOfflineGroups().memberPage(seed.lease).single { it.kind == "FILE" }
            database.vaultOfflineGroupDao().updateMember(row.copy(descriptorDigest = "f".repeat(64)))
            assertEquals(ListenableWorker.Result.failure(), worker(seed.lease.group.id).doWork())
            assertEquals(0, downloads)
            assertEquals("FAILED", store.transfer(seed.lease.group.id)?.state)
            assertEquals("DOWNLOAD_INTEGRITY", store.transfer(seed.lease.group.id)?.errorCode)
            assertEquals(
                OpenCloudError.DownloadIntegrity.safeMessage(context),
                store.transfer(seed.lease.group.id)?.error,
            )
        }

    @Test fun omittedPrivateTailCannotProduceAwaitingUnlock() =
        runBlocking {
            val seed = seed(1)
            val file = File(groupDirectory(seed.context), "plan.db")
            SQLiteDatabase
                .openDatabase(file.path, null, SQLiteDatabase.OPEN_READWRITE)
                .use { it.execSQL("DELETE FROM entries WHERE seq = 1") }
            assertEquals(ListenableWorker.Result.failure(), worker(seed.lease.group.id).doWork())
            assertEquals(0, downloads)
            assertEquals("FAILED", store.transfer(seed.lease.group.id)?.state)
        }

    @Test fun credentialRevocationDuringProgressPreservesPartialCiphertextAndDefersWithoutSuccess() =
        runBlocking {
            val seed = seed(1)
            behavior = { job, payloads, permit, progress ->
                payloads.partial(job).writeBytes(ByteArray(8))
                progress(8)
                leaseValid = false
                assertFalse(permit())
                throw CancellationException("Synthetic credential revocation")
            }
            try {
                worker(seed.lease.group.id).doWork()
                fail("Revocation should cancel the current worker")
            } catch (_: CancellationException) {
                assertEquals("RETRY", store.transfer(seed.lease.group.id)?.state)
            }
            val current = requireNotNull(store.vaultOfflineGroups().find(seed.lease.group.id))
            val member = store.vaultOfflineGroups().memberPage(current).single { it.kind == "FILE" }
            assertEquals(8L, member.checkpointBytes)
            assertEquals("RUNNING", member.state)
            assertFalse(current.parent!!.verificationPending)
            plans.open(seed.context.owner, seed.context.groupId).use { plan ->
                val file = plan.page().single { it.kind == VaultOfflineGroupMemberKind.FILE }
                val partial = plans.payloads(seed.context.owner, seed.context.groupId).partial(plan.fileJob(file))
                assertEquals(8L, partial.length())
            }
        }

    @Test fun transientFailurePersistsDeadlineAndAttemptBudgetWithoutRepeatingBeforeDeadline() =
        runBlocking {
            val seed = seed(1)
            behavior = { _, _, _, _ -> throw OpenCloudException(OpenCloudError.RateLimited(60)) }
            val worker = worker(seed.lease.group.id)
            assertEquals(ListenableWorker.Result.retry(), worker.doWork())
            val deferred = requireNotNull(store.transfer(seed.lease.group.id))
            assertEquals("RETRY", deferred.state)
            assertEquals(1, deferred.attemptCount)
            assertFalse(deferred.error.isNullOrBlank())
            assertTrue(deferred.notBeforeEpochMillis > System.currentTimeMillis())
            assertEquals(ListenableWorker.Result.retry(), worker.doWork())
            assertEquals(1, downloads)
        }

    @Test fun denseProgressCallbacksAndPermitsDoNotCreatePerBufferRoomTransactions() =
        runBlocking {
            val seed = seed(1)
            behavior = { job, payloads, permit, progress ->
                payloads.partial(job).writeBytes(ByteArray(job.source.size.toInt()))
                val before = ownershipReads.get()
                for (bytes in 1L..job.source.size) {
                    assertTrue(permit())
                    progress(bytes)
                }
                assertTrue(ownershipReads.get() - before < 20)
                job.source.size
            }
            assertEquals(ListenableWorker.Result.success(), worker(seed.lease.group.id).doWork())
            val current = requireNotNull(store.vaultOfflineGroups().find(seed.lease.group.id))
            val file = store.vaultOfflineGroups().memberPage(current).single { it.kind == "FILE" }
            assertTrue(file.revision <= 4)
            assertEquals(64L, file.checkpointBytes)
            assertEquals("AWAITING_UNLOCK", current.group.state)
        }

    @Test fun persistedRunningIntentRestartsOnlyForItsExactWorkIdAndGetsFreshCasOwnership() =
        runBlocking {
            val seed = seed(1)
            val worker = worker(seed.lease.group.id)
            val old = requireNotNull(store.vaultOfflineGroups().claim(seed.lease, worker.id.toString(), 2))
            assertEquals(ListenableWorker.Result.success(), worker(seed.lease.group.id).doWork())
            assertEquals(0, downloads)
            assertEquals("RUNNING", store.transfer(seed.lease.group.id)?.state)
            assertEquals(ListenableWorker.Result.success(), worker.doWork())
            assertEquals(1, downloads)
            assertEquals("AWAITING_UNLOCK", store.transfer(seed.lease.group.id)?.state)
            assertEquals(2, store.transfer(seed.lease.group.id)?.attemptCount)
            assertFalse(store.vaultOfflineGroups().isCurrent(old.lease))
        }

    @Test fun runningReclaimWaitsForOldPrivateAttemptBeforeOpeningAnyCiphertextWriter() =
        runBlocking {
            val seed = seed(1)
            val worker = worker(seed.lease.group.id)
            requireNotNull(store.vaultOfflineGroups().claim(seed.lease, worker.id.toString(), 2))
            plans.beginAttempt(seed.context.owner, seed.context.groupId).use {
                assertEquals(ListenableWorker.Result.retry(), worker.doWork())
                assertEquals(0, downloads)
                assertEquals("RETRY", store.transfer(seed.lease.group.id)?.state)
            }
            val fresh = worker(seed.lease.group.id)
            val current = requireNotNull(store.vaultOfflineGroups().find(seed.lease.group.id))
            requireNotNull(store.vaultOfflineGroups().retry(current, fresh.id.toString(), System.currentTimeMillis()))
            assertEquals(ListenableWorker.Result.success(), fresh.doWork())
            assertEquals(1, downloads)
            assertEquals("AWAITING_UNLOCK", store.transfer(seed.lease.group.id)?.state)
        }

    @Test fun retryReusesOnlyLocallyRevalidatedCompletedPayloadAndStillStopsAtUnlockBarrier() =
        runBlocking {
            val seed = seed(2)
            behavior = { job, payloads, permit, progress ->
                assertTrue(permit())
                if (downloads == 2) throw OpenCloudException(OpenCloudError.Connectivity)
                payloads.partial(job).writeBytes(ByteArray(job.source.size.toInt()))
                progress(job.source.size)
                job.source.size
            }
            assertEquals(ListenableWorker.Result.retry(), worker(seed.lease.group.id).doWork())
            val retryWorker = worker(seed.lease.group.id)
            val current = requireNotNull(store.vaultOfflineGroups().find(seed.lease.group.id))
            requireNotNull(store.vaultOfflineGroups().retry(current, retryWorker.id.toString(), 3))
            assertEquals(ListenableWorker.Result.success(), retryWorker.doWork())
            assertEquals(3, downloads)
            assertEquals("AWAITING_UNLOCK", store.transfer(seed.lease.group.id)?.state)
            assertEquals(128L, store.transfer(seed.lease.group.id)?.bytesTransferred)
        }

    @Test fun removedAndReaddedAccountCannotCheckpointTheOldAttempt() =
        runBlocking {
            val seed = seed(1)
            behavior = { _, _, permit, _ ->
                runBlocking {
                    store.removeAccount(account.id)
                    database.accountDao().upsert(account)
                }
                leaseValid = false
                assertFalse(permit())
                throw CancellationException("Synthetic account replacement")
            }
            try {
                worker(seed.lease.group.id).doWork()
                fail("Revoked owner should stop transport")
            } catch (_: CancellationException) {
                assertNull(store.transfer(seed.lease.group.id))
            }
            val fresh = requireNotNull(store.vaultOfflineGroups().captureOwner(account.id))
            assertNotEquals(seed.context.owner.incarnation, fresh.incarnation)
            assertNull(store.vaultOfflineGroups().find(seed.lease.group.id))
        }

    private data class Seed(
        val context: VaultOfflineGroupContext,
        val lease: VaultGroupLease,
    )

    private suspend fun seed(files: Int): Seed {
        val groups = store.vaultOfflineGroups()
        val owner = requireNotNull(groups.captureOwner(account.id))
        val id = UUID.randomUUID().toString()
        val location =
            VaultLocation(
                account.id,
                "",
                VaultLocationKind.FOLDER_VAULT,
                "drive",
                "vault-root",
                "source-root",
                "https://example.test/",
                "https://example.test/dav/",
                "vault",
                true,
            )
        val identity = VaultIdentity(account.id, location.canonicalServer, location.driveId, location.remoteVaultId)
        val captured = VaultOfflineGroupContext(id, owner, identity, location, "vault/selected", null, "a".repeat(64))
        val preparation = plans.begin(captured)
        try {
            var lease = requireNotNull(groups.beginPreparation(owner, captured.descriptor()))
            val admissions = mutableListOf(preparation.appendDirectory(source("selected", true)).admission())
            repeat(files) { admissions += preparation.appendFile(source("selected/file$it", false)).admission() }
            for (batch in admissions.chunked(128)) {
                lease =
                    requireNotNull(
                        groups.appendMembers(
                            lease,
                            batch.first().sequence,
                            batch,
                            lease.group.stagingChainDigest,
                            "b".repeat(64),
                        ),
                    )
            }
            val seal = preparation.seal(ByteArray(80) { it.toByte() })
            val parent =
                TransferEntity(
                    id,
                    account.id,
                    "drive",
                    null,
                    "DOWNLOAD",
                    "vault-offline-group:vault-root",
                    captured.selectedEncryptedRoot,
                    "Encrypted offline folder",
                    null,
                    seal.ciphertextBytes,
                    locationKind = VAULT_GROUP_LOCATION_KIND,
                    offlinePin = true,
                    createdAtEpochMillis = 1,
                    updatedAtEpochMillis = 1,
                )
            lease = requireNotNull(groups.sealAndEnqueue(lease, seal, parent) { true })
            assertTrue(preparation.finishPrepared { true })
            return Seed(captured, lease)
        } finally {
            preparation.close()
        }
    }

    private fun source(
        relative: String,
        directory: Boolean,
    ) = VaultDavEntry(
        relative,
        "vault/$relative",
        relative.substringAfterLast('/'),
        directory,
        if (directory) 0 else 64,
        if (directory) null else "\"v1\"",
        "https://example.test/dav/vault/$relative",
    )

    private fun groupDirectory(captured: VaultOfflineGroupContext): File =
        File(
            File(
                File(root, VaultOfflineGroupPlanCodec.digest(captured.owner.accountId.toByteArray())),
                captured.owner.incarnation,
            ),
            captured.groupId,
        )

    private fun worker(id: String): VaultOfflineGroupWorker =
        TestListenableWorkerBuilder<VaultOfflineGroupWorker>(context)
            .setInputData(workDataOf(TransferWorker.TRANSFER_ID to id))
            .setWorkerFactory(
                object : WorkerFactory() {
                    override fun createWorker(
                        appContext: Context,
                        workerClassName: String,
                        workerParameters: WorkerParameters,
                    ): ListenableWorker =
                        VaultOfflineGroupWorker(
                            appContext,
                            workerParameters,
                            store.vaultOfflineGroups(),
                            plans,
                            execution,
                        )
                },
            ).build()
}
