package eu.opencloud.android.next.core.sync

import android.content.Context
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
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class VaultDownloadWorkerTest {
    private val context: Context = RuntimeEnvironment.getApplication()
    private lateinit var database: FileBrowserDatabase
    private lateinit var store: FileBrowserStore
    private val directory =
        java.nio.file.Files
            .createTempDirectory("download-worker")
            .toFile()
    private val payloads = VaultDownloadStore(directory)
    private val execution =
        object : VaultDownloadExecution {
            override fun beginLease(accountId: String): () -> Boolean = { true }

            override suspend fun download(
                job: VaultDownloadJob,
                payloads: VaultDownloadStore,
                permit: () -> Boolean,
                progress: (Long) -> Unit,
            ): Long {
                org.junit.Assert.assertTrue(permit())
                payloads.partial(job).writeBytes(ByteArray(job.source.size.toInt()))
                progress(job.source.size)
                return job.source.size
            }
        }

    @Before fun setUp() {
        database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
        store = FileBrowserStore(database)
    }

    @After fun tearDown() {
        database.close()
        directory.deleteRecursively()
    }

    @Test fun `WorkManager reflection retains the public two argument constructor`() {
        org.junit.Assert.assertNotNull(
            VaultDownloadWorker::class.java.getConstructor(Context::class.java, WorkerParameters::class.java),
        )
    }

    @Test fun `raw download finishes awaiting authentication and never succeeds offline early`() =
        runTest {
            seed()
            val location =
                VaultLocation(
                    "account",
                    "",
                    VaultLocationKind.FOLDER_VAULT,
                    "space",
                    "root",
                    "source-root",
                    "https://example.test/",
                    "https://example.test/dav/",
                    "vault",
                    true,
                )
            val source =
                eu.opencloud.android.next.core.network.VaultDavEntry(
                    "source",
                    "vault/ciphertext",
                    "ciphertext",
                    false,
                    100,
                    null,
                    "https://example.test/dav/vault/ciphertext",
                )
            val job = payloads.create(location, source, null)
            org.junit.Assert.assertTrue(payloads.finishPrepared(job.id) { true })
            store.enqueueCiphertextDownload(transfer(job.id))
            assertEquals(ListenableWorker.Result.success(), worker(job.id).doWork())
            val row = requireNotNull(store.transfer(job.id))
            assertEquals("AWAITING_UNLOCK", row.state)
            assertEquals(true, row.verificationPending)
            assertEquals(100L, row.bytesTransferred)
            assertEquals(job, payloads.read(job.id))
        }

    @Test fun `awaiting unlock never retries transport`() =
        runTest {
            seed()
            store.enqueueCiphertextDownload(transfer("waiting").copy(state = "AWAITING_UNLOCK"))
            assertEquals(ListenableWorker.Result.success(), worker("waiting").doWork())
            assertEquals("AWAITING_UNLOCK", store.transfer("waiting")?.state)
            assertEquals(0, store.transfer("waiting")?.attemptCount)
        }

    @Test fun `obsolete encrypted download worker does not retry a replacement intent`() =
        runTest {
            seed()
            store.enqueueCiphertextDownload(transfer("waiting").copy(workId = "replacement"))
            assertEquals(ListenableWorker.Result.success(), worker("waiting").doWork())
            assertEquals("replacement", store.transfer("waiting")?.workId)
            assertEquals(0, store.transfer("waiting")?.attemptCount)
        }

    @Test fun `cancelled encrypted download does not retry or read its payload`() =
        runTest {
            seed()
            store.enqueueCiphertextDownload(transfer("waiting"))
            store.cancelTransfer("waiting")
            assertEquals(ListenableWorker.Result.success(), worker("waiting").doWork())
            assertEquals("CANCELLED", store.transfer("waiting")?.state)
        }

    private suspend fun seed() {
        database.accountDao().upsert(AccountEntity("account", "https://example.test", "user", "User", "BASIC", false))
    }

    private fun transfer(id: String) =
        TransferEntity(
            id = id,
            accountId = "account",
            spaceId = "space",
            resourceId = "source",
            direction = "DOWNLOAD",
            sourceUri = "vault-offline:root",
            destinationPath = "vault/ciphertext",
            displayName = "Encrypted offline download",
            mimeType = null,
            bytesTotal = 100,
            locationKind = "VAULT",
            offlinePin = true,
            createdAtEpochMillis = 0,
            updatedAtEpochMillis = 0,
        )

    private fun worker(transferId: String): VaultDownloadWorker =
        TestListenableWorkerBuilder<VaultDownloadWorker>(context)
            .setInputData(workDataOf(TransferWorker.TRANSFER_ID to transferId))
            .setWorkerFactory(
                object : WorkerFactory() {
                    override fun createWorker(
                        appContext: Context,
                        workerClassName: String,
                        workerParameters: WorkerParameters,
                    ): ListenableWorker = VaultDownloadWorker(appContext, workerParameters, store, payloads, execution)
                },
            ).build()
}
