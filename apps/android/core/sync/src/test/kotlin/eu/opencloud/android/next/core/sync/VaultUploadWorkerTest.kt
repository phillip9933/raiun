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
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class VaultUploadWorkerTest {
    private val context: Context = RuntimeEnvironment.getApplication()
    private lateinit var database: FileBrowserDatabase
    private lateinit var store: FileBrowserStore

    @Before fun setUp() {
        database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
        store = FileBrowserStore(database)
    }

    @After fun tearDown() = database.close()

    @Test fun `WorkManager reflection retains the public two argument constructor`() {
        org.junit.Assert.assertNotNull(
            VaultUploadWorker::class.java.getConstructor(Context::class.java, WorkerParameters::class.java),
        )
    }

    @Test fun `busy encrypted upload remains scheduled for retry without consuming an attempt`() =
        runTest {
            seed()
            store.enqueueCiphertextUpload(transfer("earlier").copy(state = "RUNNING", workId = "other-worker"))
            store.enqueueCiphertextUpload(transfer("waiting"))
            assertEquals(ListenableWorker.Result.retry(), worker("waiting").doWork())
            val waiting = requireNotNull(store.transfer("waiting"))
            assertEquals("QUEUED", waiting.state)
            assertEquals(0, waiting.attemptCount)
            assertNull(waiting.error)
        }

    @Test fun `obsolete encrypted worker does not retry a replacement intent`() =
        runTest {
            seed()
            store.enqueueCiphertextUpload(transfer("waiting").copy(workId = "replacement"))
            assertEquals(ListenableWorker.Result.success(), worker("waiting").doWork())
            assertEquals("replacement", store.transfer("waiting")?.workId)
            assertEquals(0, store.transfer("waiting")?.attemptCount)
        }

    @Test fun `cancelled encrypted upload does not retry or read its payload`() =
        runTest {
            seed()
            store.enqueueCiphertextUpload(transfer("waiting"))
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
            resourceId = null,
            direction = "UPLOAD",
            sourceUri = null,
            destinationPath = "vault/ciphertext",
            displayName = "Encrypted upload",
            mimeType = null,
            bytesTotal = 100,
            locationKind = "VAULT",
            createdAtEpochMillis = 0,
            updatedAtEpochMillis = 0,
        )

    private fun worker(transferId: String): VaultUploadWorker =
        TestListenableWorkerBuilder<VaultUploadWorker>(context)
            .setInputData(workDataOf(TransferWorker.TRANSFER_ID to transferId))
            .setWorkerFactory(
                object : WorkerFactory() {
                    override fun createWorker(
                        appContext: Context,
                        workerClassName: String,
                        workerParameters: WorkerParameters,
                    ): ListenableWorker = VaultUploadWorker(appContext, workerParameters, store)
                },
            ).build()
}
