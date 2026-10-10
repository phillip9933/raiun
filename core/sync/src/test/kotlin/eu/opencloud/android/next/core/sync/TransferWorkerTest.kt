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
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.database.TransferState
import eu.opencloud.android.next.core.network.TransferClient
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class TransferWorkerTest {
    private val context: Context = RuntimeEnvironment.getApplication()
    private lateinit var database: FileBrowserDatabase
    private lateinit var store: FileBrowserStore

    @Before fun setUp() {
        database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
        store = FileBrowserStore(database)
    }

    @After fun tearDown() = database.close()

    @Test fun `shared location cannot fall back to a matching ordinary drive`() =
        runTest {
            seed()
            val transfer = requireNotNull(store.transfer("transfer"))
            store.updateTransfer(transfer.copy(direction = "DOWNLOAD", locationKind = "SHARED_FOLDER"))
            assertEquals(ListenableWorker.Result.failure(), worker(CancellationException("must not execute")).doWork())
            assertEquals("UNSUPPORTED", store.transfer("transfer")?.errorCode)
            assertEquals(0, store.transfer("transfer")?.attemptCount)
        }

    @Test fun `worker persists only safe error text`() =
        runTest {
            seed()
            val worker = worker(IllegalStateException("Bearer secret https://private/path"))
            assertEquals(ListenableWorker.Result.failure(), worker.doWork())
            val persisted = requireNotNull(store.transfer("transfer"))
            assertEquals(TransferState.FAILED.name, persisted.state)
            assertEquals("The operation could not be completed.", persisted.error)
        }

    @Test fun `busy upload destination defers work without failing or consuming a network attempt`() =
        runTest {
            seed()
            val current = requireNotNull(store.transfer("transfer"))
            store.createTransfer(current.copy(id = "earlier", state = "RUNNING", workId = "other-worker"))
            assertEquals(ListenableWorker.Result.retry(), worker(IllegalStateException("must not execute")).doWork())
            val waiting = requireNotNull(store.transfer("transfer"))
            assertEquals("QUEUED", waiting.state)
            assertEquals(0, waiting.attemptCount)
            assertNull(waiting.error)
        }

    @Test fun `worker cancellation is not failure or retry`() =
        runTest {
            seed()
            val cancelled = CancellationException("cancelled")
            try {
                worker(cancelled).doWork()
                org.junit.Assert.fail("Cancellation must escape doWork")
            } catch (actual: CancellationException) {
                assertTrue(actual === cancelled || actual.cause === cancelled)
            }
            val persisted = requireNotNull(store.transfer("transfer"))
            assertEquals(TransferState.RUNNING.name, persisted.state)
            assertNull(persisted.error)
        }

    @Test fun `durable cancellation prevents a stale worker from running`() =
        runTest {
            seed()
            store.cancelTransfer("transfer")
            assertEquals(ListenableWorker.Result.success(), worker(IllegalStateException("Must not execute")).doWork())
            assertEquals("CANCELLED", store.transfer("transfer")?.state)
            assertNull(store.transfer("transfer")?.error)
        }

    @Test fun `Retry-After survives worker recreation and prevents early network work`() =
        runTest {
            seed()
            val error =
                eu.opencloud.android.next.core.network
                    .TransferHttpException(429, 3600)
            val first = worker(error)
            assertEquals(ListenableWorker.Result.retry(), first.doWork())
            val pending = requireNotNull(store.transfer("transfer"))
            assertEquals("RATE_LIMITED", pending.errorCode)
            assertTrue(pending.notBeforeEpochMillis > System.currentTimeMillis())
            val second = worker(IllegalStateException("Must not execute"))
            store.updateTransfer(pending.copy(workId = second.id.toString()))
            assertEquals(ListenableWorker.Result.retry(), second.doWork())
            assertEquals(1, store.transfer("transfer")?.attemptCount)
        }

    @Test fun obsoleteWorkerCannotFailReplacement() =
        runTest {
            seed()
            val worker =
                worker(IllegalStateException("old failure")) { transfer ->
                    store.updateTransfer(transfer.copy(state = "QUEUED", workId = "replacement"))
                }
            org.junit.Assert.assertThrows(CancellationException::class.java) {
                kotlinx.coroutines.runBlocking { worker.doWork() }
            }
            assertEquals("QUEUED", store.transfer("transfer")?.state)
            assertEquals("replacement", store.transfer("transfer")?.workId)
            assertNull(store.transfer("transfer")?.error)
        }

    @Test fun `guarded upload timeout retries automatically and retains progress`() =
        runTest {
            seed()
            store.updateTransfer(requireNotNull(store.transfer("transfer")).copy(bytesTotal = 1000))
            val attempt =
                worker(java.net.SocketTimeoutException()) { transfer ->
                    store.updateActiveTransfer(transfer.copy(bytesTransferred = 500))
                }
            assertEquals(ListenableWorker.Result.retry(), attempt.doWork())
            val pending = requireNotNull(store.transfer("transfer"))
            assertEquals("RETRY", pending.state)
            assertEquals("TIMEOUT", pending.errorCode)
            assertEquals(500L, pending.bytesTransferred)
            assertEquals(attempt.id.toString(), pending.workId)
            assertTrue(pending.notBeforeEpochMillis > System.currentTimeMillis())
        }

    @Test fun `HTTP 502 leaves a durable retry state for a guarded upload`() =
        runTest {
            seed()
            store.updateTransfer(requireNotNull(store.transfer("transfer")).copy(bytesTotal = 149_000_000))
            val attempt =
                worker(
                    eu.opencloud.android.next.core.network
                        .TransferHttpException(502),
                )
            assertEquals(ListenableWorker.Result.retry(), attempt.doWork())
            val pending = requireNotNull(store.transfer("transfer"))
            assertEquals("RETRY", pending.state)
            assertEquals("SERVER_502", pending.errorCode)
            assertTrue(pending.notBeforeEpochMillis > System.currentTimeMillis())
            assertEquals(attempt.id.toString(), pending.workId)
        }

    @Test fun `pre-existing backup target becomes a persisted conflict for user resolution`() =
        runTest {
            seed()
            MockWebServer().use { server ->
                server.start()
                server.enqueue(MockResponse().setResponseCode(200))
                val attempt =
                    TestListenableWorkerBuilder<ExistingTargetConflictWorker>(context)
                        .setInputData(workDataOf(TransferWorker.TRANSFER_ID to "transfer"))
                        .setWorkerFactory(
                            object : WorkerFactory() {
                                override fun createWorker(
                                    appContext: Context,
                                    workerClassName: String,
                                    workerParameters: WorkerParameters,
                                ): ListenableWorker =
                                    ExistingTargetConflictWorker(appContext, workerParameters, store, server)
                            },
                        ).build()

                assertEquals(ListenableWorker.Result.failure(), attempt.doWork())
                val persisted = requireNotNull(store.transfer("transfer"))
                assertEquals(TransferState.CONFLICT.name, persisted.state)
                assertEquals("CONFLICT", persisted.errorCode)
                assertEquals("An item with this name already exists.", persisted.error)
                assertEquals("HEAD", server.takeRequest().method)
            }
        }

    @Test fun `acknowledged replacement verification timeout retries without losing checkpoint`() =
        runTest {
            seed()
            store.updateTransfer(requireNotNull(store.transfer("transfer")).copy(overwrite = true, bytesTotal = 100))
            val attempt =
                worker(java.net.SocketTimeoutException()) { transfer ->
                    store.updateActiveTransfer(transfer.copy(bytesTransferred = 100, verificationPending = true))
                }
            assertEquals(ListenableWorker.Result.retry(), attempt.doWork())
            val pending = requireNotNull(store.transfer("transfer"))
            assertTrue(pending.verificationPending)
            assertEquals(100L, pending.bytesTransferred)
            assertEquals("RETRY", pending.state)
        }

    @Test fun `unconditional replacement timeout cannot blindly replay the mutation`() =
        runTest {
            seed()
            store.updateTransfer(requireNotNull(store.transfer("transfer")).copy(overwrite = true))
            assertEquals(ListenableWorker.Result.failure(), worker(java.net.SocketTimeoutException()).doWork())
            assertEquals("FAILED", store.transfer("transfer")?.state)
        }

    private fun worker(
        failure: Exception,
        beforeFailure: suspend (TransferEntity) -> Unit = {},
    ): FailingWorker =
        TestListenableWorkerBuilder<FailingWorker>(context)
            .setInputData(workDataOf(TransferWorker.TRANSFER_ID to "transfer"))
            .setWorkerFactory(
                object : WorkerFactory() {
                    override fun createWorker(
                        appContext: Context,
                        workerClassName: String,
                        workerParameters: WorkerParameters,
                    ): ListenableWorker = FailingWorker(appContext, workerParameters, store, failure, beforeFailure)
                },
            ).build()

    @Test fun `source deleting intent cannot execute before verification support`() =
        runTest {
            seed()
            store.updateTransfer(requireNotNull(store.transfer("transfer")).copy(deleteSourceAfterSuccess = true))
            assertEquals(ListenableWorker.Result.failure(), worker(IllegalStateException("must not execute")).doWork())
            assertEquals("UNSUPPORTED", store.transfer("transfer")?.errorCode)
            assertEquals("Turn off source deletion before retrying this upload.", store.transfer("transfer")?.error)
        }

    @Test fun `discovery access loss prevents queued transfer execution`() =
        runTest {
            seed()
            store.replaceRemoteSpaces("account", emptyList())
            assertEquals(ListenableWorker.Result.failure(), worker(IllegalStateException("must not execute")).doWork())
            assertEquals("ACCESS_DENIED", store.transfer("transfer")?.errorCode)
        }

    private suspend fun seed() {
        database.accountDao().upsert(AccountEntity("account", "https://example.test", "user", "User", "BASIC", false))
        store.replaceRemoteSpaces(
            "account",
            listOf(
                SpaceEntity(
                    "account",
                    "space",
                    "Space",
                    "personal",
                    null,
                    null,
                    "root",
                    "https://example.test/dav/space",
                    null,
                    null,
                ),
            ),
        )
        store.createTransfer(
            TransferEntity(
                id = "transfer",
                accountId = "account",
                spaceId = "space",
                resourceId = null,
                direction = "UPLOAD",
                sourceUri = null,
                destinationPath = "/file",
                displayName = "file",
                mimeType = null,
                bytesTotal = 0,
                createdAtEpochMillis = 0,
                updatedAtEpochMillis = 0,
            ),
        )
    }

    class FailingWorker(
        context: Context,
        params: WorkerParameters,
        store: FileBrowserStore,
        private val failure: Exception,
        private val beforeFailure: suspend (TransferEntity) -> Unit,
    ) : TransferWorker(context, params, store, network = NetworkStatus { true }) {
        override fun authorization(account: AccountEntity) = "Bearer test"

        override suspend fun execute(
            transfer: TransferEntity,
            account: AccountEntity,
            space: SpaceEntity,
            client: TransferClient,
            authorization: String,
        ) {
            beforeFailure(transfer)
            throw failure
        }
    }

    class ExistingTargetConflictWorker(
        context: Context,
        params: WorkerParameters,
        store: FileBrowserStore,
        private val server: MockWebServer,
    ) : TransferWorker(context, params, store, network = NetworkStatus { true }) {
        override fun authorization(account: AccountEntity) = "Bearer test"

        override fun client(account: AccountEntity) = TransferClient(OkHttpClient())

        override suspend fun execute(
            transfer: TransferEntity,
            account: AccountEntity,
            space: SpaceEntity,
            client: TransferClient,
            authorization: String,
        ) {
            uploadAndVerify(
                transfer,
                upload = {
                    client.upload(
                        server.url("existing/photo.jpg").toString(),
                        authorization,
                        transfer.mimeType,
                        transfer.bytesTotal,
                        overwrite = false,
                        source = { "photo".byteInputStream() },
                        onProgress = {},
                    )
                },
                verify = { error("A pre-existing first-attempt target must not be reconciled automatically") },
            )
        }
    }
}
