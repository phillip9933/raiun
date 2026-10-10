package eu.opencloud.android.next.core.sync

import android.content.Context
import androidx.room.Room
import androidx.work.Configuration
import androidx.work.ListenableWorker
import androidx.work.WorkManager
import androidx.work.WorkerFactory
import androidx.work.WorkerParameters
import androidx.work.testing.SynchronousExecutor
import androidx.work.testing.TestListenableWorkerBuilder
import androidx.work.testing.WorkManagerTestInitHelper
import androidx.work.workDataOf
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.IncomingShareStore
import eu.opencloud.android.next.core.database.SharedDownloadStore
import eu.opencloud.android.next.core.database.SharedFolderCacheStore
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.model.AppClock
import eu.opencloud.android.next.core.network.IncomingSharedItem
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.RemoteResource
import eu.opencloud.android.next.core.network.SharedFolderAccess
import eu.opencloud.android.next.core.network.SharedFolderResolution
import eu.opencloud.android.next.core.network.SharedRemoteItem
import eu.opencloud.android.next.core.network.TransferClient
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.JsonObject
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File

@RunWith(RobolectricTestRunner::class)
@Suppress("LargeClass")
class SharedDownloadExecutorTest {
    @get:Rule val temporary = TemporaryFolder()
    private val database =
        Room
            .inMemoryDatabaseBuilder(
                RuntimeEnvironment.getApplication(),
                FileBrowserDatabase::class.java,
            ).build()
    private val inventory = IncomingShareStore(database)
    private val server = MockWebServer()
    private val access =
        IncomingShareAccessRepository(inventory) { _, _ ->
            SharedFolderResolution.Resolved(
                "drive",
                "root",
                "https://example.test/dav/root/",
                SharedFolderAccess(setOf("libre.graph/driveItem/children/read")),
            )
        }
    private val item = RemoteResource("file", "/file.txt", "file.txt", false, "text/plain", 5, "\"v1\"", 0, 0)
    private val browser =
        SharedFolderBrowser(access, SharedFolderPageCache(SharedFolderCacheStore(database))) { _, _, _ ->
            listOf(item)
        }
    private val resolver = SharedDownloadResolver(browser)
    private val queue = SharedDownloadQueue(SharedDownloadStore(database), resolver)
    private lateinit var source: PreparedSharedDownload
    private lateinit var client: TransferClient
    private var checksumResponseCode = 405
    private var checksumXml = ""

    @Before fun seed() =
        runBlocking {
            server.start()
            checksumResponseCode = 405
            checksumXml = ""
            client =
                TransferClient(
                    OkHttpClient
                        .Builder()
                        .addInterceptor { chain ->
                            val request = chain.request()
                            if (request.method == "PROPFIND") {
                                Response
                                    .Builder()
                                    .request(request)
                                    .protocol(Protocol.HTTP_1_1)
                                    .code(checksumResponseCode)
                                    .message("Checksum probe")
                                    .body(checksumXml.toResponseBody())
                                    .build()
                            } else {
                                chain.proceed(request.newBuilder().url(server.url(request.url.encodedPath)).build())
                            }
                        }.build(),
                )
            database.accountDao().upsert(AccountEntity("a", "https://example.test", "u", "User", "BASIC", false))
            IncomingShareRepository(inventory) {
                listOf(IncomingSharedItem("share", SharedRemoteItem("root", "Folder", folder = JsonObject(emptyMap()))))
            }.refresh("a")
            source = resolver.prepare(resolver.capture(browser.open("a", "share"), "file"))
            queue.enqueue(source, "transfer", true, 1)
            checkNotNull(database.transferDao().claim("transfer", "worker", 2))
            Unit
        }

    @After fun close() {
        server.shutdown()
        database.close()
    }

    @Test fun completeBytes() =
        runBlocking {
            server.enqueue(response())
            val progress = mutableListOf<Long>()
            executor().execute("transfer", "worker", client, "Bearer test", progress::add)
            val copy = checkNotNull(database.sharedLocalFileDao().find("a", source.location.scopeId, "file"))
            assertEquals("hello", File(copy.localPath).readText())
            assertEquals(42L, copy.downloadedAtEpochMillis)
            assertTrue(copy.offlinePinned)
            assertTrue(SharedFileIntegrity.matches(directory(), copy))
            assertEquals("SUCCEEDED", database.transferDao().findById("transfer")?.state)
            assertEquals(5L, database.transferDao().findById("transfer")?.bytesTransferred)
            assertEquals(5L, progress.last())
            val request = server.takeRequest()
            assertEquals("/dav/root/file.txt", request.path)
            assertEquals("\"v1\"", request.getHeader("If-Match"))
            assertEquals("Bearer test", request.getHeader("Authorization"))
            assertEquals(1, directory().listFiles()?.size)
            SharedDownloadFiles.clearAccount(temporary.root, "a")
            assertFalse(File(copy.localPath).exists())
        }

    @Test fun serverChecksumMatchesAndMismatchesBeforePublication() =
        runBlocking {
            checksumResponseCode = 207
            checksumXml = checksumProperties("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
            server.enqueue(response())
            executor().execute("transfer", "worker", client, "Bearer test")
            assertEquals(
                "hello",
                File(
                    checkNotNull(database.sharedLocalFileDao().find("a", source.location.scopeId, "file")).localPath,
                ).readText(),
            )

            val previous = checkNotNull(database.sharedLocalFileDao().find("a", source.location.scopeId, "file"))
            queue.enqueue(resolver.prepare(source.request), "replacement", true, 50)
            checkNotNull(database.transferDao().claim("replacement", "replacement-worker", 51))
            checksumXml = checksumProperties("0000000000000000000000000000000000000000000000000000000000000000")
            server.enqueue(response())
            val mismatch =
                assertThrows(OpenCloudException::class.java) {
                    runBlocking { executor().execute("replacement", "replacement-worker", client, "Bearer test") }
                }
            assertEquals(OpenCloudError.DownloadIntegrity, mismatch.error)
            assertEquals(previous, database.sharedLocalFileDao().find("a", source.location.scopeId, "file"))
            assertEquals("hello", File(previous.localPath).readText())
        }

    @Test fun changedChecksumMetadataFailsClosed() =
        runBlocking {
            checksumResponseCode = 207
            checksumXml =
                checksumProperties("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", "\"v2\"")
            server.enqueue(response())
            val changed =
                assertThrows(OpenCloudException::class.java) {
                    runBlocking { executor().execute("transfer", "worker", client, "Bearer test") }
                }
            assertEquals(OpenCloudError.PreconditionFailed, changed.error)
            assertUnpublished()
        }

    @Test fun rejectedResponse() =
        runBlocking {
            server.enqueue(response().setResponseCode(403))
            assertThrows(OpenCloudException::class.java) {
                runBlocking { executor().execute("transfer", "worker", client, "Bearer test") }
            }
            assertUnpublished()
        }

    @Test fun changedVersion() =
        runBlocking {
            server.enqueue(response().setHeader("ETag", "\"v2\""))
            assertThrows(OpenCloudException::class.java) {
                runBlocking { executor().execute("transfer", "worker", client, "Bearer test") }
            }
            assertUnpublished()
        }

    @Test fun incompleteBytes() =
        runBlocking {
            server.enqueue(response().setChunkedBody("hell", 2))
            assertThrows(OpenCloudException::class.java) {
                runBlocking { executor().execute("transfer", "worker", client, "Bearer test") }
            }
            assertUnpublished()
        }

    @Test fun revokedPublication() =
        runBlocking {
            server.enqueue(response())
            assertThrows(OpenCloudException::class.java) {
                runBlocking {
                    executor().execute("transfer", "worker", client, "Bearer test") {
                        runBlocking { inventory.beginRefresh("a") }
                    }
                }
            }
            assertUnpublished()
        }

    @Test fun cancellationRemainsCancellation() =
        runBlocking {
            server.enqueue(response())
            assertThrows(CancellationException::class.java) {
                runBlocking {
                    executor().execute("transfer", "worker", client, "Bearer test") { throw CancellationException() }
                }
            }
            assertUnpublished()
        }

    @Test fun noSpaceOrWrongOwner() =
        runBlocking {
            assertThrows(OpenCloudException::class.java) {
                runBlocking { executor(0).execute("transfer", "worker", client, "Bearer test") }
            }
            assertThrows(OpenCloudException::class.java) {
                runBlocking { executor().execute("transfer", "other", client, "Bearer test") }
            }
            assertEquals(0, server.requestCount)
            assertUnpublished()
        }

    @Test fun orphanCleanup() =
        runBlocking {
            server.enqueue(response())
            executor().execute("transfer", "worker", client, "Bearer test")
            val copy = checkNotNull(database.sharedLocalFileDao().find("a", source.location.scopeId, "file"))
            File(directory(), "interrupted.part").writeText("partial")
            val staleScope = SharedDownloadFiles.directory(temporary.root, "a", "removed-scope").also { it.mkdirs() }
            File(staleScope, "unpublished.blob").writeText("orphan")
            val other = SharedDownloadFiles.directory(temporary.root, "other", "scope").also { it.mkdirs() }
            val otherFile = File(other, "other.blob").also { it.writeText("other account") }
            val maintenance = SharedDownloadMaintenance(database, temporary.root)
            assertEquals(2, maintenance.cleanupAccount("a"))
            assertTrue(File(copy.localPath).exists())
            assertTrue(otherFile.exists())
            assertFalse(staleScope.exists())
            FileBrowserStore(database).removeAccount("a")
            assertEquals(1, maintenance.cleanupAccount("a"))
            assertFalse(File(copy.localPath).exists())
            assertTrue(otherFile.exists())
        }

    @Test fun cleanupWaitsForWriter() =
        runBlocking {
            val entered = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            val writer =
                async {
                    SharedDownloadFiles.guard(temporary.root, "a") {
                        directory().mkdirs()
                        val staging = File(directory(), "active.part").also { it.writeText("writing") }
                        entered.complete(Unit)
                        release.await()
                        assertTrue(staging.exists())
                    }
                }
            withTimeout(5_000) { entered.await() }
            val cleanup =
                async(start = CoroutineStart.UNDISPATCHED) {
                    SharedDownloadMaintenance(database, temporary.root).cleanupAccount("a")
                }
            assertFalse(cleanup.isCompleted)
            release.complete(Unit)
            withTimeout(5_000) {
                writer.await()
                assertEquals(1, cleanup.await())
            }
        }

    @Test fun removalDuringDownload() =
        runBlocking {
            server.enqueue(response())
            assertThrows(OpenCloudException::class.java) {
                runBlocking {
                    executor().execute("transfer", "worker", client, "Bearer test") {
                        runBlocking { FileBrowserStore(database).removeAccount("a") }
                    }
                }
            }
            SharedDownloadFiles.clearAccount(temporary.root, "a")
            assertFalse(directory().exists())
            assertEquals(null, database.transferDao().findById("transfer"))
            assertEquals(null, database.sharedLocalFileDao().find("a", source.location.scopeId, "file"))
        }

    @Test fun startupCleanupIncludesMissingAccounts() =
        runBlocking {
            server.enqueue(response())
            executor().execute("transfer", "worker", client, "Bearer test")
            val copy = checkNotNull(database.sharedLocalFileDao().find("a", source.location.scopeId, "file"))
            val account = checkNotNull(database.accountDao().findById("a"))
            database.accountDao().upsert(account.copy(isActive = false))
            val orphan = SharedDownloadFiles.directory(temporary.root, "deleted-account", "scope").also { it.mkdirs() }
            File(orphan, "abandoned.part").writeText("abandoned")
            val unknown = File(orphan, "unexpected.txt").also { it.writeText("preserve") }
            assertEquals(1, SharedDownloadMaintenance(database, temporary.root).cleanupAll())
            assertTrue(File(copy.localPath).exists())
            assertTrue(unknown.exists())
            assertEquals(0, SharedDownloadMaintenance(database, temporary.root).cleanupAll())
        }

    @Test fun workerPublishesWithoutOrdinarySpace() =
        runBlocking {
            server.enqueue(response())
            val worker = sharedWorker()
            assertEquals(ListenableWorker.Result.success(), worker.doWork())
            val completed = checkNotNull(database.transferDao().findById("transfer"))
            assertEquals("SUCCEEDED", completed.state)
            assertEquals(worker.id.toString(), completed.workId)
            assertEquals(1, completed.attemptCount)
            assertEquals(5L, completed.bytesTransferred)
            assertEquals(1, server.requestCount)
        }

    @Test fun workerRetainsRetryAfter() =
        runBlocking {
            server.enqueue(response().setResponseCode(429).setHeader("Retry-After", "3600"))
            val worker = sharedWorker()
            assertEquals(ListenableWorker.Result.retry(), worker.doWork())
            val pending = checkNotNull(database.transferDao().findById("transfer"))
            assertEquals("RETRY", pending.state)
            assertEquals("RATE_LIMITED", pending.errorCode)
            assertTrue(pending.notBeforeEpochMillis > System.currentTimeMillis())
            assertEquals(ListenableWorker.Result.retry(), worker.doWork())
            assertEquals(1, server.requestCount)
            assertEquals(1, database.transferDao().findById("transfer")?.attemptCount)
        }

    @Test fun workerCancellationDoesNotFailTransfer() =
        runBlocking {
            server.enqueue(response())
            val worker = sharedWorker { throw CancellationException() }
            assertThrows(CancellationException::class.java) { runBlocking { worker.doWork() } }
            assertUnpublished()
            assertEquals(null, database.transferDao().findById("transfer")?.errorCode)
        }

    @Test fun schedulingAndRetryKeepOneIntent() =
        runBlocking {
            val context = RuntimeEnvironment.getApplication()
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
                            ): ListenableWorker =
                                object : androidx.work.Worker(appContext, workerParameters) {
                                    override fun doWork(): Result = Result.retry()
                                }
                        },
                    ).build(),
            )
            val workManager = WorkManager.getInstance(context)
            try {
                val current = checkNotNull(database.transferDao().findById("transfer"))
                database.transferDao().update(current.copy(state = "QUEUED", workId = null))
                val manager = TransferManager(context, FileBrowserStore(database), workManager, sharedQueue = queue)
                val accepted = manager.enqueueSharedDownload(source.request, true)
                manager.reconcile()
                assertEquals("transfer", accepted.id)
                assertEquals(accepted.workId, database.transferDao().findById("transfer")?.workId)
                val failed = accepted.copy(state = "FAILED")
                database.transferDao().update(failed)
                manager.retry(failed)
                val retried = checkNotNull(database.transferDao().findById("transfer"))
                assertTrue(retried.workId != accepted.workId)
                manager.retry(failed)
                manager.reconcile()
                assertEquals(retried.workId, database.transferDao().findById("transfer")?.workId)
                val work =
                    workManager
                        .getWorkInfosForUniqueWork(
                            "transfer-transfer",
                        ).get()
                        .filterNot { it.state.isFinished }
                assertEquals(listOf(retried.workId), work.map { it.id.toString() })
            } finally {
                workManager.cancelAllWork().result.get()
                WorkManagerTestInitHelper.closeWorkDatabase()
            }
        }

    private suspend fun sharedWorker(onProgress: () -> Unit = {}): TransferWorker {
        val current = checkNotNull(database.transferDao().findById("transfer"))
        database.transferDao().update(current.copy(state = "QUEUED", workId = null))
        return TestListenableWorkerBuilder<TransferWorker>(RuntimeEnvironment.getApplication())
            .setInputData(workDataOf(TransferWorker.TRANSFER_ID to "transfer"))
            .setWorkerFactory(
                object : WorkerFactory() {
                    override fun createWorker(
                        appContext: Context,
                        workerClassName: String,
                        workerParameters: WorkerParameters,
                    ): ListenableWorker =
                        object : TransferWorker(
                            appContext,
                            workerParameters,
                            FileBrowserStore(database),
                            network = NetworkStatus { true },
                        ) {
                            override val supportsSharedDownloads = true

                            override fun authorization(account: AccountEntity) = "Bearer test"

                            override fun client(account: AccountEntity) = this@SharedDownloadExecutorTest.client

                            override suspend fun execute(
                                transfer: TransferEntity,
                                account: AccountEntity,
                                space: SpaceEntity,
                                client: TransferClient,
                                authorization: String,
                            ): Unit = error("Shared download must not execute against an ordinary space")

                            override suspend fun executeShared(
                                transfer: TransferEntity,
                                client: TransferClient,
                                authorization: String,
                            ) {
                                executor().execute(transfer.id, id.toString(), client, authorization) { bytes ->
                                    onProgress()
                                    updateForegroundProgress(transfer, bytes)
                                }
                            }
                        }
                },
            ).build()
    }

    @Test fun temporaryRetentionPreservesPinsAndBoundary() =
        runBlocking {
            server.enqueue(response())
            executor().execute("transfer", "worker", client, "Bearer test")
            val dao = database.sharedLocalFileDao()
            val copy = checkNotNull(dao.find("a", source.location.scopeId, "file"))
            val maintenance = SharedDownloadMaintenance(database, temporary.root)
            assertEquals(0, maintenance.clearTemporary())
            assertTrue(File(copy.localPath).exists())
            dao.save(copy.copy(offlinePinned = false))
            assertEquals(0, maintenance.expireTemporary(0, Long.MAX_VALUE))
            assertEquals(0, maintenance.expireTemporary(1, 3_600_042L))
            assertTrue(File(copy.localPath).exists())
            assertEquals(1, maintenance.expireTemporary(1, 3_600_043L))
            assertFalse(File(copy.localPath).exists())
            assertEquals(null, dao.find("a", source.location.scopeId, "file"))
            assertEquals("SUCCEEDED", database.transferDao().findById("transfer")?.state)
        }

    @Test fun temporaryClearProtectsPendingDownload() =
        runBlocking {
            server.enqueue(response())
            executor().execute("transfer", "worker", client, "Bearer test")
            val dao = database.sharedLocalFileDao()
            val copy = checkNotNull(dao.find("a", source.location.scopeId, "file"))
            dao.save(copy.copy(offlinePinned = false))
            val prepared = resolver.prepare(source.request)
            queue.enqueue(prepared, "pin-request", true, 50)
            val maintenance = SharedDownloadMaintenance(database, temporary.root)
            assertEquals(0, maintenance.clearTemporary())
            assertTrue(File(copy.localPath).exists())
            database.transferDao().cancel("pin-request")
            assertEquals(1, maintenance.clearTemporary())
            assertFalse(File(copy.localPath).exists())
            assertEquals(0, maintenance.clearTemporary())
        }

    @Test fun boundedReaderAndClose() =
        runBlocking<Unit> {
            publishForRead()
            var authorizations = 0
            val reader = SharedLocalReader(database, resolver, temporary.root, { authorizations++ }, { true })
            val session = reader.open(source.request)
            assertEquals(1, authorizations)
            assertEquals(5L, session.size)
            assertEquals("ell", session.read(1, 3).decodeToString())
            assertEquals("o", session.read(4, 10).decodeToString())
            assertTrue(session.read(5, 10).isEmpty())
            assertThrows(IllegalArgumentException::class.java) { runBlocking { session.read(0, 65_537) } }
            session.close()
            assertThrows(IllegalStateException::class.java) { runBlocking { session.read(0, 1) } }
        }

    @Test fun readerRejectsRevocationAndLocalLock() =
        runBlocking {
            publishForRead()
            var allowed = true
            val reader = SharedLocalReader(database, resolver, temporary.root, {}, { allowed })
            val session = reader.open(source.request)
            allowed = false
            assertThrows(OpenCloudException::class.java) { runBlocking { session.read(0, 5) } }
            allowed = true
            assertThrows(IllegalStateException::class.java) { runBlocking { session.read(0, 5) } }
            val refreshed = reader.open(source.request)
            inventory.beginRefresh("a")
            assertThrows(OpenCloudException::class.java) { runBlocking { refreshed.read(0, 5) } }
            refreshed.close()
            session.close()
        }

    @Test fun readerRejectsCorruptBytesAndDeniedContent() =
        runBlocking<Unit> {
            publishForRead()
            val denied =
                SharedLocalReader(database, resolver, temporary.root, { throw CancellationException() }, { true })
            assertThrows(CancellationException::class.java) { runBlocking { denied.open(source.request) } }
            val copy = checkNotNull(database.sharedLocalFileDao().find("a", source.location.scopeId, "file"))
            File(copy.localPath).writeText("jello")
            val reader = SharedLocalReader(database, resolver, temporary.root, {}, { true })
            assertThrows(OpenCloudException::class.java) { runBlocking { reader.open(source.request) } }
        }

    @Test fun readerCannotOutliveRemovedAccount() =
        runBlocking {
            publishForRead()
            val reader = SharedLocalReader(database, resolver, temporary.root, {}, { true })
            val session = reader.open(source.request)
            FileBrowserStore(database).removeAccount("a")
            SharedDownloadFiles.clearAccount(temporary.root, "a")
            assertThrows(OpenCloudException::class.java) { runBlocking { session.read(0, 5) } }
            session.close()
        }

    @Test
    fun activeReadersProtectTemporaryCopyUntilLastClose() =
        runBlocking {
            publishForRead()
            val dao = database.sharedLocalFileDao()
            val copy = checkNotNull(dao.find("a", source.location.scopeId, "file"))
            dao.save(copy.copy(offlinePinned = false))
            val reader = SharedLocalReader(database, resolver, temporary.root, {}, { true })
            val first = reader.open(source.request)
            val second = reader.open(source.request)
            val maintenance = SharedDownloadMaintenance(database, temporary.root)
            assertEquals(0, maintenance.expireTemporary(1, 9_000_000))
            first.close()
            first.close()
            assertEquals(0, maintenance.clearTemporary())
            assertEquals("hello", second.read(0, 5).decodeToString())
            second.close()
            assertEquals(1, maintenance.clearTemporary())
            assertFalse(File(copy.localPath).exists())
        }

    @Test
    fun failedReaderReleasesTemporaryProtection() =
        runBlocking {
            publishForRead()
            val dao = database.sharedLocalFileDao()
            val copy = checkNotNull(dao.find("a", source.location.scopeId, "file"))
            dao.save(copy.copy(offlinePinned = false))
            var allowed = true
            val session = SharedLocalReader(database, resolver, temporary.root, {}, { allowed }).open(source.request)
            allowed = false
            assertThrows(OpenCloudException::class.java) { runBlocking { session.read(0, 5) } }
            assertEquals(1, SharedDownloadMaintenance(database, temporary.root).clearTemporary())
            assertFalse(File(copy.localPath).exists())
        }

    @Test
    fun cachedReaderRequiresExactContentGet() =
        runBlocking {
            publishForRead()
            server.takeRequest()
            server.enqueue(response())
            val reader =
                SharedLocalReader(database, resolver, temporary.root, {
                    authorizeSharedContent(it, client, "Bearer test")
                }, { true })
            reader.open(source.request).use { session ->
                assertEquals("hello", session.read(0, 5).decodeToString())
            }
            val request = server.takeRequest()
            assertEquals("GET", request.method)
            assertEquals("/dav/root/file.txt", request.path)
            assertEquals("Bearer test", request.getHeader("Authorization"))
            assertEquals("\"v1\"", request.getHeader("If-Match"))
        }

    @Test
    fun contentAuthorizationRejectsDenialRedirectAndChangedVersion() =
        runBlocking {
            val responses =
                listOf(
                    MockResponse().setResponseCode(403),
                    MockResponse().setResponseCode(302).setHeader("Location", "https://other.test/file"),
                    response().setHeader("ETag", "\"v2\""),
                    response().removeHeader("ETag"),
                )
            for (response in responses) {
                server.enqueue(response)
                assertThrows(OpenCloudException::class.java) {
                    runBlocking { authorizeSharedContent(source, client, "Bearer test") }
                }
            }
            assertEquals(responses.size, server.requestCount)
        }

    @Test
    fun cachedContentAuthorizationRejectsWeakOrMissingVersion() =
        runBlocking {
            for (eTag in listOf(null, "W/\"v1\"")) {
                val request = source.request.copy(file = source.request.file.copy(eTag = eTag))
                val unversioned = PreparedSharedDownload(request, source.page, source.item)
                assertThrows(OpenCloudException::class.java) {
                    runBlocking { authorizeSharedContent(unversioned, client, "Bearer test") }
                }
            }
            assertEquals(0, server.requestCount)
        }

    @Test
    fun cachedReadsContinueDuringDownloadAndStopAfterReplacement() =
        runBlocking {
            publishForRead()
            val reader = SharedLocalReader(database, resolver, temporary.root, {}, { true })
            val session = reader.open(source.request)
            queue.enqueue(resolver.prepare(source.request), "replacement", true, 50)
            checkNotNull(database.transferDao().claim("replacement", "replacement-worker", 51))
            server.enqueue(response())
            val entered = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            val writer =
                async {
                    executor().execute("replacement", "replacement-worker", client, "Bearer test") {
                        entered.complete(Unit)
                        runBlocking { release.await() }
                    }
                }
            try {
                withTimeout(5_000) { entered.await() }
                withTimeout(5_000) {
                    assertEquals("hello", session.read(0, 5).decodeToString())
                    reader.open(source.request).use { assertEquals("ell", it.read(1, 3).decodeToString()) }
                }
                val cleanup =
                    async(start = CoroutineStart.UNDISPATCHED) {
                        SharedDownloadMaintenance(database, temporary.root).cleanupAccount("a")
                    }
                assertFalse(cleanup.isCompleted)
                release.complete(Unit)
                withTimeout(5_000) {
                    writer.await()
                    cleanup.await()
                }
                assertThrows(OpenCloudException::class.java) { runBlocking { session.read(0, 5) } }
                reader.open(source.request).use { assertEquals("hello", it.read(0, 5).decodeToString()) }
            } finally {
                release.complete(Unit)
                session.close()
            }
        }

    @Test
    fun pinChangesReuseVerifiedBytesWithoutNewTransfer() =
        runBlocking {
            publishForRead()
            val dao = database.sharedLocalFileDao()
            val original = checkNotNull(dao.find("a", source.location.scopeId, "file"))
            val reader =
                SharedLocalReader(database, resolver, temporary.root, {
                    authorizeSharedContent(it, client, "Bearer test")
                }, { true })
            server.enqueue(response())
            reader.setOfflinePinned(source.request, false)
            assertEquals(original.copy(offlinePinned = false), dao.find("a", source.location.scopeId, "file"))
            server.enqueue(response())
            reader.setOfflinePinned(source.request, true)
            assertEquals(original, dao.find("a", source.location.scopeId, "file"))
            assertEquals(1, directory().listFiles()?.size)
            assertEquals(0, SharedDownloadMaintenance(database, temporary.root).clearTemporary())
            assertEquals(3, server.requestCount)
        }

    @Test
    fun explicitLocalRemovalRejectsStaleActionAndClosesReader() =
        runBlocking {
            publishForRead()
            val dao = database.sharedLocalFileDao()
            val original = checkNotNull(dao.find("a", source.location.scopeId, "file"))
            val reader = SharedLocalReader(database, resolver, temporary.root, {}, { true })
            val session = reader.open(source.request)
            assertFalse(reader.removeLocalCopy(original.copy(sha256 = "stale")))
            assertTrue(File(original.localPath).exists())
            assertTrue(reader.removeLocalCopy(original))
            assertFalse(File(original.localPath).exists())
            assertEquals(null, dao.find("a", source.location.scopeId, "file"))
            assertFalse(reader.removeLocalCopy(original))
            assertThrows(OpenCloudException::class.java) { runBlocking { session.read(0, 5) } }
            session.close()
            assertEquals(1, server.requestCount)
        }

    @Test
    fun localControlsRejectLockedCorruptAndPendingCopies() =
        runBlocking {
            publishForRead()
            val copy = checkNotNull(database.sharedLocalFileDao().find("a", source.location.scopeId, "file"))
            var allowed = false
            val reader = SharedLocalReader(database, resolver, temporary.root, {}, { allowed })
            assertThrows(OpenCloudException::class.java) { runBlocking { reader.removeLocalCopy(copy) } }
            assertThrows(
                OpenCloudException::class.java,
            ) { runBlocking { reader.setOfflinePinned(source.request, false) } }
            allowed = true
            File(copy.localPath).writeText("jello")
            assertThrows(
                OpenCloudException::class.java,
            ) { runBlocking { reader.setOfflinePinned(source.request, false) } }
            File(copy.localPath).writeText("hello")
            queue.enqueue(resolver.prepare(source.request), "replacement", true, 50)
            assertFalse(reader.removeLocalCopy(copy))
            assertThrows(
                OpenCloudException::class.java,
            ) { runBlocking { reader.setOfflinePinned(source.request, false) } }
            assertTrue(File(copy.localPath).exists())
        }

    private suspend fun publishForRead() {
        server.enqueue(response())
        executor().execute("transfer", "worker", client, "Bearer test")
    }

    private fun response() = MockResponse().setBody("hello").setHeader("ETag", "\"v1\"")

    private fun checksumProperties(
        sha256: String,
        eTag: String = "\"v1\"",
    ) =
        """<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:response><d:href>/dav/root/file.txt</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>5</d:getcontentlength><d:getetag>$eTag</d:getetag><oc:checksums><oc:checksum>SHA256:$sha256</oc:checksum></oc:checksums></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"""

    private fun executor(space: Long = Long.MAX_VALUE) =
        SharedDownloadExecutor(
            database,
            queue,
            temporary.root,
            StorageSpaceProvider { space },
            AppClock { 42 },
        )

    private fun directory() = SharedDownloadFiles.directory(temporary.root, "a", source.location.scopeId)

    private suspend fun assertUnpublished() {
        assertEquals(null, database.sharedLocalFileDao().find("a", source.location.scopeId, "file"))
        assertEquals("RUNNING", database.transferDao().findById("transfer")?.state)
        assertTrue(directory().listFiles().isNullOrEmpty())
    }
}
