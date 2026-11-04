package eu.opencloud.android.next.core.sync

import androidx.room.Room
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.VaultDavEntry
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

@RunWith(RobolectricTestRunner::class)
class VaultOfflineStoreTest {
    private lateinit var root: File
    private lateinit var store: VaultOfflineStore
    private lateinit var account: AccountEntity
    private lateinit var location: VaultLocation
    private lateinit var identity: VaultIdentity
    private var currentAccount: AccountEntity? = null
    private val material = ByteArray(80) { it.toByte() }

    @Before fun setUp() {
        root = Files.createTempDirectory("vault-offline-test").toFile()
        val server = EndpointPolicy(true).endpoint("https://example.test/", allowQuery = false).toString()
        account = AccountEntity("account", server, "user", "User", "BASIC", false)
        currentAccount = account
        location =
            VaultLocation(
                accountId = account.id,
                title = "Secret.vault",
                kind = VaultLocationKind.FOLDER_VAULT,
                driveId = "drive",
                remoteVaultId = "vault-id",
                sourceRootId = "root-id",
                canonicalServer = server,
                rootWebDavUrl = "https://example.test/dav/files/",
                vaultPath = "Secret.vault",
                isVaultRoot = true,
            )
        identity = VaultIdentity(account.id, server, "drive", "vault-id")
        store =
            VaultOfflineStore(
                root,
                { currentAccount },
                { { true } },
                EndpointPolicy(true),
                { VaultOfflineTestCipher() },
                durability = jvmOfflineDurability(root),
            )
    }

    @After fun tearDown() {
        root.deleteRecursively()
        material.fill(0)
    }

    @Test fun pinnedCiphertextOpensReadOnlyAndKeepsChildNamesOutOfCatalog() =
        runBlocking {
            val plain = "private payload".toByteArray()
            val encrypted = fakeCiphertext(plain)
            val entry = fileEntry("enc_private", encrypted.size.toLong())
            store.pinFile(identity, location, entry, material) { it.write(encrypted) }
            assertTrue(store.hasSnapshot(identity))
            assertEquals(listOf("Secret.vault"), store.locations(account.id).map(VaultLocation::title))
            val catalog = root.walkTopDown().first { it.name == "root.json" }.readText()
            assertFalse(catalog.contains("enc_private"))
            assertFalse(catalog.contains("private payload"))

            val session = store.openWithKeyMaterial(account.id, location, material)!!
            try {
                assertEquals(identity, session.identity)
                val listed = session.list().single()
                assertEquals("enc_private", listed.name)
                val output = ByteArrayOutputStream()
                assertEquals(plain.size.toLong(), session.download(listed, output))
                assertArrayEquals(plain, output.toByteArray())
            } finally {
                session.close()
                plain.fill(0)
                encrypted.fill(0)
            }
        }

    @Test fun accountRemovalAtPublicationCannotRecreateManifestOrCatalog() {
        val publishing = CountDownLatch(1)
        val release = CountDownLatch(1)
        val controlled =
            VaultOfflineStore(
                root,
                { currentAccount },
                { { true } },
                EndpointPolicy(true),
                { VaultOfflineTestCipher() },
                durability = jvmOfflineDurability(root),
                beforePublication = {
                    publishing.countDown()
                    check(release.await(5, TimeUnit.SECONDS))
                },
            )
        val worker = Executors.newSingleThreadExecutor()
        try {
            val future =
                worker.submit<Unit> {
                    runBlocking {
                        val encrypted = fakeCiphertext("pending".toByteArray())
                        controlled.pinFile(
                            identity,
                            location,
                            fileEntry("enc_pending", encrypted.size.toLong()),
                            material,
                        ) {
                            it.write(encrypted)
                        }
                    }
                }
            assertTrue(publishing.await(5, TimeUnit.SECONDS))
            controlled.forgetAccount(account.id)
            currentAccount = null
            release.countDown()
            assertThrows(java.util.concurrent.ExecutionException::class.java) { future.get(5, TimeUnit.SECONDS) }
            assertFalse(root.walkTopDown().any { it.name == "manifest.enc" || it.name == "root.json" })
        } finally {
            release.countDown()
            worker.shutdownNow()
        }
    }

    @Test fun completedCiphertextCanBeAuthenticatedAfterAnOfflineUnlockWithoutNetwork() =
        runBlocking {
            store.pinDirectory(identity, location, location.vaultPath, material)
            val session = store.openWithKeyMaterial(account.id, location, material)!!
            val downloads = VaultDownloadStore(File(root, "pending-jobs"))
            val encrypted = fakeCiphertext("offline pending content".toByteArray())
            val source =
                eu.opencloud.android.next.core.network.VaultDavEntry(
                    "file-id",
                    "Secret.vault/cipher",
                    "cipher",
                    false,
                    encrypted.size.toLong(),
                    "\"tag\"",
                    "https://example.test/dav/files/Secret.vault/cipher",
                )
            val job = downloads.create(location, source, vaultProofDigest("proof"))
            assertTrue(downloads.finishPrepared(job.id) { true })
            downloads.partial(job).writeBytes(encrypted)
            try {
                assertTrue(session.list().isEmpty())
                session.publishBackgroundDownload(job, downloads, store, jobPermit = { true })
                val entry = session.list().single()
                val output = ByteArrayOutputStream()
                session.download(entry, output)
                assertArrayEquals("offline pending content".toByteArray(), output.toByteArray())
            } finally {
                session.close()
            }
        }

    @Test fun cancelledPendingCiphertextNeverPublishesAnOfflineFile() =
        runBlocking {
            store.pinDirectory(identity, location, location.vaultPath, material)
            val session = store.openWithKeyMaterial(account.id, location, material)!!
            val downloads = VaultDownloadStore(File(root, "pending-jobs"))
            val encrypted = fakeCiphertext("pending".toByteArray())
            val source =
                eu.opencloud.android.next.core.network.VaultDavEntry(
                    "file-id",
                    "Secret.vault/cipher",
                    "cipher",
                    false,
                    encrypted.size.toLong(),
                    "\"tag\"",
                    "https://example.test/dav/files/Secret.vault/cipher",
                )
            val job = downloads.create(location, source, null)
            assertTrue(downloads.finishPrepared(job.id) { true })
            downloads.partial(job).writeBytes(encrypted)
            try {
                assertThrows(OpenCloudException::class.java) {
                    runBlocking { session.publishBackgroundDownload(job, downloads, store, jobPermit = { false }) }
                }
                assertTrue(session.list().isEmpty())
            } finally {
                session.close()
            }
        }

    @Test fun existingSessionRefreshWaitsForRejectedPublicationAndCannotExposeCandidate() =
        runBlocking {
            assertExistingReaderWaitsForRejectedPublication { session, _ ->
                val output = ByteArrayOutputStream()
                session.download(session.list().single(), output)
                output.toString(Charsets.UTF_8.name())
            }
        }

    @Test fun existingSessionReadWaitsForRejectedPublicationAndKeepsOldRootUsable() =
        runBlocking {
            assertExistingReaderWaitsForRejectedPublication { session, issued ->
                val output = ByteArrayOutputStream()
                session.download(issued, output)
                output.toString(Charsets.UTF_8.name())
            }
        }

    private suspend fun assertExistingReaderWaitsForRejectedPublication(
        read: suspend (VaultOfflineSession, VaultFolder) -> String,
    ) {
        PendingPublicationFixture().use { fixture ->
            fixture.initialize()
            val existing = fixture.existingSession()
            val issued = existing.list().single()
            val published = CountDownLatch(1)
            val release = CountDownLatch(1)
            val readerStarted = CountDownLatch(1)
            val workers = Executors.newFixedThreadPool(2)
            try {
                fixture.afterPublication = {
                    published.countDown()
                    check(release.await(5, TimeUnit.SECONDS))
                }
                val publication = workers.submit<Unit> { runBlocking { fixture.complete { false } } }
                assertTrue(published.await(5, TimeUnit.SECONDS))
                val reader =
                    workers.submit<String> {
                        readerStarted.countDown()
                        runBlocking { read(existing, issued) }
                    }
                assertTrue(readerStarted.await(5, TimeUnit.SECONDS))
                assertThrows(TimeoutException::class.java) { reader.get(150, TimeUnit.MILLISECONDS) }
                release.countDown()
                publication.get(5, TimeUnit.SECONDS)
                assertEquals("previous", reader.get(5, TimeUnit.SECONDS))
                fixture.assertContent("previous")
            } finally {
                release.countDown()
                workers.shutdownNow()
            }
        }
    }

    @Test fun cancellationAfterPublicationRestoresPreviousVerifiedCopy() =
        runBlocking {
            PendingPublicationFixture().use { fixture ->
                fixture.initialize()
                fixture.afterPublication = {
                    runBlocking { fixture.transfers.cancelTransfer(fixture.job.id) }
                    fixture.downloads.discardPayload(fixture.job.id)
                }
                fixture.complete()
                assertEquals("CANCELLED", fixture.transfers.transfer(fixture.job.id)?.state)
                fixture.assertContent("previous")
                assertEquals(0, VaultDownloadStore.activeAttemptCount())
            }
        }

    @Test fun deniedCompletionCasRestoresPreviousVerifiedCopy() =
        runBlocking {
            PendingPublicationFixture().use { fixture ->
                fixture.initialize()
                fixture.complete { false }
                assertEquals("FAILED", fixture.transfers.transfer(fixture.job.id)?.state)
                fixture.assertContent("previous")
                assertEquals(0, VaultDownloadStore.activeAttemptCount())
            }
        }

    @Test fun accountRemovalAfterPublicationNeverRestoresMetadata() =
        runBlocking {
            PendingPublicationFixture().use { fixture ->
                fixture.initialize()
                fixture.afterPublication = {
                    fixture.offline.forgetAccount(account.id)
                    runBlocking { fixture.transfers.removeAccount(account.id) }
                    currentAccount = null
                }
                fixture.complete()
                assertEquals(null, fixture.transfers.transfer(fixture.job.id))
                assertFalse(root.walkTopDown().any { it.name == "manifest.enc" || it.name == "root.json" })
            }
        }

    @Test fun cancellationAfterAcceptedCompletionKeepsSucceededOfflineCopy() =
        runBlocking {
            PendingPublicationFixture().use { fixture ->
                fixture.initialize()
                fixture.complete { commit ->
                    commit().also { accepted ->
                        assertTrue(accepted)
                        fixture.transfers.cancelTransfer(fixture.job.id)
                        fixture.downloads.discardPayload(fixture.job.id)
                    }
                }
                assertEquals("SUCCEEDED", fixture.transfers.transfer(fixture.job.id)?.state)
                fixture.assertContent("replacement")
            }
        }

    @Test fun callerCancellationWhileCompletionReturnsCannotRollbackAcceptedCopy() =
        runBlocking {
            PendingPublicationFixture().use { fixture ->
                fixture.initialize()
                val completion =
                    launch(Dispatchers.IO) {
                        val caller = currentCoroutineContext()[Job]!!
                        fixture.complete { commit ->
                            commit().also { accepted ->
                                assertTrue(accepted)
                                caller.cancel()
                                // Cancellation must not hide the durable completion result at a suspension boundary.
                                yield()
                            }
                        }
                    }
                completion.join()
                assertTrue(completion.isCancelled)
                assertEquals("SUCCEEDED", fixture.transfers.transfer(fixture.job.id)?.state)
                fixture.assertContent("replacement")
            }
        }

    @Test fun cancellingFirstPublishedJobDoesNotStopFollowingOfflineImports() =
        runBlocking {
            PendingPublicationFixture().use { fixture ->
                fixture.initialize()
                val second = fixture.enqueue("cipher2")
                var cancelledId: String? = null
                fixture.afterPublication = {
                    if (cancelledId == null) {
                        cancelledId = fixture.publishingJob?.id
                        runBlocking { fixture.transfers.cancelTransfer(requireNotNull(cancelledId)) }
                        fixture.downloads.discardPayload(requireNotNull(cancelledId))
                    }
                }
                fixture.complete()
                val importedId = listOf(fixture.job.id, second.id).single { it != cancelledId }
                assertEquals("CANCELLED", fixture.transfers.transfer(requireNotNull(cancelledId))?.state)
                assertEquals("SUCCEEDED", fixture.transfers.transfer(importedId)?.state)
                assertEquals(0, VaultDownloadStore.activeAttemptCount())
            }
        }

    @Test fun restartRollsBackUnacceptedPublicationBeforeOfflineOpen() =
        runBlocking {
            PendingPublicationFixture().use { fixture ->
                fixture.initialize()
                val crashed = Files.createTempDirectory("offline-unaccepted-crash").toFile()
                try {
                    fixture.afterPublication = { root.copyRecursively(crashed, overwrite = true) }
                    fixture.complete { false }
                    fixture.assertContent("previous", fixture.restarted(crashed), crashed)
                    assertFalse(crashed.walkTopDown().any { it.name == "publication.pending" })
                } finally {
                    crashed.deleteRecursively()
                }
            }
        }

    @Test fun restartKeepsAcceptedPublicationBeforeItsTransferHistoryIsRemoved() =
        runBlocking {
            PendingPublicationFixture().use { fixture ->
                fixture.initialize()
                val crashed = Files.createTempDirectory("offline-accepted-crash").toFile()
                try {
                    fixture.afterPublication = { root.copyRecursively(crashed, overwrite = true) }
                    fixture.complete()
                    val restarted = fixture.restarted(crashed)
                    restarted.mutateTransferHistory(account.id) { fixture.transfers.clearTransferHistory(account.id) }
                    fixture.assertContent("replacement", restarted, crashed)
                    assertFalse(crashed.walkTopDown().any { it.name == "publication.pending" })
                } finally {
                    crashed.deleteRecursively()
                }
            }
        }

    @Test fun historyRemovalWaitsForPublicationAndItsAcceptedJournalCleanup() =
        runBlocking {
            PendingPublicationFixture().use { fixture ->
                fixture.initialize()
                val published = CountDownLatch(1)
                val release = CountDownLatch(1)
                val deleting = CountDownLatch(1)
                val workers = Executors.newFixedThreadPool(2)
                try {
                    fixture.afterPublication = {
                        published.countDown()
                        check(release.await(5, TimeUnit.SECONDS))
                    }
                    val publication = workers.submit<Unit> { runBlocking { fixture.complete() } }
                    assertTrue(published.await(5, TimeUnit.SECONDS))
                    val history =
                        workers.submit<Unit> {
                            runBlocking {
                                fixture.offline.mutateTransferHistory(account.id) {
                                    deleting.countDown()
                                    assertFalse(root.walkTopDown().any { it.name == "publication.pending" })
                                    fixture.transfers.clearTransferHistory(account.id)
                                }
                            }
                        }
                    assertFalse(deleting.await(100, TimeUnit.MILLISECONDS))
                    release.countDown()
                    publication.get(5, TimeUnit.SECONDS)
                    history.get(5, TimeUnit.SECONDS)
                    assertEquals(null, fixture.transfers.transfer(fixture.job.id))
                    fixture.assertContent("replacement")
                } finally {
                    release.countDown()
                    workers.shutdownNow()
                }
            }
        }

    @Test fun accountCleanupRemovesInterruptedPublicationJournalWithoutRecovery() =
        runBlocking {
            PendingPublicationFixture().use { fixture ->
                fixture.initialize()
                val crashed = Files.createTempDirectory("offline-removed-crash").toFile()
                try {
                    fixture.afterPublication = { root.copyRecursively(crashed, overwrite = true) }
                    fixture.complete { false }
                    val restarted = fixture.restarted(crashed)
                    restarted.forgetAccount(account.id)
                    fixture.transfers.removeAccount(account.id)
                    currentAccount = null
                    assertThrows(OpenCloudException::class.java) {
                        runBlocking { restarted.openWithKeyMaterial(account.id, location, material) }
                    }
                    assertFalse(
                        crashed.walkTopDown().any {
                            it.name == "publication.pending" || it.name == "manifest.enc" || it.name == "root.json"
                        },
                    )
                } finally {
                    crashed.deleteRecursively()
                }
            }
        }

    private inner class PendingPublicationFixture : AutoCloseable {
        private val context = RuntimeEnvironment.getApplication()
        private val database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
        val transfers = FileBrowserStore(database)
        val downloads = VaultDownloadStore(File(root, "pending-jobs"))
        var afterPublication: () -> Unit = {}
        val offline =
            VaultOfflineStore(
                root,
                { currentAccount },
                { { true } },
                EndpointPolicy(true),
                { VaultOfflineTestCipher() },
                durability = jvmOfflineDurability(root),
                afterPublication = { afterPublication() },
                publicationAccepted = { transferId, _ -> transfers.transfer(transferId)?.state == "SUCCEEDED" },
            )
        lateinit var job: VaultDownloadJob
        var publishingJob: VaultDownloadJob? = null
        private lateinit var session: VaultOfflineSession

        fun existingSession(): VaultOfflineSession = session

        suspend fun initialize() {
            database.accountDao().upsert(account)
            val old = fakeCiphertext("previous".toByteArray())
            offline.pinFile(identity, location, fileEntry("cipher", old.size.toLong()), material) { it.write(old) }
            session = offline.openWithKeyMaterial(account.id, location, material)!!
            job = enqueue("cipher")
        }

        suspend fun enqueue(name: String): VaultDownloadJob {
            val replacement = fakeCiphertext("replacement".toByteArray())
            val source =
                VaultDavEntry(
                    name,
                    "Secret.vault/$name",
                    name,
                    false,
                    replacement.size.toLong(),
                    "\"tag\"",
                    "https://example.test/dav/files/Secret.vault/$name",
                )
            val captured = downloads.create(location, source, null)
            downloads.partial(captured).writeBytes(replacement)
            assertTrue(downloads.finishPrepared(captured.id) { true })
            transfers.enqueueCiphertextDownload(
                TransferEntity(
                    id = captured.id,
                    accountId = account.id,
                    spaceId = location.driveId,
                    resourceId = source.id,
                    direction = "DOWNLOAD",
                    sourceUri = "vault-offline:${identity.remoteVaultId}",
                    destinationPath = source.relativePath,
                    displayName = "Encrypted offline download",
                    mimeType = "application/octet-stream",
                    bytesTotal = source.size,
                    offlinePin = true,
                    expectedETag = source.strongETag,
                    locationKind = "VAULT",
                    state = "AWAITING_UNLOCK",
                    verificationPending = true,
                    createdAtEpochMillis = 1,
                    updatedAtEpochMillis = 1,
                ),
            )
            return captured
        }

        suspend fun complete(commit: suspend (suspend () -> Boolean) -> Boolean = { it() }) {
            completeVaultPendingDownloads(
                context,
                identity,
                transfers,
                downloads,
                { true },
            ) { job, payloads, permit, finish ->
                publishingJob = job
                session.publishBackgroundDownload(job, payloads, offline, permit) { commit(finish) }
            }
        }

        fun restarted(directory: File) =
            VaultOfflineStore(
                directory,
                { currentAccount },
                { { true } },
                EndpointPolicy(true),
                { VaultOfflineTestCipher() },
                durability = jvmOfflineDurability(directory),
                publicationAccepted = { transferId, _ -> transfers.transfer(transferId)?.state == "SUCCEEDED" },
            )

        suspend fun assertContent(
            expected: String,
            target: VaultOfflineStore = offline,
            directory: File = root,
        ) {
            target.openWithKeyMaterial(account.id, location, material)!!.use { reopened ->
                val output = ByteArrayOutputStream()
                reopened.download(reopened.list().single(), output)
                assertEquals(expected, output.toString(Charsets.UTF_8.name()))
            }
            assertEquals(1, directory.walkTopDown().filter { it.parentFile?.name == "blobs" && it.isFile }.count())
        }

        override fun close() {
            if (::session.isInitialized) session.close()
            database.close()
        }
    }

    @Test fun hkdfSha256MatchesRfc5869TestCaseOne() {
        val ikm = ByteArray(22) { 0x0b }
        val salt = hex("000102030405060708090a0b0c")
        val info = hex("f0f1f2f3f4f5f6f7f8f9")
        val expected =
            hex(
                "3cb25f25faacd57a90434f64d0362f2a" +
                    "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
                    "34007208d5b887185865",
            )
        assertArrayEquals(expected, hkdfSha256(ikm, salt, info, 42))
        ikm.fill(0)
        salt.fill(0)
        info.fill(0)
    }

    @Test fun wrongKeyAndCrossIdentityManifestReplayFailClosed() =
        runBlocking {
            val encrypted = fakeCiphertext(byteArrayOf(1, 2, 3))
            store.pinFile(
                identity,
                location,
                fileEntry("enc_first", encrypted.size.toLong()),
                material,
            ) { it.write(encrypted) }
            assertThrows(OpenCloudException::class.java) {
                runBlocking { store.openWithKeyMaterial(account.id, location, ByteArray(80) { 9 }) }
            }
            val originalManifest = root.walkTopDown().first { it.name == "manifest.enc" }
            val other = location.copy(remoteVaultId = "other-vault")
            val otherIdentity = VaultIdentity(account.id, account.serverUrl, "drive", "other-vault")
            store.pinFile(
                otherIdentity,
                other,
                fileEntry("enc_second", encrypted.size.toLong()),
                material,
            ) { it.write(encrypted) }
            val otherManifest = root.walkTopDown().filter { it.name == "manifest.enc" }.first { it != originalManifest }
            originalManifest.copyTo(otherManifest, overwrite = true)
            assertThrows(OpenCloudException::class.java) {
                runBlocking { store.openWithKeyMaterial(account.id, other, material) }
            }
            Unit
        }

    @Test fun damagedBlobAndAccountRemovalPreventPlaintextAccess() =
        runBlocking {
            val encrypted = fakeCiphertext("secret".toByteArray())
            store.pinFile(
                identity,
                location,
                fileEntry("enc_data", encrypted.size.toLong()),
                material,
            ) { it.write(encrypted) }
            val session = store.openWithKeyMaterial(account.id, location, material)!!
            val listed = session.list().single()
            val blob = root.walkTopDown().first { it.parentFile?.name == "blobs" && !it.name.startsWith("staging-") }
            blob.writeBytes(blob.readBytes().also { it[32] = (it[32].toInt() xor 1).toByte() })
            val output = ByteArrayOutputStream()
            assertThrows(OpenCloudException::class.java) { runBlocking { session.download(listed, output) } }
            assertEquals(0, output.size())
            currentAccount = null
            assertThrows(OpenCloudException::class.java) { runBlocking { session.list() } }
            store.forgetAccount(account.id)
            assertFalse(root.walkTopDown().any { it.name == "manifest.enc" })
            session.close()
        }

    @Test fun partialPinFailureLeavesNoPublishedSnapshotOrStage() =
        runBlocking {
            val encrypted = fakeCiphertext(byteArrayOf(1, 2, 3))
            assertThrows(IOException::class.java) {
                runBlocking {
                    store.pinFile(identity, location, fileEntry("enc_partial", encrypted.size.toLong()), material) {
                        it.write(encrypted, 0, 10)
                        throw IOException("synthetic interruption")
                    }
                }
            }
            assertFalse(store.hasSnapshot(identity))
            assertFalse(root.walkTopDown().any { it.name.startsWith("staging-") })
        }

    @Test fun revokeBlocksOpenAndExistingSessionBeforeWaitingForPin() {
        val encrypted = fakeCiphertext(byteArrayOf(1, 2, 3))
        runBlocking {
            store.pinFile(identity, location, fileEntry("enc_existing", encrypted.size.toLong()), material) {
                it.write(encrypted)
            }
        }
        val session = runBlocking { store.openWithKeyMaterial(account.id, location, material)!! }
        val pinStarted = CountDownLatch(1)
        val releasePin = CountDownLatch(1)
        val workers = Executors.newFixedThreadPool(2)
        try {
            val pin =
                workers.submit<Unit> {
                    runBlocking {
                        store.pinFile(
                            identity,
                            location,
                            fileEntry("enc_refresh", encrypted.size.toLong()),
                            material,
                        ) {
                            pinStarted.countDown()
                            check(releasePin.await(5, TimeUnit.SECONDS))
                            it.write(encrypted)
                        }
                    }
                }
            assertTrue(pinStarted.await(5, TimeUnit.SECONDS))
            val removal = workers.submit<Unit> { runBlocking { store.remove(identity) } }
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            while (!VaultOfflineRevocations.identityBlocked(identity) && System.nanoTime() < deadline) {
                Thread.sleep(5)
            }
            assertTrue(VaultOfflineRevocations.identityBlocked(identity))
            assertThrows(OpenCloudException::class.java) { runBlocking { session.list() } }
            assertThrows(OpenCloudException::class.java) {
                runBlocking { store.openWithKeyMaterial(account.id, location, material) }
            }
            releasePin.countDown()
            assertThrows(java.util.concurrent.ExecutionException::class.java) { pin.get(5, TimeUnit.SECONDS) }
            removal.get(5, TimeUnit.SECONDS)
            assertFalse(runBlocking { store.hasSnapshot(identity) })
        } finally {
            releasePin.countDown()
            session.close()
            workers.shutdownNow()
        }
    }

    private fun fileEntry(
        name: String,
        size: Long,
    ) = VaultFolder(
        id = name,
        name = name,
        rawName = name,
        path = name,
        encryptedPath = "Secret.vault/$name",
        isFolder = false,
        size = size,
        strongETag = "\"tag\"",
    )

    private fun fakeCiphertext(plain: ByteArray) = ByteArray(32) { 7 } + plain + ByteArray(16) { 9 }

    private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
