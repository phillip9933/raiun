package eu.opencloud.android.next.core.database

import androidx.room.Room
import eu.opencloud.android.next.core.model.ResourceKind
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class TransferIntentTest {
    private lateinit var database: FileBrowserDatabase
    private lateinit var store: FileBrowserStore
    private val resource =
        ResourceEntity("a", "s", "server-id", null, "/file", "file", ResourceKind.FILE, null, 5, "v1", 0, 0)
    private val upload =
        TransferEntity(
            "upload",
            "a",
            "s",
            null,
            "UPLOAD",
            "content://source/file",
            "/file",
            "file",
            null,
            5,
            createdAtEpochMillis = 0,
            updatedAtEpochMillis = 0,
        )

    @Before fun setUp() =
        runTest {
            database =
                Room
                    .inMemoryDatabaseBuilder(
                        RuntimeEnvironment.getApplication(),
                        FileBrowserDatabase::class.java,
                    ).build()
            store = FileBrowserStore(database)
            database.accountDao().upsert(AccountEntity("a", "https://example.test", "user", "User", "BASIC", false))
            database.spaceDao().insert(
                SpaceEntity("a", "s", "Space", "project", null, null, "root", "https://example.test/dav", null, null),
            )
            database.resourceDao().insert(resource)
        }

    @After fun tearDown() = database.close()

    @Test fun `ciphertext admission cannot accept a plaintext upload and ordinary queue still rejects vaults`() =
        runTest {
            val encrypted = upload.copy(id = "encrypted", locationKind = "VAULT", sourceUri = null, bytesTotal = 64)
            org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
                kotlinx.coroutines.runBlocking { store.enqueueCiphertextUpload(upload) }
            }
            org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
                kotlinx.coroutines.runBlocking { store.enqueueTransfer(encrypted) }
            }
            assertEquals(encrypted, store.enqueueCiphertextUpload(encrypted))
            assertEquals(encrypted.id, store.claimTransfer(encrypted.id, "worker", 0)?.id)
        }

    @Test fun `ciphertext retry cannot alter destination or account identity`() =
        runTest {
            val encrypted =
                upload.copy(
                    id = "encrypted",
                    locationKind = "VAULT",
                    sourceUri = null,
                    bytesTotal = 64,
                    state = "FAILED",
                )
            store.enqueueCiphertextUpload(encrypted)
            val retry = encrypted.copy(state = "QUEUED", workId = "worker", updatedAtEpochMillis = 1)
            org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
                kotlinx.coroutines.runBlocking {
                    store.retryCiphertextUpload(
                        encrypted,
                        retry.copy(destinationPath = "/other"),
                    )
                }
            }
            assertEquals(retry, store.retryCiphertextUpload(encrypted, retry))
        }

    @Test fun `backup blocking query matches exact pending upload and ignores history`() =
        runTest {
            listOf("SUCCEEDED", "FAILED", "CANCELLED", "CONFLICT").forEach { state ->
                store.createTransfer(upload.copy(id = state, state = state))
            }
            assertFalse(store.hasActiveBackupUpload("a", "s", "content://source/file", "/file"))
            store.createTransfer(upload.copy(state = "RUNNING"))
            assertTrue(store.hasActiveBackupUpload("a", "s", "content://source/file", "/file"))
            assertFalse(store.hasActiveBackupUpload("a", "s", "content://source/other", "/file"))
            assertFalse(store.hasActiveBackupUpload("a", "s", "content://source/file", "/other"))
            assertFalse(store.hasActiveBackupUpload("other", "s", "content://source/file", "/file"))
            assertFalse(store.hasActiveBackupUpload("a", "other", "content://source/file", "/file"))
        }

    @Test fun `folder exclusion cancels only transfers within that subtree`() =
        runTest {
            val nested = upload.copy(destinationPath = "/secret/file", state = "RUNNING", workId = "worker")
            store.enqueueTransfer(nested)
            store.enqueueTransfer(upload.copy(id = "neighbor", destinationPath = "/secret-more/file"))
            store.replaceDiscoveredFolderSnapshot("a", "s", null, FolderSnapshot(emptyList(), setOf("/secret")))
            assertEquals("CANCELLED", store.transfer(nested.id)?.state)
            assertEquals("QUEUED", store.transfer("neighbor")?.state)
            assertFalse(store.updateActiveTransfer(nested.copy(state = "SUCCEEDED")))
        }

    @Test fun `vault exclusion revokes active worker ownership and preserves completed history`() =
        runTest {
            val active = upload.copy(state = "RUNNING", workId = "worker")
            store.enqueueTransfer(active)
            store.createTransfer(upload.copy(id = "done", state = "SUCCEEDED"))
            database.accountDao().upsert(requireNotNull(database.accountDao().findById("a")).copy(id = "b"))
            database.spaceDao().insert(requireNotNull(store.space("a", "s")).copy(accountId = "b"))
            store.enqueueTransfer(upload.copy(id = "other", accountId = "b"))
            assertTrue(store.replaceRemoteSpaces("a", emptyList(), excludedVaultIds = setOf("s")))
            assertEquals("CANCELLED", store.transfer("upload")?.state)
            assertEquals("SUCCEEDED", store.transfer("done")?.state)
            assertEquals("QUEUED", store.transfer("other")?.state)
            assertFalse(store.updateActiveTransfer(active.copy(state = "SUCCEEDED")))
            assertFalse(store.completeUpload(active))
        }

    @Test fun `concurrent retry actions accept only one replacement and stale success cannot be retried`() =
        runTest {
            val failed = upload.copy(state = "FAILED", bytesTransferred = 5, verificationPending = true)
            store.enqueueTransfer(failed)
            val reset = failed.copy(state = "QUEUED", workId = null, attemptCount = 0)
            val attempts =
                (0 until 16)
                    .map {
                        async(Dispatchers.Default) { FileBrowserStore(database).retryTransfer(failed, reset) }
                    }.awaitAll()
            assertEquals(1, attempts.count { it != null })
            assertTrue(requireNotNull(store.transfer(upload.id)).verificationPending)
            store.updateTransfer(reset.copy(state = "SUCCEEDED"))
            assertEquals(null, store.retryTransfer(failed, reset))
            assertEquals("SUCCEEDED", store.transfer(upload.id)?.state)
        }

    @Test fun `same destination waits for earlier upload retry while different destinations can run`() =
        runTest {
            val first = upload.copy(id = "first", state = "RETRY", createdAtEpochMillis = 1)
            val second = upload.copy(id = "second", sourceUri = "content://other", createdAtEpochMillis = 2)
            store.enqueueTransfer(first)
            store.enqueueTransfer(second)
            assertEquals(null, store.claimTransfer(second.id, "second-worker", 10))
            val different = second.copy(id = "different", destinationPath = "/other")
            store.enqueueTransfer(different)
            assertEquals("RUNNING", store.claimTransfer(different.id, "other-worker", 10)?.state)
            val running = requireNotNull(store.claimTransfer(first.id, "first-worker", 10))
            assertEquals(null, store.claimTransfer(second.id, "second-worker", 11))
            store.updateActiveTransfer(running.copy(state = "SUCCEEDED"))
            assertEquals("RUNNING", store.claimTransfer(second.id, "second-worker", 12)?.state)
        }

    @Test fun `simultaneous workers cannot claim the same upload destination`() =
        runTest {
            repeat(8) { index ->
                store.enqueueTransfer(upload.copy(id = "candidate-$index", sourceUri = "content://source/$index"))
            }
            val claimed =
                (0 until 8)
                    .map { index ->
                        async(Dispatchers.Default) { store.claimTransfer("candidate-$index", "worker-$index", 10) }
                    }.awaitAll()
                    .filterNotNull()
            assertEquals(listOf("candidate-0"), claimed.map { it.id })
        }

    @Test fun `overlapping running intents from an older process release their markers and recover in order`() =
        runTest {
            val first = upload.copy(id = "first", state = "RUNNING", workId = "first-worker", attemptCount = 2)
            val second =
                upload.copy(
                    id = "second",
                    sourceUri = "content://other",
                    state = "RUNNING",
                    workId = "second-worker",
                    createdAtEpochMillis = 1,
                    bytesTransferred = 5,
                    verificationPending = true,
                    tusUrl = "https://example.test/session",
                    tusOffset = 5,
                )
            store.enqueueTransfer(first)
            store.enqueueTransfer(second)
            assertEquals(null, store.claimTransfer(first.id, "first-worker", 10))
            assertEquals(null, store.claimTransfer(second.id, "second-worker", 11))
            assertEquals(second.copy(state = "RETRY", updatedAtEpochMillis = 11), store.transfer(second.id))
            val claimed = requireNotNull(store.claimTransfer(first.id, "first-worker", 12))
            assertEquals(2, claimed.attemptCount)
            assertEquals(null, store.claimTransfer(second.id, "second-worker", 13))
            store.updateActiveTransfer(claimed.copy(state = "SUCCEEDED"))
            assertEquals("RUNNING", store.claimTransfer(second.id, "second-worker", 14)?.state)
        }

    @Test fun `obsolete worker cannot release another worker running marker`() =
        runTest {
            val first = upload.copy(id = "first", state = "RUNNING", workId = "current-worker")
            store.enqueueTransfer(first)
            store.enqueueTransfer(upload.copy(id = "other", sourceUri = "content://other", state = "RUNNING"))
            assertEquals(null, store.claimTransfer(first.id, "obsolete-worker", 10))
            assertEquals(first, store.transfer(first.id))
        }

    @Test fun `completed upload progress persists verification intent independently of retry count`() =
        runTest {
            val running = upload.copy(state = "RUNNING", workId = "worker")
            store.enqueueTransfer(running)
            assertTrue(store.updateTransferProgress(running, running.bytesTotal, 10))
            val checkpoint = requireNotNull(store.transfer(running.id))
            assertTrue(checkpoint.verificationPending)
            store.updateTransfer(checkpoint.copy(state = "QUEUED", attemptCount = 0))
            assertTrue(requireNotNull(store.transfer(running.id)).verificationPending)
        }

    @Test fun `queue insertion order survives backwards clocks and reverse lexical ids`() =
        runTest {
            val first = upload.copy(id = "z-first", createdAtEpochMillis = 10000)
            val later = upload.copy(id = "a-later", sourceUri = "content://later", createdAtEpochMillis = 1)
            store.enqueueTransfer(first)
            store.enqueueTransfer(later)
            assertEquals(null, store.claimTransfer(later.id, "later-worker", 2))
            val running = requireNotNull(store.claimTransfer(first.id, "first-worker", 3))
            store.updateActiveTransfer(running.copy(state = "RETRY"))
            assertEquals(null, store.claimTransfer(later.id, "later-worker", 4))
            store.updateActiveTransfer(running.copy(state = "SUCCEEDED"))
            assertEquals("RUNNING", store.claimTransfer(later.id, "later-worker", 5)?.state)
        }

    @Test fun `manual retry joins queue tail without allowing stale retry to reorder it`() =
        runTest {
            val failed = upload.copy(state = "FAILED")
            val waiting = upload.copy(id = "waiting", sourceUri = "content://waiting", createdAtEpochMillis = 100)
            store.enqueueTransfer(failed)
            store.enqueueTransfer(waiting)
            val retried = requireNotNull(store.retryTransfer(failed, failed.copy(state = "QUEUED")))
            assertEquals(null, store.retryTransfer(failed, failed.copy(state = "QUEUED")))
            assertEquals(null, store.claimTransfer(retried.id, "retry-worker", 1))
            val running = requireNotNull(store.claimTransfer(waiting.id, "waiting-worker", 2))
            store.updateActiveTransfer(running.copy(state = "SUCCEEDED"))
            assertEquals("RUNNING", store.claimTransfer(retried.id, "retry-worker", 3)?.state)
            store.removeAccount("a")
            database.openHelper.readableDatabase.query("SELECT COUNT(*) FROM transfer_queue").use {
                assertTrue(it.moveToFirst())
                assertEquals(0, it.getInt(0))
            }
        }

    @Test fun `retry now replaces persisted retry ownership and retains upload verification checkpoint`() =
        runTest {
            val waiting =
                upload.copy(
                    state = "RETRY",
                    workId = "old-worker",
                    bytesTransferred = upload.bytesTotal,
                    verificationPending = true,
                    notBeforeEpochMillis = 60_000,
                    attemptCount = 4,
                )
            store.enqueueTransfer(waiting)
            val replacement =
                waiting.copy(
                    state = "QUEUED",
                    workId = "new-worker",
                    notBeforeEpochMillis = 0,
                    attemptCount = 0,
                )
            assertEquals(replacement, store.retryTransfer(waiting, replacement))
            assertEquals(null, store.claimTransfer(waiting.id, "old-worker", 1))
            val claimed = requireNotNull(store.claimTransfer(waiting.id, "new-worker", 2))
            assertTrue(claimed.verificationPending)
            assertEquals(upload.bytesTotal, claimed.bytesTransferred)
        }

    @Test fun `export cleanup cannot clear a newer downloaded copy`() =
        runTest {
            val old = resource.copy(hasLocalCopy = true, localPath = "/cache/old", offlinePinned = true)
            val newer = old.copy(localPath = "/cache/new", eTag = "new-version")
            database.resourceDao().update(newer)
            assertFalse(store.clearMatchingLocalCopy(old))
            assertEquals(newer, store.resource("a", "s", resource.remoteId))
            assertTrue(store.clearMatchingLocalCopy(newer))
            assertFalse(requireNotNull(store.resource("a", "s", resource.remoteId)).hasLocalCopy)
        }

    @Test fun `removing local copy preserves cloud identity and favorite while clearing offline pin`() =
        runTest {
            val downloaded =
                resource.copy(
                    hasLocalCopy = true,
                    localPath = "/cache/file",
                    offlinePinned = true,
                    isFavorite = true,
                )
            database.resourceDao().update(downloaded)
            store.clearLocalCopy(downloaded)
            val current = requireNotNull(store.resource("a", "s", resource.remoteId))
            assertEquals(downloaded.copy(hasLocalCopy = false, localPath = null, offlinePinned = false), current)
        }

    @Test fun `display progress preserves durable tus checkpoint and cannot revive cancellation`() =
        runTest {
            val transfer = store.enqueueTransfer(upload)
            val running =
                requireNotNull(store.claimTransfer(transfer.id, "worker", 1))
                    .copy(tusUrl = "https://example.test/session", tusOffset = 10)
            store.updateActiveTransfer(running)
            assertTrue(store.updateTransferProgress(running, 50, 2))
            assertEquals(50L, store.transfer(running.id)?.bytesTransferred)
            assertEquals(10L, store.transfer(running.id)?.tusOffset)
            store.cancelTransfer(running.id)
            assertFalse(store.updateTransferProgress(running, 100, 3))
            assertEquals("CANCELLED", store.transfer(running.id)?.state)
        }

    @Test fun `independent stores concurrently accept exactly one intent per direction`() =
        runTest {
            val accepted =
                (0 until 32)
                    .map { index ->
                        async(Dispatchers.Default) {
                            FileBrowserStore(database).enqueueTransfer(upload.copy(id = "upload-$index")).id
                        }
                    }.awaitAll()
            assertEquals(1, accepted.toSet().size)
            val downloads =
                (0 until 32)
                    .map { index ->
                        async(Dispatchers.Default) {
                            FileBrowserStore(database)
                                .enqueueTransfer(
                                    upload.copy(
                                        id = "download-$index",
                                        direction = "DOWNLOAD",
                                        resourceId = resource.remoteId,
                                        sourceUri = null,
                                        offlinePin = index == 31,
                                    ),
                                ).id
                        }
                    }.awaitAll()
            assertEquals(1, downloads.toSet().size)
            assertEquals(2, store.pendingTransfers().size)
            assertTrue(requireNotNull(store.resource("a", "s", resource.remoteId)).offlinePinned)
        }

    @Test fun `removed account cannot acquire new intent`() =
        runTest {
            store.removeAccount("a")
            try {
                store.enqueueTransfer(upload)
                org.junit.Assert.fail("Removed account accepted work")
            } catch (_: IllegalArgumentException) {
                assertTrue(store.pendingTransfers().isEmpty())
            }
        }

    @Test fun `verified upload preserves server identity and pin but invalidates cached bytes`() =
        runTest {
            store.setOfflinePinned(resource, true)
            store.updateLocalCopy("a", "s", resource.remoteId, "/cache/file")
            val running = upload.copy(state = "RUNNING", workId = "worker")
            store.createTransfer(running)
            val old = store.beginSnapshot("a")
            assertTrue(store.completeUpload(running))
            val retained = requireNotNull(store.resource("a", "s", resource.remoteId))
            val discovery = store.pendingDiscoveries().single()
            assertEquals("a", discovery.accountId)
            assertEquals("s", discovery.spaceId)
            assertEquals("", discovery.folderKey)
            assertTrue(retained.offlinePinned)
            assertFalse(retained.hasLocalCopy)
            assertEquals(null, retained.localPath)
            assertEquals(1, store.children("a", "s", null).size)
            assertFalse(store.replaceFolderSnapshot("a", "s", null, emptyList(), old))
            store.cancelTransfer(running.id)
            assertFalse(store.completeUpload(running))
            assertEquals(discovery, store.pendingDiscoveries().single())
        }

    @Test fun `new upload does not fabricate resource identity and stale worker cannot invalidate cache`() =
        runTest {
            val running = upload.copy(state = "RUNNING", workId = "new-worker", destinationPath = "/new")
            store.createTransfer(running)
            assertFalse(store.completeUpload(running.copy(workId = "old-worker")))
            assertTrue(store.completeUpload(running))
            assertEquals(null, store.resourceAtPath("a", "s", "/new"))
            store.removeAccount("a")
            assertFalse(store.completeUpload(running))
        }

    @Test fun `pending encrypted offline completion is exact and cancellation wins`() =
        runTest {
            val pending =
                upload.copy(
                    direction = "DOWNLOAD",
                    locationKind = "VAULT",
                    sourceUri = "vault-offline:root",
                    resourceId = "source",
                    bytesTotal = 96,
                    offlinePin = true,
                    state = "AWAITING_UNLOCK",
                )
            store.enqueueCiphertextDownload(pending)
            assertEquals(listOf(pending), store.awaitingCiphertextDownloadsPage("a", "vault-offline:root", "", 128))
            assertTrue(store.awaitingCiphertextDownloadsPage("a", "vault-offline:other", "", 128).isEmpty())
            val complete = pending.copy(state = "SUCCEEDED", verificationPending = false)
            org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
                kotlinx.coroutines.runBlocking {
                    store.completeAwaitingCiphertextDownload(pending, complete.copy(resourceId = "substitute"))
                }
            }
            store.cancelTransfer(pending.id)
            assertFalse(store.completeAwaitingCiphertextDownload(pending, complete))
            assertEquals("CANCELLED", store.transfer(pending.id)?.state)
        }
}
