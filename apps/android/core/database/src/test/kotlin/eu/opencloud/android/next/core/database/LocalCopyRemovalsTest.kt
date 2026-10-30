package eu.opencloud.android.next.core.database

import androidx.room.Room
import eu.opencloud.android.next.core.model.ResourceKind
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File
import java.io.IOException
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

@RunWith(RobolectricTestRunner::class)
class LocalCopyRemovalsTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun bulkAdmissionFreezesPostUnpinRowsAcrossSpacesAndRevokesOnlyOldSelectionRights() {
        runBlocking {
            fixture { f ->
                val copies =
                    (0 until 386).map { number ->
                        f
                            .row((number / 2).toString().padStart(4, '0'), if (number % 2 == 0) "one" else "two")
                            .copy(offlinePinned = number % 3 == 0)
                    }
                val folders =
                    (0 until 130).map { number ->
                        f.row("pin-$number").copy(
                            kind = ResourceKind.FOLDER,
                            path = "/pin-$number",
                            hasLocalCopy = false,
                            localPath = null,
                            offlinePinned = true,
                        )
                    }
                val disabled = f.row("disabled", "disabled").copy(offlinePinned = true)
                f.db.resourceDao().insertAll(copies + folders + disabled)
                val run = OfflineTraversalStore(f.db).start(folders.first())
                f.pending("/old-pending")
                val operation = f.operation("old-move", folders.first())
                f.db.pendingPinDao().preserve("a", "one", folders.first().path, operation.id)
                val scopes = f.service.captureAll("a", f.stages)!!
                scopes.use { scope ->
                    assertEquals(
                        "CANCELLED",
                        f.db
                            .offlineTraversalDao()
                            .run(run.id)!!
                            .state,
                    )
                    assertFalse(f.db.pendingPinDao().selected("a", "one", "/old-pending"))
                    f.db.pendingPinDao().activate("a", "one", "/moved", operation.id)
                    assertFalse(f.db.pendingPinDao().selected("a", "one", "/moved"))
                    assertEquals(operation, f.db.fileOperationDao().find(operation.id))
                    f.pending("/new-pending")
                    val late = f.row("000-late")
                    f.db.resourceDao().insert(late)
                    var after: TemporaryCopyKey? = null
                    var scanned = 0
                    var deleted = 0
                    while (true) {
                        val page = f.service.page(scope, after)
                        if (page.isEmpty()) break
                        assertTrue(page.size <= 128)
                        for (row in page) {
                            assertFalse(row.resource.offlinePinned)
                            if (row.resource.remoteId == "disabled") assertFalse(row.removeCopy)
                            assertEquals(
                                LocalCopyRemovalDecision.Applied,
                                f.service.remove(scope, row) {
                                    deleted++
                                    true
                                },
                            )
                            scanned++
                        }
                        after = page.last().resource.let { TemporaryCopyKey(it.spaceId, it.remoteId) }
                    }
                    assertEquals(517, scanned)
                    assertEquals(386, deleted)
                    copies.forEach { row ->
                        assertEquals(
                            row.copy(offlinePinned = false, hasLocalCopy = false, localPath = null),
                            f.store.resource("a", row.spaceId, row.remoteId),
                        )
                    }
                    assertEquals(disabled.copy(offlinePinned = false), f.store.resource("a", "disabled", "disabled"))
                    assertEquals(late, f.store.resource("a", "one", late.remoteId))
                    assertTrue(f.db.pendingPinDao().selected("a", "one", "/new-pending"))
                }
                assertTrue(
                    f.stages
                        .listFiles()
                        .orEmpty()
                        .isEmpty(),
                )
            }
        }
    }

    @Test fun singleRemovalRejectsFullRowChangeAndANewInnerAncestorEvenUnderAnExistingOuterPin() {
        runBlocking {
            fixture { f ->
                val target = f.row("file").copy(path = "/outer/inner/file", offlinePinned = true)
                val outer =
                    f.row("outer").copy(
                        path = "/outer",
                        kind = ResourceKind.FOLDER,
                        offlinePinned = true,
                        hasLocalCopy = false,
                        localPath = null,
                    )
                f.db.resourceDao().insertAll(listOf(target, outer))
                f.service.captureOne(target, true, f.stages)!!.use { scope ->
                    val captured = f.service.page(scope).single()
                    val newer = target.copy(isFavorite = !target.isFavorite)
                    f.db.resourceDao().update(newer)
                    var calls = 0
                    assertEquals(
                        LocalCopyRemovalDecision.Changed,
                        f.service.remove(scope, captured) {
                            calls++
                            true
                        },
                    )
                    assertEquals(0, calls)
                    assertEquals(newer, f.store.resource("a", "one", "file"))
                }
                f.db.resourceDao().update(target)
                f.service.captureOne(target, false, f.stages)!!.use { scope ->
                    val captured = f.service.page(scope).single()
                    val inner =
                        outer.copy(
                            remoteId = "inner",
                            path = "/outer/inner",
                            name = "inner",
                            parentId = outer.remoteId,
                        )
                    f.db.resourceDao().insert(inner)
                    assertEquals(
                        LocalCopyRemovalDecision.Changed,
                        f.service.remove(scope, captured) { error("must retain") },
                    )
                    assertEquals(inner, f.store.resource("a", "one", "inner"))
                    assertEquals(target, f.store.resource("a", "one", "file"))
                }
            }
        }
    }

    @Test fun bulkRetainsNewPinsAncestorsAndPendingRightsWhileContinuingLaterRows() {
        runBlocking {
            fixture { f ->
                val originals = listOf(f.row("a").copy(path = "/new-root/file"), f.row("b"), f.row("c"))
                f.db.resourceDao().insertAll(originals)
                f.service.captureAll("a", f.stages)!!.use { scope ->
                    val page = f.service.page(scope)
                    val parent =
                        f.row("root").copy(
                            path = "/new-root",
                            kind = ResourceKind.FOLDER,
                            offlinePinned = true,
                            hasLocalCopy = false,
                            localPath = null,
                        )
                    f.db.resourceDao().insert(parent)
                    f.pending(originals[1].path)
                    assertEquals(
                        LocalCopyRemovalDecision.Changed,
                        f.service.remove(scope, page[0]) { error("ancestor") },
                    )
                    assertEquals(
                        LocalCopyRemovalDecision.Changed,
                        f.service.remove(scope, page[1]) { error("pending pin") },
                    )
                    assertEquals(LocalCopyRemovalDecision.Applied, f.service.remove(scope, page[2]) { true })
                    assertEquals(parent, f.store.resource("a", "one", "root"))
                    assertEquals(originals[0], f.store.resource("a", "one", "a"))
                    assertEquals(originals[1], f.store.resource("a", "one", "b"))
                }
            }
        }
    }

    @Test fun identicalAccountAbaThroughAnotherRoomInstanceCannotReuseTheOldSnapshot() {
        runBlocking {
            fixture { f ->
                val original = f.row("file").copy(offlinePinned = true)
                f.db.resourceDao().insert(original)
                f.service.captureOne(original, true, f.stages)!!.use { scope ->
                    val row = f.service.page(scope).single()
                    val second = f.open()
                    try {
                        FileBrowserStore(second).removeAccount("a")
                        second.accountDao().upsert(f.account)
                        second.spaceDao().upsertAll(listOf(f.space("one")))
                        second.resourceDao().insert(original)
                        FileBrowserStore(second).vaultOfflineGroups().captureOwner("a")
                    } finally {
                        second.close()
                    }
                    assertTrue(f.db.temporaryCopyVersions.isCurrent(scope.token))
                    assertEquals(f.account, f.db.accountDao().findById("a"))
                    assertEquals(original, f.store.resource("a", "one", "file"))
                    assertNotEquals(
                        scope.incarnation,
                        f.db
                            .vaultOfflineGroupDao()
                            .owner("a")!!
                            .incarnation,
                    )
                    assertEquals(LocalCopyRemovalDecision.Changed, f.service.remove(scope, row) { error("old owner") })
                    assertThrows(LocalCopyRemovalChangedException::class.java) { runBlocking { f.service.page(scope) } }
                }
            }
        }
    }

    @Test fun queueWatermarkKeepsLaterLowerIdsAndSameIdRetriesAndOnlyCancelsDownloads() {
        runBlocking {
            fixture { f ->
                val target = f.row("file")
                f.db.resourceDao().insert(target)
                val old = f.transfer("z-old", target)
                val retrying = f.transfer("retry", target).copy(state = "FAILED")
                val upload = f.transfer("upload", target).copy(direction = "UPLOAD", resourceId = null)
                listOf(old, retrying, upload).forEach { f.db.transferDao().insert(it) }
                f.service.captureAll("a", f.stages)!!.use { scope ->
                    val late = f.transfer("000-late", target)
                    f.db.transferDao().insert(late)
                    val replacement = retrying.copy(state = "QUEUED", workId = UUID.randomUUID().toString())
                    assertEquals(replacement, f.db.transferDao().retry(retrying, replacement))
                    assertEquals(listOf(old), f.service.downloadPage(scope))
                    assertEquals(old, f.service.cancelDownload(scope, old.id))
                    assertEquals(null, f.service.cancelDownload(scope, upload.id))
                    assertEquals(null, f.service.cancelDownload(scope, replacement.id))
                    assertEquals("CANCELLED", f.store.transfer(old.id)!!.state)
                    assertEquals(late, f.store.transfer(late.id))
                    assertEquals(replacement, f.store.transfer(replacement.id))
                    assertEquals(upload, f.store.transfer(upload.id))
                    assertEquals(
                        LocalCopyRemovalDecision.ActiveDownload,
                        f.service.remove(scope, f.service.page(scope).single()) { error("new download") },
                    )
                }
            }
        }
    }

    @Test fun identicalRowLateCompletedDownloadsAndBothHistoryClearPathsRevokeOldDeletionProof() {
        runBlocking {
            fixture { f ->
                val otherAccount = f.account.copy(id = "other")
                val other = f.row("other-file").copy(accountId = "other")
                f.db.accountDao().upsert(otherAccount)
                f.db.spaceDao().upsertAll(listOf(f.space("one").copy(accountId = "other")))
                f.db.resourceDao().insert(other)
                f.service.captureOne(other, false, f.stages)!!.use { unaffected ->
                    val otherRow = f.service.page(unaffected).single()
                    for (clear in listOf("none", "direct", "scoped")) {
                        val original = f.row("file-$clear")
                        f.db.resourceDao().insert(original)
                        f.service.captureOne(original, true, f.stages)!!.use { scope ->
                            val row = f.service.page(scope).single()
                            val completed = f.transfer("late-$clear", original).copy(state = "SUCCEEDED")
                            f.db.transferDao().insert(completed)
                            assertEquals(original, f.store.resource("a", "one", original.remoteId))
                            when (clear) {
                                "direct" -> f.store.clearTransferHistory("a")
                                "scoped" -> {
                                    val inventory = f.store.transferInventory()
                                    inventory.deleteScopedHistory(inventory.captureScope("a")!!)
                                }
                            }
                            var callbacks = 0
                            assertEquals(
                                LocalCopyRemovalDecision.Changed,
                                f.service.remove(scope, row) {
                                    callbacks++
                                    true
                                },
                            )
                            assertEquals(0, callbacks)
                            assertEquals(original, f.store.resource("a", "one", original.remoteId))
                            if (clear != "none") {
                                assertEquals(null, f.store.transfer(completed.id))
                                assertThrows(LocalCopyRemovalChangedException::class.java) {
                                    runBlocking { f.service.page(scope) }
                                }
                            }
                        }
                    }
                    assertEquals(LocalCopyRemovalDecision.Applied, f.service.remove(unaffected, otherRow) { true })
                    assertFalse(f.store.resource("other", "one", other.remoteId)!!.hasLocalCopy)
                }
            }
        }
    }

    @Test fun deleteRefusalCancellationAndStaleExportKeepOriginalMetadataAndCloseOnlyTheirStage() {
        runBlocking {
            fixture { f ->
                val original = f.row("file").copy(offlinePinned = true)
                f.db.resourceDao().insert(original)
                val other = f.service.captureOne(original, false, f.stages)!!
                try {
                    f.service.captureOne(original, true, f.stages)!!.use { scope ->
                        val row = f.service.page(scope).single()
                        assertThrows(IOException::class.java) { runBlocking { f.service.remove(scope, row) { false } } }
                        assertThrows(CancellationException::class.java) {
                            runBlocking { f.service.remove(scope, row) { throw CancellationException("stop") } }
                        }
                        assertEquals(original, f.store.resource("a", "one", "file"))
                    }
                    assertEquals(
                        2,
                        f.stages
                            .listFiles()
                            .orEmpty()
                            .size,
                    )
                    val transfer = f.transfer("active", original)
                    f.db.transferDao().insert(transfer)
                    val replacement = original.copy(eTag = "new", localPath = "/private/new")
                    f.db.resourceDao().update(replacement)
                    assertThrows(LocalCopyRemovalChangedException::class.java) {
                        runBlocking { f.service.captureOne(original, true, f.stages) }
                    }
                    assertEquals(transfer, f.store.transfer(transfer.id))
                    assertEquals(replacement, f.store.resource("a", "one", "file"))
                    assertEquals(
                        2,
                        f.stages
                            .listFiles()
                            .orEmpty()
                            .size,
                    )
                } finally {
                    other.close()
                }
                assertTrue(
                    f.stages
                        .listFiles()
                        .orEmpty()
                        .isEmpty(),
                )
            }
        }
    }

    @Test fun bulkDownloadCancellationPreservesIndependentGroupPublicationReceiptAfterHistoryClear() {
        runBlocking {
            fixture { f ->
                val groups = f.store.vaultOfflineGroups()
                val owner = groups.captureOwner("a")!!
                val id = UUID.randomUUID().toString()
                val descriptor =
                    VaultGroupDescriptor(
                        id,
                        "one",
                        "vault",
                        "1".repeat(64),
                        id,
                        "2".repeat(64),
                        "3".repeat(64),
                        id,
                    )
                val preparing = groups.beginPreparation(owner, descriptor)!!
                val member = VaultGroupMemberAdmission(0, UUID.randomUUID().toString(), "4".repeat(64), "DIRECTORY")
                val staged =
                    groups.appendMembers(
                        preparing,
                        0,
                        listOf(member),
                        preparing.group.stagingChainDigest,
                        "5".repeat(64),
                    )!!
                val seal = VaultGroupSeal(id, "6".repeat(64), 1, 0, 0)
                val parent =
                    TransferEntity(
                        id,
                        "a",
                        "one",
                        null,
                        "DOWNLOAD",
                        "vault-offline-group:vault",
                        "Vault.vault",
                        "Encrypted offline folder",
                        null,
                        0,
                        offlinePin = true,
                        locationKind = VAULT_GROUP_LOCATION_KIND,
                        createdAtEpochMillis = 1,
                        updatedAtEpochMillis = 1,
                    )
                val queued = groups.sealAndEnqueue(staged, seal, parent) { true }!!
                val waiting = groups.awaitUnlock(groups.claim(queued, UUID.randomUUID().toString(), 2)!!, 3)!!
                val exact =
                    VaultGroupPublication(
                        UUID.randomUUID().toString(),
                        id,
                        owner,
                        descriptor.identityDigest,
                        descriptor.descriptorDigest,
                        seal.digest,
                        1,
                        descriptor.baseOfflineRootDigest,
                        "7".repeat(64),
                    )
                assertTrue(groups.reservePublication(waiting, exact) { true } != null)
                f.service.captureAll("a", f.stages)!!.use { scope ->
                    assertEquals(
                        id,
                        f.service
                            .downloadPage(scope)
                            .single()
                            .id,
                    )
                    assertTrue(f.service.cancelDownload(scope, id) != null)
                    assertEquals("CANCELLED", groups.find(id)!!.group.state)
                    f.store.clearTransferHistory("a")
                    assertEquals(null, f.store.transfer(id))
                    assertEquals(VaultGroupPublicationDecision.REJECTED, groups.publicationDecision(exact))
                    assertTrue(groups.hasUnresolved(owner, id))
                }
            }
        }
    }

    @Test fun cancelledBulkAdmissionRollsBackPinsAndReclaimsOnlyItsOwnedStage() {
        runBlocking {
            fixture { f ->
                val rows = (0 until 390).map { f.row(it.toString().padStart(4, '0')).copy(offlinePinned = true) }
                f.db.resourceDao().insertAll(rows)
                val other = f.service.captureOne(rows.first(), false, f.stages)!!
                val unknown = File(f.stages, "unknown.keep").apply { writeText("unowned") }
                f.stages
                    .listFiles()
                    .orEmpty()
                    .filter { it != unknown }
                    .forEach { assertTrue(it.setLastModified(1)) }
                val entered = CountDownLatch(1)
                val release = CountDownLatch(1)
                val pages = AtomicInteger()
                f.query.set { sql ->
                    if (sql.startsWith("SELECT r.*, CASE WHEN r.hasLocalCopy") && pages.incrementAndGet() == 2) {
                        entered.countDown()
                        check(release.await(10, TimeUnit.SECONDS))
                    }
                }
                val capture = launch(Dispatchers.IO) { f.service.captureAll("a", f.stages)?.close() }
                try {
                    assertTrue(withContext(Dispatchers.IO) { entered.await(5, TimeUnit.SECONDS) })
                    capture.cancel()
                    release.countDown()
                    capture.join()
                    f.query.set {}
                    assertEquals(rows.first(), f.store.resource("a", "one", rows.first().remoteId))
                    assertEquals(rows.last(), f.store.resource("a", "one", rows.last().remoteId))
                    assertEquals(
                        3,
                        f.stages
                            .listFiles()
                            .orEmpty()
                            .size,
                    )
                    assertEquals("unowned", unknown.readText())
                } finally {
                    release.countDown()
                    capture.cancelAndJoin()
                    f.query.set {}
                    other.close()
                }
                assertEquals(
                    listOf(unknown),
                    f.stages
                        .listFiles()
                        .orEmpty()
                        .toList(),
                )
            }
        }
    }

    private suspend fun fixture(action: suspend (Fixture) -> Unit) {
        val f = Fixture(temporary.newFolder())
        try {
            f.seed()
            action(f)
        } finally {
            f.db.close()
        }
    }

    private class Fixture(
        root: File,
    ) {
        private val context = RuntimeEnvironment.getApplication()
        private val source = File(root, "source.db")
        val query = AtomicReference<(String) -> Unit>({})
        val db = open()
        val store = FileBrowserStore(db)
        val service = store.localCopyRemovals()
        val stages = File(root, "stages")
        val account = AccountEntity("a", "https://example.test/", "u", "User", "BASIC", false)

        fun open(): FileBrowserDatabase =
            Room
                .databaseBuilder(context, FileBrowserDatabase::class.java, source.path)
                .setQueryCallback({ sql, _ -> query.get().invoke(sql) }, Executor { it.run() })
                .build()

        suspend fun seed() {
            db.accountDao().upsert(account)
            db.spaceDao().upsertAll(listOf(space("one"), space("two"), space("disabled").copy(isDisabled = true)))
        }

        fun space(id: String) = SpaceEntity("a", id, id, "personal", null, null, "root", null, null, null)

        fun row(
            id: String,
            space: String = "one",
        ) = ResourceEntity(
            "a",
            space,
            id,
            "root",
            "/$id",
            id,
            ResourceKind.FILE,
            "text/plain",
            4,
            "etag",
            1,
            1,
            hasLocalCopy = true,
            localPath = "/private/$space/$id",
        )

        fun transfer(
            id: String,
            row: ResourceEntity,
        ) = TransferEntity(
            id,
            row.accountId,
            row.spaceId,
            row.remoteId,
            "DOWNLOAD",
            null,
            row.path,
            row.name,
            null,
            row.sizeBytes,
            createdAtEpochMillis = 1,
            updatedAtEpochMillis = 1,
            workId = UUID.randomUUID().toString(),
        )

        fun pending(path: String) =
            db.openHelper.writableDatabase.execSQL(
                "INSERT INTO pending_pins(accountId,spaceId,path,attemptedAt) VALUES ('a','one',?,0)",
                arrayOf(path),
            )

        suspend fun operation(
            id: String,
            row: ResourceEntity,
        ): FileOperationEntity {
            val operation =
                FileOperationEntity(
                    id,
                    "a",
                    "one",
                    "one",
                    row.remoteId,
                    "root",
                    "root",
                    "/",
                    "/",
                    row.path,
                    "/moved",
                    "etag",
                    true,
                    sourceFolder = true,
                )
            db.fileOperationDao().insert(operation)
            return operation
        }
    }
}
