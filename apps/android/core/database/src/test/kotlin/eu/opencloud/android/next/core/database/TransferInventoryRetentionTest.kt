package eu.opencloud.android.next.core.database

import androidx.room.Room
import androidx.room.withTransaction
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class TransferInventoryRetentionTest {
    private lateinit var database: FileBrowserDatabase
    private lateinit var inventory: TransferInventory
    private val account = AccountEntity("a", "https://example.test", "user", "User", "BASIC", false)

    @Before fun setUp() =
        runBlocking {
            database =
                Room
                    .inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), FileBrowserDatabase::class.java)
                    .allowMainThreadQueries()
                    .build()
            inventory = TransferInventory(database)
            database.accountDao().upsert(account)
            database.accountDao().upsert(account.copy(id = "other"))
        }

    @After fun close() = database.close()

    @Test fun hundredThousandRetainedRowsDoNotChangeBoundedOverviewOrWindowSemantics() =
        runBlocking {
            val backup =
                FolderBackupEntity(
                    "backup",
                    "a",
                    "space",
                    "content://tree_%",
                    destinationPath = "/Backup_%",
                    mediaType = "IMAGE",
                    wifiOnly = false,
                    chargingOnly = false,
                    deleteAfterUpload = false,
                )
            database.folderBackupDao().upsert(backup)
            database.withTransaction {
                repeat(
                    100_000,
                ) { index -> database.transferDao().insert(row("history-$index", "SUCCEEDED", index.toLong())) }
                database.transferDao().insert(row("awaiting", "AWAITING_UNLOCK", 200_000).copy(locationKind = "VAULT"))
                database.transferDao().insert(row("running", "RUNNING", 5))
                database.transferDao().insert(row("conflict", "CONFLICT", 300_000))
                database.transferDao().insert(row("failed", "FAILED", 300_001))
                database.transferDao().insert(row("other-running", "RUNNING", 999_999).copy(accountId = "other"))
                database.transferDao().insert(
                    row("backup-pending", "QUEUED", 1).copy(
                        sourceUri = "content://tree_%/document/photo",
                        destinationPath = "/Backup_%/photo",
                    ),
                )
                database.transferDao().insert(
                    row("backup-done", "SUCCEEDED", 2).copy(
                        sourceUri = "content://tree_%/document/done",
                        destinationPath = "/Backup_%/done",
                        updatedAtEpochMillis = 900_000,
                    ),
                )
                database.transferDao().insert(
                    row("prefix-impostor", "FAILED", 3).copy(
                        sourceUri = "content://treeXX/document/other",
                        destinationPath = "/Backup_XX/other",
                    ),
                )
            }
            val overview = inventory.overview("a")
            assertEquals("running", overview.representative?.id)
            assertEquals("conflict", overview.uploadConflict?.id)
            assertEquals(1, overview.uploadConflictCount)
            assertEquals(setOf("backup"), overview.backupStats.keys)
            assertEquals(
                BackupTransferStats(pending = 1, attention = 0, lastCompleted = 900_000),
                overview.backupStats["backup"],
            )
            val first = inventory.load("a")
            assertEquals(100_007, first.total)
            assertEquals(128, first.entries.size)
            assertEquals(3, first.counts.active)
            assertEquals(3, first.counts.attention)
            assertEquals(100_001, first.counts.history)
            assertEquals(first.total, first.actions.total)
            val middle = inventory.load("a", requestedOffset = 50_048)
            assertEquals(first.counts, middle.counts)
            assertEquals(first.actions, middle.actions)
            assertEquals(128, middle.entries.size)
            assertTrue(middle.entries.all { it.accountId == "a" && it.state == "SUCCEEDED" })
            assertTrue(middle.entries.none { it.id in first.entries.map(TransferEntity::id) })
            database.accountDao().upsert(account.copy(isActive = false))
            assertFalse(inventory.load("a").accessible)
            assertNull(inventory.overview("a").representative)
            assertTrue(inventory.overview("a").backupStats.isEmpty())
        }

    @Test fun bulkScopeIncludesWholeHistoryButExcludesLaterBackdatedRowsAndPreservesAwaitingVerification() =
        runBlocking {
            database.withTransaction {
                repeat(400) { index ->
                    database.transferDao().insert(
                        row(
                            "old-$index",
                            if (index % 2 ==
                                0
                            ) {
                                "SUCCEEDED"
                            } else {
                                "CANCELLED"
                            },
                            100,
                        ),
                    )
                }
                database.transferDao().insert(row("awaiting", "AWAITING_UNLOCK", 100).copy(locationKind = "VAULT"))
                database.transferDao().insert(row("active", "RUNNING", 100))
                database.transferDao().insert(row("other", "SUCCEEDED", 100).copy(accountId = "other"))
            }
            val scope = requireNotNull(inventory.captureScope("a"))
            database.transferDao().insert(row("000-new-backdated", "SUCCEEDED", 1))
            val seen = mutableSetOf<String>()
            var after: String? = null
            while (true) {
                val page = inventory.bulkPage(scope, after, TransferBulkKind.History)
                if (page.isEmpty()) break
                assertTrue(page.size <= 128)
                page.forEach { assertTrue(seen.add(it.id)) }
                after = page.last().id
            }
            assertEquals((0 until 400).map { "old-$it" }.toSet(), seen)
            assertEquals(400, inventory.deleteScopedHistory(scope))
            assertEquals("SUCCEEDED", database.transferDao().findById("000-new-backdated")?.state)
            assertEquals("AWAITING_UNLOCK", database.transferDao().findById("awaiting")?.state)
            assertEquals("RUNNING", database.transferDao().findById("active")?.state)
            assertEquals("SUCCEEDED", database.transferDao().findById("other")?.state)
        }

    @Test fun replacingAccountInvalidatesAnOldBulkScope() =
        runBlocking {
            database.transferDao().insert(row("history", "SUCCEEDED", 1))
            val scope = requireNotNull(inventory.captureScope("a"))
            database.accountDao().upsert(account.copy(serverUrl = "https://changed.example.test"))
            assertThrows(IllegalStateException::class.java) {
                runBlocking { inventory.bulkPage(scope, kind = TransferBulkKind.History) }
            }
            assertThrows(IllegalStateException::class.java) {
                runBlocking { inventory.deleteScopedHistory(scope) }
            }
            assertEquals("SUCCEEDED", database.transferDao().findById("history")?.state)
        }

    @Test fun manualRetryCreatesANewQueueIntentOutsideAnAlreadyCapturedClearScope() =
        runBlocking {
            val original = row("same-id", "CANCELLED", 100).copy(workId = "old-worker")
            database.transferDao().insert(original)
            val scope = requireNotNull(inventory.captureScope("a"))
            assertEquals(listOf("same-id"), inventory.bulkPage(scope).map { it.id })
            val replacement = original.copy(state = "QUEUED", workId = "new-worker", updatedAtEpochMillis = 101)
            assertEquals(replacement, database.transferDao().retry(original, replacement))
            assertNull(inventory.cancelForClear(scope, original.id))
            assertEquals(0, inventory.deleteScopedHistory(scope))
            assertEquals(replacement, database.transferDao().findById(original.id))
        }

    @Test fun removingAndReaddingIdenticalAccountCannotReviveAnOldBulkScope() =
        runBlocking {
            database.transferDao().insert(row("before-removal", "SUCCEEDED", 100))
            val scope = requireNotNull(inventory.captureScope("a"))
            FileBrowserStore(database).removeAccount(account.id)
            database.accountDao().upsert(account)
            val fresh = row("000-fresh", "CANCELLED", 1).copy(workId = "fresh-worker")
            database.transferDao().insert(fresh)
            assertEquals(account, database.accountDao().findById(account.id))
            assertThrows(IllegalStateException::class.java) { runBlocking { inventory.bulkPage(scope) } }
            assertThrows(IllegalStateException::class.java) {
                runBlocking { inventory.cancelForClear(scope, fresh.id) }
            }
            assertThrows(IllegalStateException::class.java) { runBlocking { inventory.deleteScopedHistory(scope) } }
            assertEquals(fresh, database.transferDao().findById(fresh.id))
            val current = requireNotNull(inventory.captureScope("a"))
            assertEquals(listOf(fresh.id), inventory.bulkPage(current).map { it.id })
        }

    @Test fun scopedRetryRejectsRetainedPageAfterIdenticalAccountAndRowAreRecreated() =
        runBlocking {
            val original = row("same-row", "FAILED", 1).copy(workId = "old-worker", errorCode = "CONNECTIVITY")
            database.transferDao().insert(original)
            val scope = requireNotNull(inventory.captureScope(account.id))
            val retained = inventory.bulkPage(scope, kind = TransferBulkKind.RetryUploads).single()
            FileBrowserStore(database).removeAccount(account.id)
            database.accountDao().upsert(account)
            database.transferDao().insert(original)
            assertEquals(retained, database.transferDao().findById(original.id))
            val newSequence = queueSequence(original.id)
            assertTrue(newSequence > scope.watermark)
            val replacement = retained.copy(state = "QUEUED", workId = "stale-bulk-worker", errorCode = null)
            assertNull(inventory.retryScoped(scope, retained, replacement))
            assertEquals(original, database.transferDao().findById(original.id))
            assertEquals(newSequence, queueSequence(original.id))
            val current = requireNotNull(inventory.captureScope(account.id))
            assertEquals(replacement, inventory.retryScoped(current, original, replacement))
            assertTrue(queueSequence(original.id) > newSequence)
        }

    @Test fun scopedRetryAdmitsOneExactIntentAndDoesNotReadmitANewerQueueGeneration() =
        runBlocking {
            val original = row("retry", "FAILED", 100).copy(workId = "old-worker", errorCode = "CONNECTIVITY")
            database.transferDao().insert(original)
            val scope = requireNotNull(inventory.captureScope(account.id))
            val replacement = original.copy(state = "QUEUED", workId = "accepted-worker", errorCode = null)
            assertEquals(replacement, inventory.retryScoped(scope, original, replacement))
            val admittedSequence = queueSequence(original.id)
            assertTrue(admittedSequence > scope.watermark)
            val failedAgain = replacement.copy(state = "FAILED", updatedAtEpochMillis = 101)
            database.transferDao().update(failedAgain)
            val unwanted = failedAgain.copy(state = "QUEUED", workId = "duplicate-worker")
            assertNull(inventory.retryScoped(scope, failedAgain, unwanted))
            assertEquals(failedAgain, database.transferDao().findById(original.id))
            assertEquals(admittedSequence, queueSequence(original.id))
        }

    @Test fun scopedRetryRejectsChangedRowsAndMismatchedReplacementAccountsWithoutAdmission() =
        runBlocking {
            val original = row("changed", "FAILED", 100).copy(workId = "old-worker")
            database.transferDao().insert(original)
            val scope = requireNotNull(inventory.captureScope(account.id))
            val sequence = queueSequence(original.id)
            val replacement = original.copy(state = "QUEUED", workId = "unwanted-worker")
            assertThrows(IllegalArgumentException::class.java) {
                runBlocking { inventory.retryScoped(scope, original, replacement.copy(accountId = "other")) }
            }
            val changed = original.copy(workId = "changed-worker", updatedAtEpochMillis = 101)
            database.transferDao().update(changed)
            assertNull(inventory.retryScoped(scope, original, replacement))
            assertEquals(changed, database.transferDao().findById(original.id))
            assertEquals(sequence, queueSequence(original.id))
        }

    private fun queueSequence(id: String): Long =
        database.openHelper.readableDatabase
            .query(
                "SELECT sequence FROM transfer_queue WHERE transferId = ?",
                arrayOf(id),
            ).use { cursor ->
                check(cursor.moveToFirst())
                cursor.getLong(0)
            }

    private fun row(
        id: String,
        state: String,
        created: Long,
    ) = TransferEntity(
        id = id,
        accountId = "a",
        spaceId = "space",
        resourceId = null,
        direction = "UPLOAD",
        sourceUri = null,
        destinationPath = "/$id",
        displayName = "$id.txt",
        mimeType = "text/plain",
        bytesTotal = 10,
        state = state,
        createdAtEpochMillis = created,
        updatedAtEpochMillis = created,
    )
}
