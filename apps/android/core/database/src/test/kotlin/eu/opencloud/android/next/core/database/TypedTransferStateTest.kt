package eu.opencloud.android.next.core.database

import androidx.room.Room
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
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
class TypedTransferStateTest {
    private val context = RuntimeEnvironment.getApplication()
    private lateinit var database: FileBrowserDatabase
    private val account = AccountEntity("a", "https://example.test", "u", "User", "BASIC", false)

    @Before fun setUp() =
        runBlocking {
            database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
            database.accountDao().upsert(account)
        }

    @After fun close() = database.close()

    @Test fun exactHistoricalValuesRoundTripAndUnknownCannotBeSerialized() {
        val historical =
            listOf("QUEUED", "RUNNING", "RETRY", "CONFLICT", "AWAITING_UNLOCK", "SUCCEEDED", "FAILED", "CANCELLED")
        assertEquals(
            historical,
            TransferState.entries.filterNot { it == TransferState.UNKNOWN }.map { it.persistedValue },
        )
        historical.forEach { assertEquals(it, TransferState.fromPersisted(it).persistedValue) }
        for (raw in listOf(null, "", "running", " SUCCEEDED", "SUCCEEDED ", "FUTURE", "UNKNOWN")) {
            val state = TransferState.fromPersisted(raw)
            assertEquals(TransferState.UNKNOWN, state)
            assertFalse(state.isRunnable)
            assertFalse(state.isHistory)
            assertFalse(state.allowsExplicitRetry)
            assertTrue(state.requiresAttention)
        }
        assertThrows(IllegalStateException::class.java) { TransferState.UNKNOWN.persistedValue }
    }

    @Test fun pendingSqlAndWorkerClaimsMatchTypedSemanticsWithoutResettingBytes() =
        runBlocking {
            val rows = TransferState.entries.map { row(it.name, it.name) }
            rows.forEach { database.transferDao().insert(it) }
            assertEquals(
                rows
                    .filter {
                        it.typedState.isRunnable
                    }.map { it.id }
                    .toSet(),
                database
                    .transferDao()
                    .findPending()
                    .map { it.id }
                    .toSet(),
            )
            for (row in rows) {
                val claimed = database.transferDao().claim(row.id, "worker", 10)
                if (row.typedState.isRunnable) {
                    assertEquals(TransferState.RUNNING, claimed?.typedState)
                    assertEquals(row.bytesTransferred, claimed?.bytesTransferred)
                    assertEquals(row.verificationPending, claimed?.verificationPending)
                } else {
                    assertNull(claimed)
                    assertEquals(row, database.transferDao().findById(row.id))
                }
            }
        }

    @Test fun unknownRowsRemainVisibleAsAttentionAndCannotBeClaimedRetriedOrCompleted() =
        runBlocking {
            val unknown = row("unknown", "FUTURE_AFTER_NETWORK_WRITE")
            val dao = database.transferDao()
            dao.insert(unknown)
            val page =
                TransferInventory(
                    database,
                ).load("a", TransferInventoryFilter(status = TransferInventoryStatus.Attention))
            assertEquals(listOf(unknown), page.entries)
            assertEquals(TransferInventoryCounts(attention = 1), page.counts)
            assertEquals(1, page.actions.total)
            assertEquals(0, page.actions.uploadRetryCount)
            assertEquals(unknown, TransferInventory(database).overview("a").representative)
            assertNull(dao.claim(unknown.id, "worker", 10))
            assertNull(dao.retry(unknown, unknown.copy(state = "QUEUED")))
            assertFalse(dao.updateActive(unknown.copy(state = "SUCCEEDED")))
            assertEquals(unknown, dao.findById(unknown.id))
            dao.cancel(unknown.id)
            assertEquals(TransferState.CANCELLED, dao.findById(unknown.id)?.typedState)
        }

    @Test fun cancellationAndWorkerReplacementStillRejectLateProgressAndCompletion() =
        runBlocking {
            val dao = database.transferDao()
            dao.insert(row("cancel", "RUNNING").copy(workId = "old"))
            val old = requireNotNull(dao.findById("cancel"))
            dao.cancel(old.id)
            assertEquals(0, dao.updateProgress(old.id, old.workId, 99, 20))
            assertFalse(dao.updateActive(old.copy(state = "SUCCEEDED")))
            val cancelled = requireNotNull(dao.findById(old.id))
            val retry = cancelled.copy(state = "QUEUED", workId = "new")
            assertEquals(retry, dao.retry(cancelled, retry))
            assertNull(dao.retry(cancelled, retry.copy(workId = "other")))
            assertNull(dao.claim(old.id, "old", 30))
            assertFalse(dao.updateActive(old.copy(state = "FAILED")))
            assertEquals(retry, dao.findById(old.id))
        }

    @Test fun conflictsNeedExplicitResolutionAndAwaitingUnlockNeverJoinsWorkerRecovery() =
        runBlocking {
            val dao = database.transferDao()
            val conflict = row("conflict", "CONFLICT")
            val awaiting = row("awaiting", "AWAITING_UNLOCK").copy(direction = "DOWNLOAD", locationKind = "VAULT")
            dao.insert(conflict)
            dao.insert(awaiting)
            assertTrue(awaiting.typedState.isActive)
            assertFalse(awaiting.typedState.isRunnable)
            assertTrue(dao.findPendingPage("", 256).isEmpty())
            assertNull(dao.retry(awaiting, awaiting.copy(state = "QUEUED")))
            assertFalse(conflict.typedState.allowsRetryWithoutConflictDecision)
            val resolved = conflict.copy(state = "QUEUED", destinationPath = "/renamed")
            assertEquals(resolved, dao.retry(conflict, resolved))
            assertNull(dao.retry(conflict, resolved.copy(destinationPath = "/other")))
            assertEquals(awaiting, dao.findById(awaiting.id))
        }

    @Test fun reopenPreservesRawStatesAndPendingRemovalDoesNotAdmitTheirInventory() =
        runBlocking {
            val name = "typed-transfers-${UUID.randomUUID()}.db"

            fun open() = Room.databaseBuilder(context, FileBrowserDatabase::class.java, name).build()
            var persisted = open()
            val rows =
                listOf(row("interrupted", "RUNNING"), row("waiting", "AWAITING_UNLOCK"), row("corrupt", "future"))
            try {
                persisted.accountDao().upsert(account)
                rows.forEach { persisted.transferDao().insert(it) }
                persisted.close()
                persisted = open()
                rows.forEach { assertEquals(it, persisted.transferDao().findById(it.id)) }
                assertEquals(listOf("interrupted"), persisted.transferDao().findPendingPage("", 256).map { it.id })
                persisted.accountDao().upsert(account.copy(isActive = false, removalPending = true))
                assertFalse(TransferInventory(persisted).load("a").accessible)
                assertNull(FileBrowserStore(persisted).claimTransfer("interrupted", "worker", 50))
                assertEquals(rows.first(), persisted.transferDao().findById("interrupted"))
            } finally {
                persisted.close()
                context.deleteDatabase(name)
            }
        }

    private fun row(
        id: String,
        state: String,
    ) = TransferEntity(
        id = id,
        accountId = "a",
        spaceId = "s",
        resourceId = null,
        direction = "UPLOAD",
        sourceUri = null,
        destinationPath = "/$id",
        displayName = id,
        mimeType = null,
        bytesTotal = 100,
        bytesTransferred = 41,
        state = state,
        verificationPending = true,
        createdAtEpochMillis = 0,
        updatedAtEpochMillis = 0,
    )
}
