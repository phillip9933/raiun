package eu.opencloud.android.next.core.database

import androidx.room.Room
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
class BulkUploadConflictCancellationTest {
    private val context = RuntimeEnvironment.getApplication()
    private lateinit var database: FileBrowserDatabase
    private lateinit var store: FileBrowserStore

    private val conflict =
        TransferEntity(
            id = "conflict",
            accountId = "account",
            spaceId = "space",
            resourceId = null,
            direction = "UPLOAD",
            sourceUri = "content://local/file",
            destinationPath = "/file",
            displayName = "file",
            mimeType = null,
            bytesTotal = 10,
            state = "CONFLICT",
            error = "A file already exists",
            errorCode = "CONFLICT",
            attemptCount = 3,
            notBeforeEpochMillis = 123,
            createdAtEpochMillis = 1,
            updatedAtEpochMillis = 2,
        )

    @Before fun setUp() {
        database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
        store = FileBrowserStore(database)
    }

    @After fun tearDown() = database.close()

    @Test fun `bulk cancellation changes only current account upload conflicts and preserves receipts`() =
        runTest {
            val shared = conflict.copy(id = "shared", locationKind = "SHARED_FOLDER")
            val vault = conflict.copy(id = "vault", locationKind = "VAULT")
            val unaffected =
                listOf(
                    conflict.copy(id = "other-account", accountId = "other"),
                    conflict.copy(id = "download", direction = "DOWNLOAD"),
                    conflict.copy(id = "queued", state = "QUEUED"),
                    conflict.copy(id = "running", state = "RUNNING"),
                    conflict.copy(id = "retry", state = "RETRY"),
                    conflict.copy(id = "failed", state = "FAILED"),
                    conflict.copy(id = "succeeded", state = "SUCCEEDED"),
                )
            (listOf(conflict, shared, vault) + unaffected).forEach { store.createTransfer(it) }
            val receipt = BackupReceipt("backup", "content://local/file", acceptedSignature = "signature")
            database.backupReceiptDao().save(receipt)

            assertEquals(3, store.cancelUploadConflicts("account", 500))
            listOf(conflict, shared, vault).forEach { original ->
                val cancelled = requireNotNull(store.transfer(original.id))
                assertEquals(
                    original.copy(
                        state = "CANCELLED",
                        error = null,
                        errorCode = null,
                        notBeforeEpochMillis = 0,
                        attemptCount = 0,
                        updatedAtEpochMillis = 500,
                    ),
                    cancelled,
                )
            }
            unaffected.forEach { original -> assertEquals(original, store.transfer(original.id)) }
            assertEquals(receipt, database.backupReceiptDao().find(receipt.pairId, receipt.sourceKey))
            assertEquals(0, store.cancelUploadConflicts("account", 600))
        }

    @Test fun `resolved conflict cannot be overwritten by an earlier conflict snapshot`() =
        runTest {
            store.createTransfer(conflict)
            val earlierSnapshot = requireNotNull(store.transfer(conflict.id))
            val resolved = earlierSnapshot.copy(state = "QUEUED", workId = "new-worker", updatedAtEpochMillis = 100)
            store.updateTransfer(resolved)

            assertEquals(0, store.cancelUploadConflicts(earlierSnapshot.accountId, 200))
            assertEquals(resolved, store.transfer(conflict.id))
        }

    @Test fun `cancellation survives closing and reopening the database`() =
        runTest {
            val name = "bulk-upload-conflicts-${UUID.randomUUID()}.db"
            val persisted = Room.databaseBuilder(context, FileBrowserDatabase::class.java, name).build()
            try {
                val persistedStore = FileBrowserStore(persisted)
                persistedStore.createTransfer(conflict)
                assertEquals(1, persistedStore.cancelUploadConflicts("account", 500))
            } finally {
                persisted.close()
            }

            val reopened = Room.databaseBuilder(context, FileBrowserDatabase::class.java, name).build()
            try {
                val cancelled = requireNotNull(FileBrowserStore(reopened).transfer(conflict.id))
                assertEquals("CANCELLED", cancelled.state)
                assertEquals(500L, cancelled.updatedAtEpochMillis)
                assertNull(cancelled.error)
                assertNull(cancelled.errorCode)
            } finally {
                reopened.close()
                context.deleteDatabase(name)
            }
        }
}
