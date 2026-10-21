package eu.opencloud.android.next.core.sync

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class BackupInventoryTest {
    private lateinit var database: eu.opencloud.android.next.core.database.FileBrowserDatabase

    @org.junit.Before fun prepare() {
        database = openDatabase()
    }

    @org.junit.After fun close() = database.close()

    private fun openDatabase() =
        androidx.room.Room
            .databaseBuilder(
                RuntimeEnvironment.getApplication(),
                eu.opencloud.android.next.core.database.FileBrowserDatabase::class.java,
                "backup-receipts-test.db",
            ).setJournalMode(androidx.room.RoomDatabase.JournalMode.TRUNCATE)
            .build()

    @Test fun `old dated arrivals and separate folders remain discoverable after receipts persist`() =
        runTest {
            val context = RuntimeEnvironment.getApplication()
            val inventory = BackupInventory(context, "pair", database.backupReceiptDao())
            inventory.queued("camera/a.jpg", "12:100")
            database.close()
            database = openDatabase()
            val reopened = BackupInventory(context, "pair", database.backupReceiptDao())
            assertFalse(reopened.needsUpload("camera/a.jpg", "12:100"))
            assertTrue(reopened.needsUpload("edited/a.jpg", "12:100"))
            assertTrue(reopened.needsUpload("camera/a.jpg", "13:101"))
            assertEquals("/Photos/Camera", backupParent("/Photos/", "Camera"))
            assertEquals("/Photos/Edited", backupParent("/Photos/", "Edited"))
        }

    @Test fun `unknown timestamps need two stable observations and content changes reset stability`() =
        runTest {
            val inventory = BackupInventory(RuntimeEnvironment.getApplication(), "unknown", database.backupReceiptDao())
            assertFalse(inventory.stable("file", "first", 0, 1000))
            assertFalse(inventory.stable("file", "changed", 0, 12000))
            assertFalse(inventory.stable("file", "changed", 0, 15000))
            assertTrue(inventory.stable("file", "changed", 0, 23000))
            assertFalse(inventory.stable("growing", "x", 22000, 23000))
        }

    @Test fun `unknown metadata uses content fingerprint and propagates cancellation`() {
        val first = backupSignature(-1, 0) { "one".byteInputStream() }
        val second = backupSignature(-1, 0) { "two".byteInputStream() }
        assertNotEquals(first, second)
        assertThrows(java.util.concurrent.CancellationException::class.java) {
            backupSignature(-1, 0, { throw java.util.concurrent.CancellationException() }) { "one".byteInputStream() }
        }
    }

    @Test fun `historical transfers do not block changed backup sources but pending uploads do`() {
        val transfer =
            eu.opencloud.android.next.core.database.TransferEntity(
                id = "old",
                accountId = "account",
                spaceId = "space",
                resourceId = null,
                direction = "UPLOAD",
                sourceUri = "content://camera/photo",
                destinationPath = "/Photos/photo.jpg",
                displayName = "photo.jpg",
                mimeType = "image/jpeg",
                bytesTotal = 10,
                createdAtEpochMillis = 0,
                updatedAtEpochMillis = 0,
            )

        fun blocks(item: eu.opencloud.android.next.core.database.TransferEntity) =
            item.blocksBackupScan("space", "content://camera/photo", "/Photos/photo.jpg")
        listOf(
            "SUCCEEDED",
            "FAILED",
            "CANCELLED",
            "CONFLICT",
        ).forEach { assertFalse(blocks(transfer.copy(state = it))) }
        listOf("QUEUED", "RUNNING", "RETRY").forEach { assertTrue(blocks(transfer.copy(state = it))) }
        assertFalse(blocks(transfer.copy(spaceId = "other")))
        assertFalse(blocks(transfer.copy(sourceUri = "content://camera/other")))
        assertFalse(blocks(transfer.copy(destinationPath = "/Elsewhere/photo.jpg")))
        assertFalse(blocks(transfer.copy(direction = "DOWNLOAD")))
    }
}
