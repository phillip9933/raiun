package eu.opencloud.android.next.core.sync

import android.net.Uri
import eu.opencloud.android.next.core.database.FolderBackupEntity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.time.Instant
import java.time.ZoneOffset

@RunWith(RobolectricTestRunner::class)
class BackupOrganizationTest {
    private val backup =
        FolderBackupEntity(
            "pair",
            "account",
            "space",
            "content://source/tree/root",
            destinationPath = "/Photos",
            mediaType = "ALL",
            wifiOnly = false,
            chargingOnly = false,
            deleteAfterUpload = false,
        )
    private val document =
        BackupDocument(
            Uri.parse("content://source/file"),
            "picture.jpg",
            "Camera",
            "image/jpeg",
            Instant.parse("2026-09-29T23:59:59Z").toEpochMilli(),
            10,
        )

    @Test fun `date organization preserves subfolders and handles absent timestamps explicitly`() {
        assertEquals("/Photos/Camera", backupDestination(backup, document))
        val dated = backup.copy(dateOrganization = "YEAR_MONTH")
        assertEquals("/Photos/2026/09/Camera", backupDestination(dated, document))
        assertEquals("/Photos/Undated/Camera", backupDestination(dated, document.copy(modified = 0)))
    }

    @Test fun `changing destination or organization does not reuse receipts from the old target`() {
        val key = backupReceiptKey(backup, document)
        assertNotEquals(key, backupReceiptKey(backup.copy(destinationPath = "/Other"), document))
        assertNotEquals(key, backupReceiptKey(backup.copy(dateOrganization = "YEAR_MONTH"), document))
        assertNotEquals(key, backupReceiptKey(backup, document.copy(relativeParent = "Edited")))
        assertEquals(key, backupReceiptKey(backup.copy(spaceId = "other"), document))
        assertNotEquals(key, backupReceiptKey(backup.copy(spaceId = "other", destinationRevision = 1), document))
    }

    @Test fun `date templates support reordered tokens and nested folders`() {
        val timestamp = Instant.parse("2026-09-29T23:59:59Z").toEpochMilli()
        assertEquals("29/September/26", formatBackupDateFolder("[DD]/[MMMM]/[YY]", timestamp, ZoneOffset.UTC))
        assertEquals("29 of September", formatBackupDateFolder("[DD] of [MMMM]", timestamp, ZoneOffset.UTC))
        val localPath = requireNotNull(formatBackupDateFolder("[DD]/[MMMM]", timestamp))
        assertEquals(
            "/Photos/$localPath/Camera",
            backupDestination(backup.copy(dateOrganization = "[DD]/[MMMM]"), document, timestamp),
        )
    }

    @Test fun `invalid date templates and unsafe source paths are rejected`() {
        val timestamp = Instant.parse("2026-09-29T23:59:59Z").toEpochMilli()
        assertNull(formatBackupDateFolder("../[YYYY]", timestamp))
        assertNull(formatBackupDateFolder("[YYYY]//[MM]", timestamp))
        assertNull(formatBackupDateFolder("[UNKNOWN]", timestamp))
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
            backupDestination(backup, document.copy(relativeParent = "Camera//Edited"))
        }
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
            backupDestination(backup, document.copy(relativeParent = "../escape"))
        }
    }

    @Test fun `provider added and taken dates use their documented time units`() {
        assertEquals(1_790_687_999_000L, normalizeDateAddedSeconds(1_790_687_999L))
        assertEquals(1_790_687_999_000L, normalizeDateTakenMillis(1_790_687_999_000L))
        assertNull(normalizeDateAddedSeconds(0L))
        assertNull(normalizeDateTakenMillis(0L))
    }
}
