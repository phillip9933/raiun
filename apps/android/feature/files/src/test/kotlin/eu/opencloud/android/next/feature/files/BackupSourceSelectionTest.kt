package eu.opencloud.android.next.feature.files

import eu.opencloud.android.next.core.database.FolderBackupEntity
import org.junit.Assert.assertEquals
import org.junit.Test

class BackupSourceSelectionTest {
    @Test fun `reselecting source retains backup identity and destination while resetting completed scan`() {
        val backup =
            FolderBackupEntity(
                id = "pair",
                accountId = "account",
                spaceId = "space",
                sourceTreeUri = "content://old/source",
                sourceDisplayName = "old",
                destinationPath = "/uploads",
                mediaType = "ALL",
                wifiOnly = true,
                chargingOnly = false,
                deleteAfterUpload = false,
                lastSafeScanEpochMillis = 100,
            )
        val rebound = backupSourceSelection(backup, "content://new/source", "new")
        assertEquals("content://new/source", rebound.sourceTreeUri)
        assertEquals("new", rebound.sourceDisplayName)
        assertEquals(0L, rebound.lastSafeScanEpochMillis)
        assertEquals(
            backup,
            rebound.copy(
                sourceTreeUri = backup.sourceTreeUri,
                sourceDisplayName = backup.sourceDisplayName,
                lastSafeScanEpochMillis = backup.lastSafeScanEpochMillis,
            ),
        )
        assertEquals(backup, backupSourceSelection(backup, null, null))
    }

    @Test fun `delayed source response identity rejects configuration changes but permits scan progress`() {
        val backup =
            FolderBackupEntity(
                id = "pair",
                accountId = "account",
                spaceId = "space",
                sourceTreeUri = "content://old/source",
                destinationPath = "/uploads",
                mediaType = "ALL",
                wifiOnly = true,
                chargingOnly = false,
                deleteAfterUpload = false,
            )
        val expected = backupSourceSelectionFingerprint(backup)
        assertEquals(expected, backupSourceSelectionFingerprint(backup.copy(lastSafeScanEpochMillis = 500)))
        org.junit.Assert.assertNotEquals(
            expected,
            backupSourceSelectionFingerprint(backup.copy(sourceTreeUri = "content://changed")),
        )
        org.junit.Assert.assertNotEquals(
            expected,
            backupSourceSelectionFingerprint(backup.copy(destinationPath = "/new")),
        )
        org.junit.Assert.assertNotEquals(expected, backupSourceSelectionFingerprint(backup.copy(id = "replacement")))
    }
}
