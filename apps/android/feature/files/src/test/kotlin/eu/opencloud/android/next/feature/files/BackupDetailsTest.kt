package eu.opencloud.android.next.feature.files

import eu.opencloud.android.next.core.database.FolderBackupEntity
import org.junit.Assert.assertEquals
import org.junit.Test

class BackupDetailsTest {
    @Test
    fun `backup details include destination type and active constraints`() {
        val backup =
            FolderBackupEntity(
                id = "backup",
                accountId = "account",
                spaceId = "personal",
                sourceTreeUri = "content://provider/tree/primary%3ADCIM",
                sourceDisplayName = "DCIM",
                destinationPath = "/Camera Uploads",
                mediaType = "IMAGE",
                wifiOnly = true,
                chargingOnly = true,
                deleteAfterUpload = false,
            )

        assertEquals("Photos • Wi-Fi only • Charging", backupDetails(backup))
    }

    @Test
    fun `backup details show unrestricted all files configuration`() {
        val backup =
            FolderBackupEntity(
                id = "backup",
                accountId = "account",
                spaceId = "personal",
                sourceTreeUri = "content://provider/tree/primary%3APictures",
                destinationPath = "/Pictures",
                mediaType = "ALL",
                wifiOnly = false,
                chargingOnly = false,
                deleteAfterUpload = false,
            )

        assertEquals("All files • No restrictions", backupDetails(backup))
    }
}
