package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.FolderBackupEntity
import eu.opencloud.android.next.core.network.OpenCloudError
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class BackupScanDiagnosticsTest {
    private val context: Context = RuntimeEnvironment.getApplication()
    private val backup =
        FolderBackupEntity(
            id = "pair",
            accountId = "account",
            spaceId = "space",
            sourceTreeUri = "content://private/source",
            sourceDisplayName = "private source",
            destinationPath = "/private/destination",
            mediaType = "ALL",
            wifiOnly = false,
            chargingOnly = false,
            deleteAfterUpload = false,
        )

    @Before fun clear() {
        context
            .getSharedPreferences("backup-scan-diagnostics", Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()
    }

    @Test fun `failure survives repository recreation without persisting private source details`() {
        BackupScanDiagnostics(context).record(backup, OpenCloudError.SourcePermissionDenied, 100)
        assertEquals(OpenCloudError.SourcePermissionDenied, BackupScanDiagnostics(context).read(backup)?.error)
        val data = context.getSharedPreferences("backup-scan-diagnostics", Context.MODE_PRIVATE).all.toString()
        assertFalse(data.contains("private"))
        assertFalse(data.contains("content://"))
        assertFalse(data.contains("account"))
    }

    @Test fun `configuration edit hides stale failure and cannot clear failure for replacement configuration`() {
        val repository = BackupScanDiagnostics(context)
        repository.record(backup, OpenCloudError.DirectoryListingTooLarge, 100)
        val rebound = backup.copy(sourceTreeUri = "content://new/source", lastSafeScanEpochMillis = 0)
        assertNull(repository.read(rebound))
        repository.record(rebound, OpenCloudError.SourceUnavailable, 200)
        repository.clear(backup, 300)
        assertEquals(OpenCloudError.SourceUnavailable, repository.read(rebound)?.error)
    }

    @Test fun `older scan cannot replace or clear a newer failure`() {
        val repository = BackupScanDiagnostics(context)
        repository.record(backup, OpenCloudError.LocalStorageWriteFailed, 200)
        repository.record(backup, OpenCloudError.Unknown, 100)
        repository.clear(backup, 100)
        assertEquals(OpenCloudError.LocalStorageWriteFailed, repository.read(backup)?.error)
        repository.clear(backup, 200)
        assertNull(repository.read(backup))
    }

    @Test fun `scan cursor preserves failure identity and account deletion clears it`() {
        val repository = BackupScanDiagnostics(context)
        repository.record(backup, OpenCloudError.SourceUnavailable, 100)
        assertEquals(
            OpenCloudError.SourceUnavailable,
            repository.read(backup.copy(lastSafeScanEpochMillis = 50))?.error,
        )
        repository.clearAccount(backup.accountId)
        assertNull(repository.read(backup))
    }

    @Test fun `source rebind preserves receipts only for the same actual document`() {
        val document =
            BackupDocument(android.net.Uri.parse("content://old/document/file"), "file", "", "image/jpeg", 1, 10)
        val rebound = backup.copy(sourceTreeUri = "content://new/source")
        assertEquals(backupReceiptKey(backup, document), backupReceiptKey(rebound, document))
        org.junit.Assert.assertNotEquals(
            backupReceiptKey(backup, document),
            backupReceiptKey(rebound, document.copy(uri = android.net.Uri.parse("content://new/document/file"))),
        )
    }

    @Test fun `arbitrary saved code cannot become user displayed exception text`() {
        assertEquals(OpenCloudError.Unknown, backupScanError("Bearer secret https://private.test"))
        assertEquals(OpenCloudError.Unknown, backupScanError("HTTP_999"))
        assertEquals(OpenCloudError.ServerFailure(502, null), backupScanError("SERVER_502"))
    }
}
