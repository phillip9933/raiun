package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.model.cacheIdentity
import java.io.File

/** Call after cancelling work and removing the account's durable intents. */
suspend fun clearAccountPrivateFiles(
    context: Context,
    accountId: String,
) {
    SharedDownloadFiles.clearAccount(context.filesDir, accountId)
    val key = cacheIdentity(accountId)
    val directories =
        listOf(
            File(context.filesDir, "resources-v2/$key"),
            File(context.noBackupFilesDir, "upload-sources/$key"),
            File(context.noBackupFilesDir, "text-drafts/$key"),
            File(context.noBackupFilesDir, "document-edits/$key"),
        )
    DocumentEditStore(context).coordinateAccountRemoval {
        directories.forEach { directory ->
            check(
                !directory.exists() || directory.deleteRecursively(),
            ) { "Some local account files could not be removed." }
        }
    }
    BackupScanDiagnostics(context).clearAccount(accountId)
    ScanUploadStore(context).clearAccount(accountId)
}
