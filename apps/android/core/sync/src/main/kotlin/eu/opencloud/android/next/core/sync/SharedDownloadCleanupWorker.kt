package eu.opencloud.android.next.core.sync

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import java.io.IOException
import java.util.concurrent.TimeUnit

/** Local-only cleanup; the writer gate prevents deleting active staging or newly published bytes. */
class SharedDownloadCleanupWorker(
    context: Context,
    parameters: WorkerParameters,
) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result =
        runSharedDownloadCleanup {
            SharedDownloadMaintenance(
                FileBrowserDatabase.create(applicationContext),
                applicationContext.filesDir,
            ).cleanupAll()
        }
}

internal suspend fun runSharedDownloadCleanup(cleanup: suspend () -> Unit): androidx.work.ListenableWorker.Result =
    try {
        cleanup()
        androidx.work.ListenableWorker.Result
            .success()
    } catch (_: IOException) {
        androidx.work.ListenableWorker.Result
            .retry()
    }

internal fun scheduleSharedDownloadCleanup(context: Context): androidx.work.Operation {
    val request =
        OneTimeWorkRequestBuilder<SharedDownloadCleanupWorker>()
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
            .build()
    // Keep a follow-up when discovery finishes during cleanup; KEEP could lose that invalidation.
    return WorkManager.getInstance(context).enqueueUniqueWork(
        "shared-download-cleanup",
        ExistingWorkPolicy.APPEND_OR_REPLACE,
        request,
    )
}
