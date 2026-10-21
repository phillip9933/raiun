package eu.opencloud.android.next.core.sync

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.util.concurrent.TimeUnit

class ExcludedCacheCleanupWorker(
    context: Context,
    parameters: WorkerParameters,
) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result =
        withContext(Dispatchers.IO) {
            try {
                val database = FileBrowserDatabase.create(applicationContext)
                reclaimExcludedCache(database, applicationContext.filesDir)
                if (database.excludedCacheDao().pending().isEmpty()) Result.success() else Result.retry()
            } catch (_: IOException) {
                Result.retry()
            }
        }
}

internal fun scheduleExcludedCacheCleanup(context: Context): androidx.work.Operation =
    WorkManager.getInstance(context).enqueueUniqueWork(
        "excluded-cache-cleanup",
        ExistingWorkPolicy.APPEND_OR_REPLACE,
        OneTimeWorkRequestBuilder<ExcludedCacheCleanupWorker>()
            .setBackoffCriteria(BackoffPolicy.LINEAR, 30, TimeUnit.SECONDS)
            .build(),
    )

internal suspend fun schedulePendingExcludedCache(context: Context) {
    if (FileBrowserDatabase
            .create(context)
            .excludedCacheDao()
            .pending()
            .isNotEmpty()
    ) {
        scheduleExcludedCacheCleanup(context)
    }
}
