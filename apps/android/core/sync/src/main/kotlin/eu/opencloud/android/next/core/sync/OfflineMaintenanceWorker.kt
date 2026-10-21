package eu.opencloud.android.next.core.sync

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.OfflineTraversalStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

internal data class OfflineMaintenanceCursor(
    val account: String?,
    val space: String?,
    val resource: String?,
)

/** Each page returns a continuation key, never an in-memory list of every selected root/run. */
internal class OfflineMaintenance(
    private val queue: OfflineTraversalStore,
    private val schedule: suspend (String) -> Unit,
) {
    suspend fun discover(cursor: OfflineMaintenanceCursor): OfflineMaintenanceCursor? {
        val page = queue.dao.pinnedRootPage(cursor.account, cursor.space, cursor.resource)
        page.forEach { root ->
            currentCoroutineContext().ensureActive()
            queue.startIfSelected(root)?.let { schedule(it.id) }
        }
        return page.lastOrNull()?.takeIf { page.size == 32 }?.let {
            OfflineMaintenanceCursor(it.accountId, it.spaceId, it.remoteId)
        }
    }

    suspend fun recover(after: String?): String? {
        val page = queue.dao.activePage(after)
        page.forEach { run ->
            currentCoroutineContext().ensureActive()
            queue.reconcile(run.id)?.let { schedule(it.id) }
        }
        return page.lastOrNull()?.id?.takeIf { page.size == 32 }
    }
}

class OfflineMaintenanceWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result =
        withContext(Dispatchers.IO) {
            val queue = OfflineTraversalStore(FileBrowserDatabase.create(applicationContext))
            val maintenance = OfflineMaintenance(queue) { scheduleOfflineTraversal(applicationContext, it) }
            val recovery = inputData.getBoolean("recovery", false)
            val next =
                if (recovery) {
                    maintenance
                        .recover(
                            inputData.getString("afterResource"),
                        )?.let { OfflineMaintenanceCursor(null, null, it) }
                } else {
                    maintenance.discover(
                        OfflineMaintenanceCursor(
                            inputData.getString("afterAccount"),
                            inputData.getString("afterSpace"),
                            inputData.getString("afterResource"),
                        ),
                    )
                }
            next?.let { scheduleOfflineMaintenance(applicationContext, recovery, it) }
            Result.success()
        }
}

internal fun scheduleOfflineMaintenance(
    context: Context,
    recovery: Boolean = false,
    cursor: OfflineMaintenanceCursor? = null,
) {
    val request =
        OneTimeWorkRequestBuilder<OfflineMaintenanceWorker>()
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.NOT_REQUIRED).build())
            .setInputData(
                workDataOf(
                    "recovery" to recovery,
                    "afterAccount" to cursor?.account,
                    "afterSpace" to cursor?.space,
                    "afterResource" to cursor?.resource,
                ),
            ).build()
    WorkManager
        .getInstance(context)
        .enqueueUniqueWork(
            "offline-maintenance-$recovery",
            if (cursor == null) ExistingWorkPolicy.KEEP else ExistingWorkPolicy.APPEND_OR_REPLACE,
            request,
        ).result
        .get()
}
