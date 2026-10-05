package eu.opencloud.android.next.core.sync

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters

/** Removes a temporary external-copy export after its bounded handoff window. */
class VaultExternalCopyCleanupWorker(
    context: Context,
    parameters: WorkerParameters,
) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result {
        val id = inputData.getString(KEY_ID) ?: return Result.failure()
        val removed =
            if (id == VaultExternalCopyStore.ROOT_CLEANUP_ID_FOR_WORKER) {
                VaultExternalCopyStore.cleanupStartupFromWorker(applicationContext)
            } else {
                VaultExternalCopyStore.cleanupFromWorker(applicationContext, id)
            }
        return if (removed) Result.success() else Result.retry()
    }

    companion object {
        const val KEY_ID = "lease_id"
    }
}
