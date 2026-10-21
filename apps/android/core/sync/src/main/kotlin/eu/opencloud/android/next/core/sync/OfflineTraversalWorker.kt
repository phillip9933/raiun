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
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.OfflineTraversalStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.RemoteDiscoveryClient
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.security.TlsPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient

/** Small resumable passes; no recursive Kotlin stack and no full-tree in-memory queue. */
internal class OfflineTraversal(
    private val queue: OfflineTraversalStore,
    private val files: FileBrowserStore,
    private val refresh: suspend (ResourceEntity) -> Unit,
    private val download: suspend (ResourceEntity) -> Unit,
    private val elapsedMillis: () -> Long = { System.nanoTime() / 1_000_000 },
) {
    @Suppress("ReturnCount") // Stop immediately on cancelled/missing runs or a drained queue.
    suspend fun step(
        runId: String,
        budget: Int = 32,
    ): Boolean {
        require(budget in 1..128)
        val started = elapsedMillis()
        val run = queue.dao.run(runId)?.takeIf { it.state == "ACTIVE" } ?: return false
        val root = files.resource(run.accountId, run.spaceId, run.rootId)
        if (root?.offlinePinned != true) {
            queue.dao.finish(runId, "CANCELLED")
            return false
        }
        repeat(budget) {
            currentCoroutineContext().ensureActive()
            if (queue.dao.run(runId)?.state != "ACTIVE") return false
            if (elapsedMillis() - started >= 20_000) return true
            val node = queue.dao.next(runId)
            if (node == null) {
                queue.dao.finish(runId, "COMPLETE")
                return false
            }
            val resource = files.resource(run.accountId, run.spaceId, node.resourceId)
            when {
                resource == null -> queue.dao.updateNode(node.copy(state = "DONE"))
                resource.kind == ResourceKind.FILE -> {
                    if (queue.dao.run(runId)?.state != "ACTIVE") return false
                    download(resource)
                    queue.dao.updateNode(node.copy(state = "DONE"))
                }
                node.state == "PENDING" -> {
                    refresh(resource)
                    currentCoroutineContext().ensureActive()
                    if (queue.dao.run(runId)?.state != "ACTIVE") return false
                    queue.dao.updateNode(node.copy(state = "DISCOVERED"))
                }
                else -> queue.expand(run, node)
            }
        }
        return true
    }
}

class OfflineTraversalWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {
    @Suppress("TooGenericExceptionCaught") // Worker boundary uses the shared safe error/cancellation contract.
    override suspend fun doWork(): Result =
        withContext(Dispatchers.IO) {
            val id = inputData.getString(RUN_ID) ?: return@withContext Result.failure()
            val database = FileBrowserDatabase.create(applicationContext)
            val queue = OfflineTraversalStore(database)
            val store = FileBrowserStore(database)
            try {
                val manager = TransferManager(applicationContext, store)
                val traversal =
                    OfflineTraversal(queue, store, { resource ->
                        val account = requireNotNull(store.account(resource.accountId))
                        val space = requireNotNull(store.space(resource.accountId, resource.spaceId))
                        val client = TlsPolicy(applicationContext).applyTo(OkHttpClient(), account.serverUrl)
                        refreshFolder(
                            FolderRefresh(
                                store,
                                RemoteDiscoveryClient(client),
                                account.id,
                                space,
                                resource.remoteId,
                                resource.path,
                                WorkerAuthorizationProvider(applicationContext).authorization(account),
                            ),
                        )
                        schedulePendingExcludedCache(applicationContext)
                    }, { manager.ensureOfflineDownload(it) })
                if (traversal.step(id)) scheduleOfflineTraversal(applicationContext, id, continuation = true)
                Result.success()
            } catch (failure: Exception) {
                val error = failure.toOpenCloudError()
                if (error in setOf(OpenCloudError.Connectivity, OpenCloudError.PreconditionFailed) &&
                    runAttemptCount < 3
                ) {
                    Result.retry()
                } else {
                    queue.dao.finish(id, "FAILED", error.diagnosticCode())
                    Result.failure(workDataOf("errorCode" to error.diagnosticCode()))
                }
            }
        }

    companion object {
        const val RUN_ID = "offlineRunId"
    }
}

internal fun scheduleOfflineTraversal(
    context: Context,
    runId: String,
    continuation: Boolean = false,
) {
    val request =
        OneTimeWorkRequestBuilder<OfflineTraversalWorker>()
            .setInputData(workDataOf(OfflineTraversalWorker.RUN_ID to runId))
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.NOT_REQUIRED).build())
            .build()
    WorkManager
        .getInstance(context)
        .enqueueUniqueWork(
            "offline-run-$runId",
            if (continuation) ExistingWorkPolicy.APPEND_OR_REPLACE else ExistingWorkPolicy.KEEP,
            request,
        ).result
        .get()
}

internal suspend fun reconcileOfflineTraversals(context: Context) {
    scheduleOfflineMaintenance(context, recovery = true)
}
