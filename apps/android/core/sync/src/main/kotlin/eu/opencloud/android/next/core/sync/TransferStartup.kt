package eu.opencloud.android.next.core.sync

import android.content.Context
import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/** Application lifetime; recovery runs off the main thread after WorkManager initialization. */
object TransferStartup {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    fun initialize(context: Context) {
        val application = context.applicationContext
        scope.launch {
            val manager by lazy { TransferManager(application) }
            val stages =
                linkedMapOf<StartupRecoveryStep, suspend () -> Unit>(
                    StartupRecoveryStep.SHARED_CLEANUP to { scheduleSharedDownloadCleanup(application) },
                    StartupRecoveryStep.FILE_OPERATIONS to { FileOperationManager(application).reconcile() },
                    StartupRecoveryStep.PENDING_PINS to { schedulePendingPins(application) },
                    StartupRecoveryStep.TRANSFERS to { manager.reconcile() },
                    StartupRecoveryStep.OFFLINE_TRAVERSALS to { reconcileOfflineTraversals(application) },
                    StartupRecoveryStep.CACHE_CLEANUP to { manager.scheduleCleanup() },
                    StartupRecoveryStep.DOCUMENT_EDITS to { DocumentEditReconciler(application).reconcile() },
                )
            recoverStartupStages(stages) { step -> Log.e("OpenCloudSync", "STARTUP_${step.name}_FAILED") }
        }
    }
}

internal enum class StartupRecoveryStep {
    SHARED_CLEANUP,
    FILE_OPERATIONS,
    PENDING_PINS,
    TRANSFERS,
    OFFLINE_TRAVERSALS,
    CACHE_CLEANUP,
    DOCUMENT_EDITS,
}

/** A failed independent recovery stage must not strand other durable work until another process start. */
@Suppress("TooGenericExceptionCaught")
internal suspend fun recoverStartupStages(
    stages: Map<StartupRecoveryStep, suspend () -> Unit>,
    reportFailure: (StartupRecoveryStep) -> Unit,
) {
    stages.forEach { (step, recover) ->
        try {
            recover()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            reportFailure(step)
        }
    }
}
