package eu.opencloud.android.next.core.sync

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.network.RemoteDiscoveryClient
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.security.TlsPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient

class PendingPinWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {
    @Suppress("TooGenericExceptionCaught")
    override suspend fun doWork(): Result =
        withContext(Dispatchers.IO) {
            val database = FileBrowserDatabase.create(applicationContext)
            val store = FileBrowserStore(database)
            val dao = database.pendingPinDao()
            var budget = 32
            for (pin in dao.pending()) {
                dao.attempted(pin.accountId, pin.spaceId, pin.path, System.currentTimeMillis())
                try {
                    if (!restorePin(store, pin) { budget-- > 0 }) return@withContext Result.retry()
                    dao.acknowledge(pin.accountId, pin.spaceId, pin.path)
                } catch (failure: Exception) {
                    failure.toOpenCloudError()
                }
            }
            if (dao.pending().isEmpty()) Result.success() else Result.retry()
        }

    private suspend fun restorePin(
        store: FileBrowserStore,
        pin: eu.opencloud.android.next.core.database.PendingPinEntity,
        takeRequest: () -> Boolean,
    ): Boolean {
        val account = requireNotNull(store.account(pin.accountId))
        val space = requireNotNull(store.space(pin.accountId, pin.spaceId))
        val client =
            RemoteDiscoveryClient(TlsPolicy(applicationContext).applyTo(OkHttpClient(), account.serverUrl))
        val authorization = WorkerAuthorizationProvider(applicationContext).authorization(account)
        var parentId: String? = null
        var path = "/"
        var current: eu.opencloud.android.next.core.database.ResourceEntity? = null
        for (name in pin.path.trim('/').split('/')) {
            val cached = store.child(pin.accountId, pin.spaceId, parentId, name)
            val expected = "${path.trimEnd('/')}/$name"
            if (cached?.path != expected || expected == pin.path) {
                if (!takeRequest()) return false
                refreshFolder(
                    FolderRefresh(store, client, pin.accountId, space, parentId, path, authorization),
                )
                schedulePendingExcludedCache(applicationContext)
            }
            current = requireNotNull(store.child(pin.accountId, pin.spaceId, parentId, name))
            parentId = current.remoteId
            path = current.path
            if (path != pin.path) require(current.kind == ResourceKind.FOLDER)
        }
        current?.let { TransferManager(applicationContext, store).makeAvailableOffline(it) }
        return true
    }
}

internal fun schedulePendingPins(context: Context) {
    val request =
        OneTimeWorkRequestBuilder<PendingPinWorker>()
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.NOT_REQUIRED).build())
            .build()
    WorkManager
        .getInstance(
            context,
        ).enqueueUniqueWork("pending-offline-pins", ExistingWorkPolicy.APPEND_OR_REPLACE, request)
}
