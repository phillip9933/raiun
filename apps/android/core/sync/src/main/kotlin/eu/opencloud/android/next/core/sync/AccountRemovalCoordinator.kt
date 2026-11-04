package eu.opencloud.android.next.core.sync

import android.content.Context
import android.provider.DocumentsContract
import androidx.work.BackoffPolicy
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import eu.opencloud.android.next.core.database.AccountRemovalAdmission
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.accountRemovalOwner
import eu.opencloud.android.next.core.database.beginAccountRemoval
import eu.opencloud.android.next.core.database.hasOtherAccountAtServer
import eu.opencloud.android.next.core.database.pendingAccountRemovals
import eu.opencloud.android.next.core.datastore.SettingsRepository
import eu.opencloud.android.next.core.security.AccountSessions
import eu.opencloud.android.next.core.security.ClientCertificatePolicy
import eu.opencloud.android.next.core.security.VaultKeyStore
import eu.opencloud.android.next.core.security.VaultPreferences
import eu.opencloud.android.next.core.security.VaultUnlockSession
import eu.opencloud.android.next.core.security.WifiServerRouteStore
import kotlinx.coroutines.CancellationException
import java.util.concurrent.TimeUnit

/** The database tombstone is the queue of record; WorkManager is a repeatable execution trigger. */
class AccountRemovalCoordinator(
    private val context: Context,
    private val store: FileBrowserStore = FileBrowserStore(FileBrowserDatabase.create(context)),
) {
    suspend fun request(accountId: String): String? =
        AccountRemovalAdmission.withLock {
            if (store.beginAccountRemoval(accountId)) {
                VaultUnlockSession(context).forgetAccount(accountId)
                enqueue(accountId)
            }
            selectRemainingAccount(accountId)
        }

    suspend fun reconcile() {
        store.pendingAccountRemovals().forEach { enqueue(it.id) }
    }

    private fun enqueue(accountId: String) {
        val request =
            OneTimeWorkRequestBuilder<AccountRemovalWorker>()
                .setInputData(workDataOf(ACCOUNT_REMOVAL_ID to accountId))
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
                // Intentionally no accountWorkTag: cleanup cancels that tag itself.
                .build()
        WorkManager
            .getInstance(context)
            .enqueueUniqueWork(
                "account-removal-$accountId",
                ExistingWorkPolicy.APPEND_OR_REPLACE,
                request,
            ).result
            .get()
    }

    internal suspend fun cleanup(accountId: String) =
        AccountRemovalAdmission.withLock {
            val account = store.pendingAccountRemovals().firstOrNull { it.id == accountId }
            if (account != null) {
                val owner = store.accountRemovalOwner(accountId)
                val stages: List<suspend () -> Unit> =
                    listOf(
                        { TransferManager(context, store).cancelAccountWork(accountId) },
                        { AccountSessions.get(context).remove(accountId) },
                        { VaultUploadStore(context).forgetAccountForRemoval(accountId) },
                        {
                            VaultDownloadStore(context).forgetAccountForRemoval(accountId)
                            if (owner != null) VaultOfflineGroupPlanStore(context).forgetForAccountRemoval(owner)
                        },
                        { VaultKeyStore(context).forgetAccount(accountId) },
                        { VaultPreferences(context).forgetAccount(accountId) },
                        { VaultOfflineStore(context).forgetAccount(accountId) },
                        { clearAccountPrivateFiles(context, accountId) },
                        { AccountProfiles.clear(context, accountId) },
                        {
                            if (!store.hasOtherAccountAtServer(account)) {
                                ClientCertificatePolicy(context).clear(account.serverUrl)
                                WifiServerRouteStore(context).remove(account.serverUrl)
                            }
                        },
                        { selectRemainingAccount(accountId) },
                    )
                completeAccountRemoval(stages) { store.removeAccount(accountId) }
            }
        }

    private suspend fun selectRemainingAccount(accountId: String): String? {
        val settings = SettingsRepository.create(context)
        val next = store.activeAccounts().firstOrNull()?.id
        // A background retry must not change the user's later selection of another account.
        val selected = settings.replaceActiveAccountIfCurrent(accountId, next)
        context.contentResolver.notifyChange(
            DocumentsContract.buildRootsUri("${context.packageName}.documents"),
            null,
        )
        return selected
    }
}

/** No stage acknowledgement is needed: all stages are idempotent, and only success removes the tombstone. */
internal suspend fun completeAccountRemoval(
    stages: List<suspend () -> Unit>,
    finish: suspend () -> Unit,
) {
    stages.forEach { it() }
    finish()
}

internal const val ACCOUNT_REMOVAL_ID = "account-removal-id"

class AccountRemovalWorker(
    context: Context,
    parameters: WorkerParameters,
) : CoroutineWorker(context, parameters) {
    @Suppress("TooGenericExceptionCaught") // Keep the durable tombstone on every failed cleanup stage.
    override suspend fun doWork(): Result {
        val id = inputData.getString(ACCOUNT_REMOVAL_ID) ?: return Result.failure()
        return try {
            AccountRemovalCoordinator(applicationContext).cleanup(id)
            Result.success()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            Result.retry()
        }
    }
}
