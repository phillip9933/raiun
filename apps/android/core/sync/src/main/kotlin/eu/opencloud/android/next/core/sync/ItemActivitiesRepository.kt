package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.network.ItemActivitiesClient
import eu.opencloud.android.next.core.network.ItemActivity
import eu.opencloud.android.next.core.security.AppLock
import eu.opencloud.android.next.core.security.TlsPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient

/** No activity cache: the server checks access on every request, including shared items. */
class ItemActivitiesRepository(
    context: Context,
) {
    private val app = context.applicationContext
    private val store = FileBrowserStore(FileBrowserDatabase.create(app))

    suspend fun list(
        accountId: String,
        itemId: String,
    ): List<ItemActivity> =
        withContext(Dispatchers.IO) {
            val permit = AppLock(app).beginAppAction()
            val account = requireNotNull(store.account(accountId))
            check(account.isActive)
            val authorization = WorkerAuthorizationProvider(app).authorization(account)
            currentCoroutineContext().ensureActive()
            check(permit() && store.account(accountId) == account)
            val http = TlsPolicy(app).applyTo(OkHttpClient(), account.serverUrl)
            val result = ItemActivitiesClient(http).list(account.serverUrl, authorization, itemId)
            currentCoroutineContext().ensureActive()
            check(permit() && store.account(accountId) == account)
            result
        }
}
