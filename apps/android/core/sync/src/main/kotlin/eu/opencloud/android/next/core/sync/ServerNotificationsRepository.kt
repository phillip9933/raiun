package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.network.ServerNotification
import eu.opencloud.android.next.core.network.ServerNotificationsClient
import eu.opencloud.android.next.core.security.AppLock
import eu.opencloud.android.next.core.security.TlsPolicy
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import okhttp3.OkHttpClient

class ServerNotificationsRepository(
    context: Context,
) {
    private val app = context.applicationContext
    private val store = FileBrowserStore(FileBrowserDatabase.create(app))

    suspend fun list(accountId: String): List<ServerNotification> =
        session(accountId) { client, server, auth ->
            client.list(server, auth)
        }

    suspend fun markRead(
        accountId: String,
        ids: List<String>,
    ) = session(accountId) { client, server, auth ->
        client.markRead(server, auth, ids)
    }

    private suspend fun <T> session(
        accountId: String,
        action: (ServerNotificationsClient, String, String) -> T,
    ): T {
        val permit = AppLock(app).beginAppAction()
        val account = requireNotNull(store.account(accountId))
        check(account.isActive)
        val authorization = WorkerAuthorizationProvider(app).authorization(account)
        currentCoroutineContext().ensureActive()
        check(permit() && store.account(accountId) == account)
        val http = TlsPolicy(app).applyTo(OkHttpClient(), account.serverUrl)
        val result = action(ServerNotificationsClient(http), account.serverUrl, authorization)
        currentCoroutineContext().ensureActive()
        check(permit() && store.account(accountId) == account)
        return result
    }
}
