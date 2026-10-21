package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.network.ShareRecipient
import eu.opencloud.android.next.core.network.SpaceMembersClient
import eu.opencloud.android.next.core.security.AppLock
import eu.opencloud.android.next.core.security.TlsPolicy
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import okhttp3.OkHttpClient

class SpaceMembersRepository(
    private val context: Context,
) {
    private val store = FileBrowserStore(FileBrowserDatabase.create(context))

    suspend fun list(
        account: String,
        drive: String,
    ) = session(account) { client, server, auth, _ ->
        client.list(server, auth, drive)
    }

    suspend fun add(
        account: String,
        drive: String,
        recipient: ShareRecipient,
        role: String,
    ) = session(account) { client, server, auth, checkCurrent ->
        require(client.list(server, auth, drive).roles.any { it.id == role })
        checkCurrent()
        client.add(server, auth, drive, recipient, role)
    }

    suspend fun update(
        account: String,
        drive: String,
        permission: String,
        role: String,
    ) = session(account) { client, server, auth, checkCurrent ->
        val latest = client.list(server, auth, drive)
        require(latest.members.any { it.id == permission } && latest.roles.any { it.id == role })
        checkCurrent()
        client.update(server, auth, drive, permission, role)
    }

    suspend fun remove(
        account: String,
        drive: String,
        permission: String,
    ) = session(account) { client, server, auth, checkCurrent ->
        require(client.list(server, auth, drive).members.any { it.id == permission })
        checkCurrent()
        client.remove(server, auth, drive, permission)
    }

    private suspend fun <T> session(
        accountId: String,
        action: suspend (SpaceMembersClient, String, String, suspend () -> Unit) -> T,
    ): T {
        val permit = AppLock(context).beginAppAction()
        val account = requireNotNull(store.account(accountId))
        check(account.isActive && permit())
        val auth = WorkerAuthorizationProvider(context).authorization(account)
        currentCoroutineContext().ensureActive()
        check(permit() && store.account(accountId) == account)
        val client = SpaceMembersClient(TlsPolicy(context).applyTo(OkHttpClient(), account.serverUrl))
        val result =
            action(client, account.serverUrl, auth) {
                currentCoroutineContext().ensureActive()
                check(permit() && store.account(accountId) == account)
            }
        currentCoroutineContext().ensureActive()
        check(permit() && store.account(accountId) == account)
        return result
    }
}
