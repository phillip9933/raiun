package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.model.auth.ServerCapabilities
import eu.opencloud.android.next.core.network.GraphShareTarget
import eu.opencloud.android.next.core.network.GuestPermission
import eu.opencloud.android.next.core.network.GuestPermissions
import eu.opencloud.android.next.core.network.GuestPermissionsClient
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.AccountSessions
import eu.opencloud.android.next.core.security.AppLock
import eu.opencloud.android.next.core.security.TlsPolicy
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import okhttp3.OkHttpClient

/** Account-bound access to OpenCloud 9 guest permissions. Invitation URLs are never retained here. */
class GuestInvitationManager(
    private val context: Context,
    private val store: FileBrowserStore = FileBrowserStore(FileBrowserDatabase.create(context)),
) {
    suspend fun list(
        accountId: String,
        target: GraphShareTarget,
    ): GuestPermissions =
        session(accountId) { client, server, auth ->
            client.list(server, auth, target)
        }

    suspend fun invite(
        accountId: String,
        target: GraphShareTarget,
        email: String,
        roleId: String,
        expirationDateTime: String? = null,
    ): GuestPermission =
        session(accountId) { client, server, auth ->
            client.invite(server, auth, target, email, roleId, expirationDateTime)
        }

    suspend fun update(
        accountId: String,
        target: GraphShareTarget,
        permissionId: String,
        roleId: String,
        expirationDateTime: String? = null,
    ): GuestPermission =
        session(accountId) { client, server, auth ->
            client.update(server, auth, target, permissionId, roleId, expirationDateTime)
        }

    suspend fun remove(
        accountId: String,
        target: GraphShareTarget,
        permissionId: String,
    ) = session(accountId) { client, server, auth ->
        client.remove(server, auth, target, permissionId)
    }

    private suspend fun <T> session(
        accountId: String,
        action: suspend (GuestPermissionsClient, String, String) -> T,
    ): T {
        val callerContext = currentCoroutineContext()
        callerContext.ensureActive()
        val callerJob = callerContext[Job]
        val permit = AppLock(context).beginAppAction()
        val account = requireNotNull(store.account(accountId)) { "The account is unavailable." }
        check(account.isActive && permit())
        val accountLease = AccountSessions.get(context).beginLease(accountId)
        check(accountLease())
        val authorization = WorkerAuthorizationProvider(context).authorization(account)
        currentCoroutineContext().ensureActive()
        check(permit() && accountLease() && store.account(accountId)?.sameIdentityAs(account) == true)

        val capabilities =
            CapabilityRepository.get(context).refresh(account, authorization, store)
        checkCurrent(accountId, account, permit, accountLease)
        requireGuestInvitationSupport(capabilities)

        val client =
            GuestPermissionsClient(
                TlsPolicy(context).applyTo(OkHttpClient(), account.serverUrl),
                beforeRequest = {
                    callerContext.ensureActive()
                    check(callerJob?.isActive != false && permit() && accountLease())
                },
            )
        val result = action(client, account.serverUrl, authorization)
        checkCurrent(accountId, account, permit, accountLease)
        callerContext.ensureActive()
        return result
    }

    private suspend fun checkCurrent(
        accountId: String,
        account: AccountEntity,
        permit: () -> Boolean,
        accountLease: () -> Boolean,
    ) {
        currentCoroutineContext().ensureActive()
        check(permit() && accountLease() && store.account(accountId)?.sameIdentityAs(account) == true)
    }

    private fun AccountEntity.sameIdentityAs(other: AccountEntity): Boolean =
        id == other.id &&
            serverUrl == other.serverUrl &&
            userId == other.userId &&
            authenticationType == other.authenticationType &&
            isActive == other.isActive &&
            oidcIssuer == other.oidcIssuer &&
            oidcTokenEndpoint == other.oidcTokenEndpoint
}

/** OpenCloud advertises guest support explicitly; version.string is a legacy compatibility version. */
internal fun requireGuestInvitationSupport(capabilities: ServerCapabilities) {
    if (!capabilities.sharingEnabled || !capabilities.guestLinksEnabled) {
        throw OpenCloudException(OpenCloudError.Unsupported)
    }
}
