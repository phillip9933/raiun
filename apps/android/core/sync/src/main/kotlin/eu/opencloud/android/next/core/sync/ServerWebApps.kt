package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.model.auth.ServerAppProvider
import eu.opencloud.android.next.core.network.EmbeddedWebAppMode
import eu.opencloud.android.next.core.network.EmbeddedWebAppRequest
import eu.opencloud.android.next.core.network.EmbeddedWebAppSession
import eu.opencloud.android.next.core.network.OpenCloudApi
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.ServerWebApp
import eu.opencloud.android.next.core.network.ServerWebAppClient
import eu.opencloud.android.next.core.security.AppLock
import eu.opencloud.android.next.core.security.TlsPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient

data class ServerWebAppChoice(
    val provider: ServerAppProvider,
    val app: ServerWebApp,
)

/** Selections are transient; the server authorizes the file when creating the browser handoff. */
class ServerWebApps(
    context: Context,
) {
    private val context = context.applicationContext
    private val store = FileBrowserStore(FileBrowserDatabase.create(this.context))

    suspend fun choices(
        resource: ResourceEntity,
        embedded: Boolean = false,
    ): List<ServerWebAppChoice> =
        session(resource) { http, server, auth ->
            OpenCloudApi(http)
                .capabilities(server, auth)
                .appProviders
                .filter { if (embedded) it.openUrl != null else it.openWebUrl != null }
                .flatMap { provider ->
                    ServerWebAppClient(http)
                        .list(server, provider, auth)
                        .filter { it.mimeType.equals(resource.mimeType, ignoreCase = true) }
                        .map { ServerWebAppChoice(provider, it) }
                }.sortedWith(compareByDescending<ServerWebAppChoice> { it.app.isDefault }.thenBy { it.app.name })
        }

    suspend fun open(
        resource: ResourceEntity,
        choice: ServerWebAppChoice,
    ): String =
        session(resource) { http, server, auth ->
            val capabilities = OpenCloudApi(http).capabilities(server, auth)
            if (choice.provider !in capabilities.appProviders ||
                !choice.app.mimeType.equals(resource.mimeType, true)
            ) {
                denied()
            }
            ServerWebAppClient(http).openInWeb(server, choice.provider, auth, resource.remoteId, choice.app)
        }

    suspend fun prepareEmbedded(
        resource: ResourceEntity,
        choice: ServerWebAppChoice,
        mode: EmbeddedWebAppMode = EmbeddedWebAppMode.VIEW,
    ): WebSessionLease<EmbeddedWebAppSession> =
        withContext(Dispatchers.IO) {
            val permitted = AppLock(context).beginAppAction()
            val account = store.account(resource.accountId) ?: denied()
            val prepared =
                session(resource) { http, server, auth ->
                    val capabilities = OpenCloudApi(http).capabilities(server, auth)
                    if (choice.provider !in capabilities.appProviders ||
                        !choice.app.mimeType.equals(resource.mimeType, true)
                    ) {
                        denied()
                    }
                    ServerWebAppClient(
                        http,
                    ).prepareEmbedded(
                        server,
                        choice.provider,
                        auth,
                        EmbeddedWebAppRequest(resource.remoteId, choice.app, mode),
                    )
                }
            WebSessionLease(prepared, permitted) {
                requireResource(resource)
                store.account(resource.accountId) == account
            }.also { it.current() }
        }

    private suspend fun <T> session(
        resource: ResourceEntity,
        work: (OkHttpClient, String, String) -> T,
    ): T =
        withContext(Dispatchers.IO) {
            val account = store.account(resource.accountId) ?: denied()
            requireResource(resource)
            if (!account.isActive) denied()
            val auth = WorkerAuthorizationProvider(context).authorization(account)
            val http = TlsPolicy(context).applyTo(OkHttpClient(), account.serverUrl)
            withRequestCancellation(http.dispatcher::cancelAll) {
                currentCoroutineContext().ensureActive()
                val result = work(http, account.serverUrl, auth)
                currentCoroutineContext().ensureActive()
                requireResource(resource)
                if (store.account(resource.accountId) != account) denied()
                result
            }
        }

    private suspend fun requireResource(resource: ResourceEntity) {
        if (!AppLock(context).canOpenApp() || resource.kind != ResourceKind.FILE) denied()
        val space = store.space(resource.accountId, resource.spaceId) ?: denied()
        if (space.isDeleted || space.isDisabled) denied()
        val current = store.resource(resource.accountId, resource.spaceId, resource.remoteId)
        if (current != resource) throw OpenCloudException(OpenCloudError.PreconditionFailed)
    }

    private fun denied(): Nothing = throw OpenCloudException(OpenCloudError.AccessDenied)
}
