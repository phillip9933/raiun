package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.IncomingShareEntity
import eu.opencloud.android.next.core.database.IncomingShareStore
import eu.opencloud.android.next.core.network.IncomingSharedItem
import eu.opencloud.android.next.core.network.IncomingSharesClient
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.TlsPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.OkHttpClient

/** Publishes only complete discovery; storage grants no access until root/permission resolution. */
class IncomingShareRepository(
    private val inventory: IncomingShareStore,
    private val afterPublication: suspend (String) -> Unit = {},
    private val fetch: suspend (String) -> List<IncomingSharedItem>,
) {
    private val json = Json { ignoreUnknownKeys = true }

    fun observe(accountId: String) = inventory.observe(accountId)

    suspend fun refresh(accountId: String): Boolean {
        val token = inventory.beginRefresh(accountId)
        val rows =
            fetch(accountId).map { item ->
                currentCoroutineContext().ensureActive()
                val metadata = json.encodeToString(item)
                if (metadata.toByteArray(Charsets.UTF_8).size > 256 * 1024) {
                    throw OpenCloudException(OpenCloudError.InvalidResponse)
                }
                IncomingShareEntity(
                    accountId,
                    item.id,
                    item.remoteItem.id,
                    requireNotNull(item.name?.takeIf(String::isNotBlank) ?: item.remoteItem.name),
                    item.folder != null || item.remoteItem.folder != null,
                    item.remoteItem.webDavUrl,
                    metadata,
                )
            }
        currentCoroutineContext().ensureActive()
        val published = inventory.replace(accountId, token, rows)
        if (published) afterPublication(accountId)
        return published
    }

    companion object {
        fun create(context: Context): IncomingShareRepository {
            val application = context.applicationContext
            val database = FileBrowserDatabase.create(application)
            val accounts = FileBrowserStore(database)
            return IncomingShareRepository(
                IncomingShareStore(database),
                afterPublication = { scheduleSharedDownloadCleanup(application) },
            ) { accountId ->
                val account = requireNotNull(accounts.account(accountId))
                check(account.isActive)
                val authorization = WorkerAuthorizationProvider(application).authorization(account)
                val http = TlsPolicy(application).applyTo(OkHttpClient(), account.serverUrl)
                withContext(Dispatchers.IO) {
                    IncomingSharesClient(http).list(account.serverUrl, authorization)
                }
            }
        }
    }
}
