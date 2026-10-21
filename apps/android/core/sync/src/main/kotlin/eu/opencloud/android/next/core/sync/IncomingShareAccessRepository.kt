package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.IncomingShareLease
import eu.opencloud.android.next.core.database.IncomingShareStore
import eu.opencloud.android.next.core.network.IncomingSharedItem
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.SharedFolderAccessClient
import eu.opencloud.android.next.core.network.SharedFolderResolution
import eu.opencloud.android.next.core.security.TlsPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import okhttp3.OkHttpClient

/** Null means locally missing/stale evidence, not server revocation. Never publish stale network results. */
class IncomingShareAccessRepository(
    private val inventory: IncomingShareStore,
    private val fetch: suspend (AccountEntity, IncomingSharedItem) -> SharedFolderResolution,
) {
    private val json = Json { ignoreUnknownKeys = true }

    suspend fun resolve(
        accountId: String,
        shareId: String,
    ): CheckedShareAccess? {
        val lease = inventory.beginAccess(accountId, shareId) ?: return null
        val item = decode(lease.share.metadataJson)
        if (item.id != lease.share.id || item.remoteItem.id != lease.share.remoteId) {
            throw OpenCloudException(OpenCloudError.InvalidResponse)
        }
        currentCoroutineContext().ensureActive()
        val result = fetch(lease.account, item)
        currentCoroutineContext().ensureActive()
        return if (inventory.isCurrent(lease)) CheckedShareAccess(lease, result) else null
    }

    suspend fun isCurrent(access: CheckedShareAccess): Boolean = inventory.isCurrent(access.lease)

    private fun decode(metadata: String): IncomingSharedItem =
        try {
            json.decodeFromString<IncomingSharedItem>(metadata)
        } catch (_: SerializationException) {
            throw OpenCloudException(OpenCloudError.InvalidResponse)
        } catch (_: IllegalArgumentException) {
            throw OpenCloudException(OpenCloudError.InvalidResponse)
        }

    companion object {
        fun create(context: Context): IncomingShareAccessRepository {
            val app = context.applicationContext
            val inventory = IncomingShareStore(FileBrowserDatabase.create(app))
            return IncomingShareAccessRepository(inventory) { account, item ->
                val authorization = WorkerAuthorizationProvider(app).authorization(account)
                val http = TlsPolicy(app).applyTo(OkHttpClient(), account.serverUrl)
                withContext(Dispatchers.IO) {
                    SharedFolderAccessClient(http).resolveWithMounts(account.serverUrl, authorization, item)
                }
            }
        }
    }
}

/** A current local snapshot plus a server outcome, not a permanent authorization grant. */
class CheckedShareAccess internal constructor(
    internal val lease: IncomingShareLease,
    val resolution: SharedFolderResolution,
) {
    val share: eu.opencloud.android.next.core.database.IncomingShareEntity get() = lease.share
}
