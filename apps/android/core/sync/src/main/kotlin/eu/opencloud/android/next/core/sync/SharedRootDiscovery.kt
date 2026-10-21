package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.IncomingShareEntity
import eu.opencloud.android.next.core.database.IncomingShareSnapshot
import eu.opencloud.android.next.core.database.IncomingShareStore
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.SharedFolderResolution
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

/** Only a complete fresh inventory and checked server roots can produce a catalog; failures never become emptiness. */
class SharedRootDiscovery(
    private val inventory: IncomingShareStore,
    private val refresh: suspend (String) -> Boolean,
    private val resolve: suspend (IncomingShareEntity) -> SharedFolderLocation?,
) {
    suspend fun discover(account: String): SharedRootCatalog {
        if (!refresh(account)) staleRoots()
        val snapshot = inventory.snapshot(account) ?: staleRoots()
        val roots = mutableListOf<SharedFolderLocation>()
        val unavailable = mutableListOf<IncomingShareEntity>()
        for (share in snapshot.shares.filter { it.isFolder }) {
            currentCoroutineContext().ensureActive()
            if (!inventory.isCurrent(snapshot)) staleRoots()
            val root = resolve(share)
            if (root == null) {
                unavailable.add(share)
            } else {
                if (root.accountId != account ||
                    root.shareId != share.id ||
                    root.rootItemId != share.remoteId
                ) {
                    staleRoots()
                }
                roots.add(root)
            }
        }
        currentCoroutineContext().ensureActive()
        if (!inventory.isCurrent(snapshot)) staleRoots()
        return SharedRootCatalog(snapshot, roots.toList(), unavailable.toList())
    }

    suspend fun isCurrent(catalog: SharedRootCatalog): Boolean = inventory.isCurrent(catalog.snapshot)

    companion object {
        fun create(context: Context): SharedRootDiscovery {
            val app = context.applicationContext
            val inventory = IncomingShareStore(FileBrowserDatabase.create(app))
            val discovery = IncomingShareRepository.create(app)
            val access = IncomingShareAccessRepository.create(app)
            val browser = SharedFolderBrowser.create(app)
            return SharedRootDiscovery(inventory, discovery::refresh) { share ->
                val checked = access.resolve(share.accountId, share.id) ?: staleRoots()
                val resolved = checked.resolution as? SharedFolderResolution.Resolved
                if (resolved?.access?.canBrowse == true) browser.open(share.accountId, share.id).location else null
            }
        }
    }
}

class SharedRootCatalog internal constructor(
    internal val snapshot: IncomingShareSnapshot,
    val roots: List<SharedFolderLocation>,
    val unavailable: List<IncomingShareEntity>,
)

private fun staleRoots(): Nothing = throw OpenCloudException(OpenCloudError.PreconditionFailed)
