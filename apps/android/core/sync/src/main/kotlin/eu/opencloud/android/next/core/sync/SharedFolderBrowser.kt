package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.SharedFolderCacheStore
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.RemoteDiscoveryClient
import eu.opencloud.android.next.core.network.RemoteFolderSnapshot
import eu.opencloud.android.next.core.network.RemoteResource
import eu.opencloud.android.next.core.network.SharedMetadataException
import eu.opencloud.android.next.core.network.SharedMetadataStage
import eu.opencloud.android.next.core.security.TlsPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient

/** Read-only listing with isolated metadata caching; transfer/provider registration remains separate. */
class SharedFolderBrowser(
    private val access: IncomingShareAccessRepository,
    private val cache: SharedFolderPageCache? = null,
    private val fetchSnapshot: (
        suspend (
            CheckedShareAccess,
            SharedFolderLocation,
            String,
        ) -> RemoteFolderSnapshot
    )? = null,
    private val fetch: suspend (CheckedShareAccess, SharedFolderLocation, String) -> List<RemoteResource>,
) {
    suspend fun open(
        accountId: String,
        shareId: String,
    ): SharedFolderPage = browse(accountId, shareId, "/", null)

    suspend fun list(
        location: SharedFolderLocation,
        path: String,
    ): SharedFolderPage = browse(location.accountId, location.shareId, path, location.scopeId)

    internal suspend fun listBound(
        accountId: String,
        shareId: String,
        scopeId: String,
        path: String,
    ): SharedFolderPage = browse(accountId, shareId, path, scopeId)

    suspend fun isCurrent(page: SharedFolderPage): Boolean = access.isCurrent(page.checked)

    /** A remembered folder path must still identify the same folder before listing its children. */
    suspend fun openFolder(request: SharedFolderRequest): SharedFolderPage {
        requireSharedPath(request.path)
        if (request.remoteId.isBlank()) stale()
        if (request.path == "/") {
            val page = listBound(request.account, request.share, request.scope, "/")
            if (page.location.rootItemId != request.remoteId) stale()
            return page
        }
        val parent = request.path.substringBeforeLast('/').ifEmpty { "/" }
        val page = listBound(request.account, request.share, request.scope, parent)
        val folder = page.items.singleOrNull { it.id == request.remoteId } ?: stale()
        if (!folder.folder || folder.path != request.path) stale()
        return list(page.location, folder.path)
    }

    private suspend fun browse(
        accountId: String,
        shareId: String,
        path: String,
        expectedScope: String?,
    ): SharedFolderPage {
        requireSharedPath(path)
        val checked = access.resolve(accountId, shareId) ?: stale()
        val location = SharedFolderLocation.from(checked)
        if (expectedScope != null && expectedScope != location.scopeId) stale()
        if (!access.isCurrent(checked)) stale()
        val cacheToken = cache?.let { it.begin(checked, location, path) ?: stale() }
        currentCoroutineContext().ensureActive()
        val snapshot =
            fetchSnapshot?.invoke(checked, location, path)
                ?: RemoteFolderSnapshot(fetch(checked, location, path), emptySet())
        val items = snapshot.resources
        currentCoroutineContext().ensureActive()
        validateListing(path, items)
        validateExclusions(path, items, snapshot.excludedVaultPaths)
        if (!access.isCurrent(checked)) stale()
        val requestedCollectionExcluded = path in snapshot.excludedVaultPaths
        val page =
            SharedFolderPage(
                location,
                path,
                items,
                checked,
                snapshot.excludedVaultPaths,
                snapshot.plainCollectionConfirmed,
            )
        if (cacheToken != null) {
            if (cache?.save(page, cacheToken) != true) stale()
        }
        if (requestedCollectionExcluded) throw OpenCloudException(OpenCloudError.Unsupported)
        return page
    }

    private fun validateListing(
        path: String,
        items: List<RemoteResource>,
    ) {
        val ids = mutableSetOf<String>()
        val paths = mutableSetOf<String>()
        items.forEach { item ->
            requireSharedPath(item.path)
            val parent = item.path.substringBeforeLast('/').ifEmpty { "/" }
            if (item.path == "/" || parent != path || invalidIdentity(item, ids, paths)) {
                throw SharedMetadataException(SharedMetadataStage.CHILDREN)
            }
        }
    }

    private fun invalidIdentity(
        item: RemoteResource,
        ids: MutableSet<String>,
        paths: MutableSet<String>,
    ): Boolean = item.id.isBlank() || !ids.add(item.id) || !paths.add(item.path)

    private fun validateExclusions(
        path: String,
        items: List<RemoteResource>,
        excludedPaths: Set<String>,
    ) {
        excludedPaths.forEach { excluded ->
            try {
                requireSharedPath(excluded)
            } catch (_: OpenCloudException) {
                throw SharedMetadataException(SharedMetadataStage.CHILDREN)
            }
            if (exclusionConflictsWithListing(path, excluded, items)) {
                throw SharedMetadataException(SharedMetadataStage.CHILDREN)
            }
        }
    }

    private fun exclusionConflictsWithListing(
        path: String,
        excluded: String,
        items: List<RemoteResource>,
    ): Boolean {
        if (excluded == path) return items.isNotEmpty()
        val parent = excluded.substringBeforeLast('/').ifEmpty { "/" }
        val listedAsPlain = items.any { it.path == excluded || it.path.startsWith("$excluded/") }
        return parent != path || listedAsPlain
    }

    private fun stale(): Nothing = throw OpenCloudException(OpenCloudError.PreconditionFailed)

    companion object {
        fun create(context: Context): SharedFolderBrowser {
            val app = context.applicationContext
            val access = IncomingShareAccessRepository.create(app)
            val cache =
                SharedFolderPageCache(SharedFolderCacheStore(FileBrowserDatabase.create(app))) {
                    scheduleSharedDownloadCleanup(app)
                }
            return SharedFolderBrowser(
                access,
                cache,
                fetch = { checked, location, path ->
                    val account = checked.lease.account
                    val authorization = WorkerAuthorizationProvider(app).authorization(account)
                    if (!access.isCurrent(checked)) throw OpenCloudException(OpenCloudError.PreconditionFailed)
                    val http = TlsPolicy(app).applyTo(OkHttpClient(), account.serverUrl)
                    withContext(Dispatchers.IO) {
                        RemoteDiscoveryClient(http).folder(location.rootWebDavUrl, path, authorization)
                    }
                },
                fetchSnapshot = { checked, location, path ->
                    val account = checked.lease.account
                    val authorization = WorkerAuthorizationProvider(app).authorization(account)
                    if (!access.isCurrent(checked)) throw OpenCloudException(OpenCloudError.PreconditionFailed)
                    val http = TlsPolicy(app).applyTo(OkHttpClient(), account.serverUrl)
                    withContext(Dispatchers.IO) {
                        RemoteDiscoveryClient(http).sharedFolderSnapshot(location.rootWebDavUrl, path, authorization)
                    }
                },
            )
        }
    }
}

class SharedFolderPage internal constructor(
    val location: SharedFolderLocation,
    val path: String,
    val items: List<RemoteResource>,
    internal val checked: CheckedShareAccess,
    internal val excludedVaultPaths: Set<String> = emptySet(),
    internal val plainCollectionConfirmed: Boolean = false,
)

data class SharedFolderRequest(
    val account: String,
    val share: String,
    val scope: String,
    val remoteId: String,
    val path: String,
)
