package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.SharedFolderCacheStore
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.RemoteDiscoveryClient
import eu.opencloud.android.next.core.network.RemoteFolderSink
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
    private val stagingDirectory: java.io.File? = null,
    private val streamSnapshot: (
        suspend (CheckedShareAccess, SharedFolderLocation, String, RemoteFolderSink) -> RemoteFolderSnapshot
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

    /** Refresh metadata and isolated indexes without materializing all children. */
    suspend fun openMetadata(
        accountId: String,
        shareId: String,
    ): SharedFolderPage = browse(accountId, shareId, "/", null, retainItems = false)

    internal suspend fun refreshBound(
        accountId: String,
        shareId: String,
        scopeId: String,
        path: String,
    ): SharedFolderPage = browse(accountId, shareId, path, scopeId, retainItems = false)

    suspend fun find(
        page: SharedFolderPage,
        remoteId: String,
    ): RemoteResource? {
        if (!access.isCurrent(page.checked)) stale()
        val item =
            if (cache == null) {
                page.items.singleOrNull { it.id == remoteId }
            } else {
                cache.find(page.checked, page.location, remoteId)?.takeIf { it.parentPath == page.path }?.resource()
            }
        if (!access.isCurrent(page.checked)) stale()
        return item
    }

    internal suspend fun findPath(
        page: SharedFolderPage,
        path: String,
    ): RemoteResource? {
        requireSharedPath(path)
        if (path.substringBeforeLast('/').ifEmpty { "/" } != page.path) stale()
        if (!access.isCurrent(page.checked)) stale()
        val item =
            if (cache == null) {
                if (path in page.excludedVaultPaths) throw OpenCloudException(OpenCloudError.Unsupported)
                page.items.singleOrNull { it.path == path }
            } else {
                val result = cache.findPath(page.checked, page.location, page.path, path) ?: stale()
                if (result.second) throw OpenCloudException(OpenCloudError.Unsupported)
                result.first?.resource()
            }
        if (!access.isCurrent(page.checked)) stale()
        return item
    }

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

    /** Resolves remembered identity and refreshes using bounded staging, without a list-returning discovery. */
    suspend fun refreshFolder(request: SharedFolderRequest): SharedFolderPage {
        requireSharedPath(request.path)
        if (request.remoteId.isBlank()) stale()
        if (cache == null) return openFolder(request)
        return refreshCachedFolder(request)
    }

    /** Opens a remembered folder through fresh metadata while retaining no complete child list. */
    suspend fun openFolderMetadata(request: SharedFolderRequest): SharedFolderPage = refreshFolder(request)

    private suspend fun refreshCachedFolder(request: SharedFolderRequest): SharedFolderPage {
        if (request.path == "/") return refreshCachedRoot(request)
        val parent = request.path.substringBeforeLast('/').ifEmpty { "/" }
        val page = browse(request.account, request.share, parent, request.scope, retainItems = false)
        val entry = cache?.find(page.checked, page.location, request.remoteId) ?: stale()
        if (!entry.isFolder || entry.path != request.path || entry.parentPath != parent) stale()
        if (!access.isCurrent(page.checked)) stale()
        return browse(request.account, request.share, request.path, request.scope, retainItems = false)
    }

    private suspend fun refreshCachedRoot(request: SharedFolderRequest): SharedFolderPage {
        val page = browse(request.account, request.share, "/", request.scope, retainItems = false)
        if (page.location.rootItemId != request.remoteId) stale()
        return page
    }

    suspend fun displayPage(
        page: SharedFolderPage,
        offset: Int,
    ): Pair<List<eu.opencloud.android.next.core.database.SharedFolderEntry>, Int> {
        if (!access.isCurrent(page.checked)) stale()
        require(offset >= 0)
        val result =
            cache?.displayPage(page.checked, page.location, page.path, offset)
                ?: if (cache == null) {
                    page.items.drop(offset).take(256).map { item ->
                        eu.opencloud.android.next.core.database.SharedFolderEntry(
                            page.location.accountId,
                            page.location.scopeId,
                            item.id,
                            page.path,
                            item.path,
                            item.name,
                            item.folder,
                            item.mimeType,
                            item.size,
                            item.eTag,
                            item.modifiedAtEpochMillis,
                            item.createdAtEpochMillis,
                        )
                    } to page.items.size
                } else {
                    stale()
                }
        if (!access.isCurrent(page.checked)) stale()
        return result
    }

    /** Pins provider pagination to one atomically counted cache generation. */
    suspend fun captureDisplaySnapshot(page: SharedFolderPage): SharedFolderPageCursorSnapshot {
        if (!access.isCurrent(page.checked)) stale()
        val snapshot =
            cache?.captureDisplaySnapshot(page.checked, page.location, page.path)
                ?: if (cache == null) {
                    eu.opencloud.android.next.core.database
                        .SharedFolderDisplaySnapshot(page.items.size, 0)
                } else {
                    stale()
                }
        if (!access.isCurrent(page.checked)) stale()
        return SharedFolderPageCursorSnapshot(snapshot.total, snapshot.revision)
    }

    suspend fun displayPage(
        page: SharedFolderPage,
        offset: Int,
        revision: Long,
    ): List<eu.opencloud.android.next.core.database.SharedFolderEntry> {
        if (!access.isCurrent(page.checked)) stale()
        require(offset >= 0)
        val result =
            cache?.displayPageAtRevision(page.checked, page.location, page.path, offset, revision)
                ?: if (cache == null && revision == 0L) {
                    page.items.drop(offset).take(256).map { item ->
                        eu.opencloud.android.next.core.database.SharedFolderEntry(
                            page.location.accountId,
                            page.location.scopeId,
                            item.id,
                            page.path,
                            item.path,
                            item.name,
                            item.folder,
                            item.mimeType,
                            item.size,
                            item.eTag,
                            item.modifiedAtEpochMillis,
                            item.createdAtEpochMillis,
                        )
                    }
                } else {
                    stale()
                }
        if (!access.isCurrent(page.checked)) stale()
        return result
    }

    suspend fun isDisplaySnapshotCurrent(
        page: SharedFolderPage,
        revision: Long,
    ): Boolean =
        access.isCurrent(page.checked) &&
            (cache?.isDisplayRevisionCurrent(page.checked, page.location, page.path, revision) ?: (revision == 0L))

    /** Refreshes the isolated cache without retaining the shared directory in the caller's heap. */
    suspend fun refresh(
        location: SharedFolderLocation,
        path: String,
    ) {
        browse(location.accountId, location.shareId, path, location.scopeId, retainItems = false)
    }

    @Suppress("CyclomaticComplexMethod") // Compatibility and streaming routes share one checked-access boundary.
    private suspend fun browse(
        accountId: String,
        shareId: String,
        path: String,
        expectedScope: String?,
        retainItems: Boolean = true,
    ): SharedFolderPage {
        requireSharedPath(path)
        val checked = access.resolve(accountId, shareId) ?: stale()
        val location = SharedFolderLocation.from(checked)
        if (expectedScope != null && expectedScope != location.scopeId) stale()
        if (!access.isCurrent(checked)) stale()
        val cacheToken = cache?.let { it.begin(checked, location, path) ?: stale() }
        currentCoroutineContext().ensureActive()
        if (streamSnapshot != null && stagingDirectory != null && cacheToken != null) {
            return withContext(Dispatchers.IO) {
                StagedRemoteFolder.create(stagingDirectory).use { staged ->
                    val job = currentCoroutineContext()
                    val metadata =
                        streamSnapshot.invoke(
                            checked,
                            location,
                            path,
                            RemoteFolderSink(
                                registerCanonicalPath = { value ->
                                    job.ensureActive()
                                    staged.registerCanonicalPath(value)
                                },
                                registerCollectionId = { value ->
                                    job.ensureActive()
                                    staged.registerCollectionId(value)
                                },
                                onEntry = { entry ->
                                    job.ensureActive()
                                    staged.add(entry)
                                },
                            ),
                        )
                    staged.finish()
                    job.ensureActive()
                    if (!access.isCurrent(checked)) stale()
                    if (cache?.saveStaged(checked, location, path, cacheToken, staged, metadata) != true) stale()
                    if (path in metadata.excludedVaultPaths) throw OpenCloudException(OpenCloudError.Unsupported)
                    materializePage(staged, checked, location, path, metadata, retainItems)
                }
            }
        }
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
        return if (retainItems || cache == null) {
            page
        } else {
            SharedFolderPage(
                location,
                path,
                emptyList(),
                checked,
                snapshot.excludedVaultPaths,
                snapshot.plainCollectionConfirmed,
            )
        }
    }

    @Suppress("LongParameterList") // Compatibility list publication shares the checked snapshot identity.
    private suspend fun materializePage(
        staged: StagedRemoteFolder,
        checked: CheckedShareAccess,
        location: SharedFolderLocation,
        path: String,
        metadata: RemoteFolderSnapshot,
        retainItems: Boolean,
    ): SharedFolderPage {
        val job = currentCoroutineContext()
        val items = mutableListOf<RemoteResource>()
        val exclusions = mutableSetOf<String>()
        if (retainItems) {
            var after = 0L
            while (true) {
                job.ensureActive()
                val batch = staged.page(after)
                if (batch.isEmpty()) break
                after = batch.last().sequence
                batch.forEach { row ->
                    row.entry.resource?.let(items::add) ?: exclusions.add(row.entry.path)
                }
            }
        }
        return SharedFolderPage(
            location,
            path,
            items,
            checked,
            exclusions,
            metadata.plainCollectionConfirmed,
        )
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
        @Suppress("ThrowsCount") // Every network route rechecks the live share lease.
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
                stagingDirectory = app.cacheDir,
                streamSnapshot = { checked, location, path, sink ->
                    val account = checked.lease.account
                    val authorization = WorkerAuthorizationProvider(app).authorization(account)
                    if (!access.isCurrent(checked)) throw OpenCloudException(OpenCloudError.PreconditionFailed)
                    val http = TlsPolicy(app).applyTo(OkHttpClient(), account.serverUrl)
                    RemoteDiscoveryClient(http).streamSharedFolder(location.rootWebDavUrl, path, authorization, sink)
                },
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

data class SharedFolderPageCursorSnapshot(
    val total: Int,
    val revision: Long,
)

data class SharedFolderRequest(
    val account: String,
    val share: String,
    val scope: String,
    val remoteId: String,
    val path: String,
)

private fun eu.opencloud.android.next.core.database.SharedFolderEntry.resource() =
    RemoteResource(
        remoteId,
        path,
        name,
        isFolder,
        mimeType,
        sizeBytes,
        eTag,
        modifiedAtEpochMillis,
        createdAtEpochMillis,
    )
