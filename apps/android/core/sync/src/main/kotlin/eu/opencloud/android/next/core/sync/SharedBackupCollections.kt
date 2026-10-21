package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.TransferClient
import eu.opencloud.android.next.core.security.TlsPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient

/** Resolve every backup subfolder within a received share; never promote its scope to a drive. */
internal class SharedBackupCollections(
    private val browser: SharedFolderBrowser,
    private val resolver: SharedUploadDestinationResolver,
    private val create: suspend (PreparedSharedUploadDestination, String, suspend () -> Unit) -> Unit,
) {
    @Suppress("ThrowsCount") // Each rejected path, exclusion, or permission must stop before MKCOL.
    suspend fun ensure(
        base: SharedFolderRequest,
        desiredPath: String,
        checkCurrent: suspend () -> Unit = {},
    ): SharedFolderRequest {
        requireSharedPath(base.path)
        requireSharedPath(desiredPath)
        val suffix =
            when {
                desiredPath == base.path -> ""
                base.path == "/" -> desiredPath.removePrefix("/")
                desiredPath.startsWith("${base.path}/") -> desiredPath.removePrefix("${base.path}/")
                else -> throw OpenCloudException(OpenCloudError.PreconditionFailed)
            }
        var current = base
        resolver.prepare(current)
        if (suffix.isEmpty()) return current
        val segments = suffix.split('/')
        require(segments.size <= 256) { "Backup folder nesting is too deep." }
        for (segment in segments) {
            currentCoroutineContext().ensureActive()
            checkCurrent()
            segment.requireValidSegment()
            val prepared = resolver.prepare(current)
            val page = browser.openFolder(current)
            val childPath = if (current.path == "/") "/$segment" else "${current.path}/$segment"
            if (childPath in page.excludedVaultPaths) throw OpenCloudException(OpenCloudError.Unsupported)
            var child = page.items.singleOrNull { it.path == childPath }
            if (child == null) {
                if (!prepared.canCreateFolder || !resolver.isCurrent(prepared)) {
                    throw OpenCloudException(OpenCloudError.AccessDenied)
                }
                checkCurrent()
                create(prepared, segment, checkCurrent)
                child = browser.openFolder(current).items.singleOrNull { it.path == childPath }
            }
            if (child?.folder != true) throw OpenCloudException(OpenCloudError.PreconditionFailed)
            current = current.copy(remoteId = child.id, path = childPath)
            resolver.prepare(current)
        }
        return current
    }

    companion object {
        fun create(context: Context): SharedBackupCollections {
            val app = context.applicationContext
            val browser = SharedFolderBrowser.create(app)
            val resolver = SharedUploadDestinationResolver.create(app)
            return SharedBackupCollections(browser, resolver) { parent, name, checkCurrent ->
                val account = parent.page.checked.lease.account
                val http = TlsPolicy(app).applyTo(OkHttpClient(), account.serverUrl)
                val token = WorkerAuthorizationProvider(app).authorization(account)
                val url =
                    parent.webDavUrl
                        .toHttpUrl()
                        .newBuilder()
                        .addPathSegment(name)
                        .build()
                        .toString()
                withRequestCancellation(
                    cancelRequests = { http.dispatcher.cancelAll() },
                    isOwned = {
                        if (!resolver.isCurrent(parent)) {
                            false
                        } else {
                            try {
                                checkCurrent()
                                true
                            } catch (_: IllegalArgumentException) {
                                false
                            }
                        }
                    },
                ) {
                    withContext(Dispatchers.IO) {
                        // A racing MKCOL returning 405 is accepted only if DAV confirms a collection.
                        TransferClient(http).createCollection(url, token, acceptExisting = true)
                    }
                }
            }
        }
    }
}
