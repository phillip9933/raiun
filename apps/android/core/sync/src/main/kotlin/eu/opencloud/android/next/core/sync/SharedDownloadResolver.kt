package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.network.DownloadExpectation
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.RemoteResource
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.serialization.Serializable
import okhttp3.HttpUrl.Companion.toHttpUrl

/** Persist identity/version, never credentials, an access grant, or a guessed server address. */
@Serializable
data class SharedDownloadRequest(
    val accountId: String,
    val shareId: String,
    val scopeId: String,
    val file: SharedDownloadFile,
)

@Serializable
data class SharedDownloadFile(
    val remoteId: String,
    val path: String,
    val sizeBytes: Long,
    val eTag: String?,
)

/** Resolves a captured file selection again before a transfer attempt. This does not queue or download bytes. */
class SharedDownloadResolver(
    private val browser: SharedFolderBrowser,
) {
    suspend fun capture(
        page: SharedFolderPage,
        remoteId: String,
    ): SharedDownloadRequest {
        currentCoroutineContext().ensureActive()
        if (!browser.isCurrent(page)) staleDownload()
        val item = page.items.singleOrNull { it.id == remoteId } ?: staleDownload()
        if (item.folder || item.size < 0) staleDownload()
        return SharedDownloadRequest(
            page.location.accountId,
            page.location.shareId,
            page.location.scopeId,
            SharedDownloadFile(item.id, item.path, item.size, item.eTag),
        )
    }

    suspend fun prepare(request: SharedDownloadRequest): PreparedSharedDownload {
        validateRequest(request)
        val parent =
            request.file.path
                .substringBeforeLast('/')
                .ifEmpty { "/" }
        val page = browser.listBound(request.accountId, request.shareId, request.scopeId, parent)
        val item = page.items.singleOrNull { it.id == request.file.remoteId } ?: staleDownload()
        val unchanged =
            !item.folder &&
                item.path == request.file.path &&
                item.size == request.file.sizeBytes &&
                item.eTag == request.file.eTag
        if (!unchanged) staleDownload()
        currentCoroutineContext().ensureActive()
        if (!browser.isCurrent(page)) staleDownload()
        return PreparedSharedDownload(request, page, item)
    }

    /** Local lifecycle check only. The GET must still enforce descendant content access on the server. */
    suspend fun isCurrent(source: PreparedSharedDownload): Boolean = browser.isCurrent(source.page)

    private fun validateRequest(request: SharedDownloadRequest) {
        val file = request.file
        requireSharedPath(file.path)
        val missingIdentity =
            listOf(
                request.accountId,
                request.shareId,
                request.scopeId,
                file.remoteId,
            ).any(String::isBlank)
        if (missingIdentity || file.path == "/" || file.sizeBytes < 0) staleDownload()
    }

    companion object {
        fun create(context: Context) = SharedDownloadResolver(SharedFolderBrowser.create(context))
    }
}

/** Fresh metadata is not permission to bypass GET, reuse cached bytes, or publish a local copy. */
class PreparedSharedDownload internal constructor(
    val request: SharedDownloadRequest,
    internal val page: SharedFolderPage,
    val item: RemoteResource,
) {
    val location get() = page.location
    val expectation get() = DownloadExpectation(request.file.sizeBytes, request.file.eTag)
    val url: String get() {
        val builder = location.rootWebDavUrl.toHttpUrl().newBuilder()
        if (!builder.build().encodedPath.endsWith('/')) builder.addPathSegment("")
        request.file.path
            .removePrefix("/")
            .split('/')
            .forEach(builder::addPathSegment)
        return builder.build().toString()
    }
}

private fun staleDownload(): Nothing = throw OpenCloudException(OpenCloudError.PreconditionFailed)
