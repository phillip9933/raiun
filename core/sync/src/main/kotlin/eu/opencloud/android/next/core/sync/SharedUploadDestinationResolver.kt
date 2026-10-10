package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.network.IncomingSharedItem
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.SharedFolderAccessClient
import eu.opencloud.android.next.core.network.SharedFolderResolution
import eu.opencloud.android.next.core.network.SharedParentReference
import eu.opencloud.android.next.core.network.SharedRemoteItem
import eu.opencloud.android.next.core.security.TlsPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient

/** Fresh exact-target rights and containment evidence, never permission to reuse an ordinary drive upload. */
class SharedUploadDestinationResolver(
    private val browser: SharedFolderBrowser,
    private val resolveTarget: suspend (SharedFolderPage, String) -> SharedFolderResolution,
) {
    suspend fun prepare(request: SharedFolderRequest): PreparedSharedUploadDestination {
        val page = browser.openFolder(request)
        val target =
            resolveTarget(page, request.remoteId) as? SharedFolderResolution.Resolved
                ?: throw OpenCloudException(OpenCloudError.AccessDenied)
        currentCoroutineContext().ensureActive()
        val identity = target.driveId == page.location.serverDriveId && target.itemId == request.remoteId
        if (!identity || !browser.isCurrent(page)) throw OpenCloudException(OpenCloudError.PreconditionFailed)
        requireUploadAccess(target)
        validateAddress(page, request, target)
        return PreparedSharedUploadDestination(request, page, target.webDavUrl, target.access.canCreateFolder)
    }

    suspend fun isCurrent(destination: PreparedSharedUploadDestination): Boolean = browser.isCurrent(destination.page)

    private fun requireUploadAccess(target: SharedFolderResolution.Resolved) {
        if (!target.access.canUpload) throw OpenCloudException(OpenCloudError.AccessDenied)
    }

    private fun validateAddress(
        page: SharedFolderPage,
        request: SharedFolderRequest,
        target: SharedFolderResolution.Resolved,
    ) {
        val root = page.location.rootWebDavUrl.toHttpUrl()
        val expected = root.newBuilder()
        if (!root.encodedPath.endsWith('/')) expected.addPathSegment("")
        if (request.path != "/") {
            request.path
                .removePrefix("/")
                .split('/')
                .forEach(expected::addPathSegment)
        }
        val actual = target.webDavUrl.toHttpUrl()
        val normalized = actual.newBuilder().encodedPath(actual.encodedPath.trimEnd('/') + "/").build()
        val expectedUrl = expected.build()
        val normalizedExpected =
            expectedUrl
                .newBuilder()
                .encodedPath(
                    expectedUrl.encodedPath.trimEnd('/') + "/",
                ).build()
        if (normalized != normalizedExpected) throw OpenCloudException(OpenCloudError.Trust)
    }

    companion object {
        fun create(context: Context): SharedUploadDestinationResolver {
            val app = context.applicationContext
            val browser = SharedFolderBrowser.create(app)
            return SharedUploadDestinationResolver(browser) { page, remote ->
                val account = page.checked.lease.account
                val authorization = WorkerAuthorizationProvider(app).authorization(account)
                val http = TlsPolicy(app).applyTo(OkHttpClient(), account.serverUrl)
                val selection =
                    IncomingSharedItem(
                        page.location.shareId,
                        SharedRemoteItem(
                            remote,
                            parentReference = SharedParentReference(driveId = page.location.serverDriveId),
                        ),
                    )
                withContext(Dispatchers.IO) {
                    SharedFolderAccessClient(http).resolve(account.serverUrl, authorization, selection)
                }
            }
        }
    }
}

class PreparedSharedUploadDestination internal constructor(
    val request: SharedFolderRequest,
    internal val page: SharedFolderPage,
    val webDavUrl: String,
    val canCreateFolder: Boolean,
)
