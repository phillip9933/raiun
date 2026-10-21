package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.IncomingShareVisibilityClient
import eu.opencloud.android.next.core.network.IncomingSharedItem
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.SharedFolderAccess
import eu.opencloud.android.next.core.security.AppLock
import eu.opencloud.android.next.core.security.TlsPolicy
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.serialization.json.Json
import okhttp3.OkHttpClient

data class IncomingFolderDetails(
    val name: String,
    val path: String,
    val shareName: String,
    val owner: String?,
    val sharedBy: List<String>,
    val sharedAt: List<String>,
    val expiresAt: List<String>,
    val modifiedAt: String?,
    val size: Long?,
    val visibleItems: Int,
    val access: SharedFolderAccess,
    val permanentLink: String,
    val hidden: Boolean,
    val canChangeVisibility: Boolean,
)

/** Fresh share-root and folder identity checks precede disclosure or a visibility change. */
class IncomingFolderDetailsLoader(
    context: Context,
) {
    private val app = context.applicationContext
    private val browser = SharedFolderBrowser.create(app)
    private val repository = IncomingShareRepository.create(app)
    private val json = Json { ignoreUnknownKeys = true }

    suspend fun load(request: SharedFolderRequest): IncomingFolderDetails {
        val permit = AppLock(app).beginAppAction()
        val page = fresh(request)
        val details = describeIncomingFolder(page, metadata(page), request.remoteId)
        requireCurrent(page, permit)
        return details
    }

    suspend fun setHidden(
        request: SharedFolderRequest,
        hidden: Boolean,
    ) {
        require(request.path == "/")
        val permit = AppLock(app).beginAppAction()
        val page = fresh(request)
        val item = metadata(page)
        val account = page.checked.lease.account
        val authorization = WorkerAuthorizationProvider(app).authorization(account)
        requireCurrent(page, permit)
        val http = TlsPolicy(app).applyTo(OkHttpClient(), account.serverUrl)
        IncomingShareVisibilityClient(http).setHidden(account.serverUrl, authorization, item, hidden)
        requireCurrent(page, permit)
    }

    private suspend fun fresh(request: SharedFolderRequest): SharedFolderPage {
        if (!repository.refresh(request.account)) stale()
        return browser.openFolder(request)
    }

    private fun metadata(page: SharedFolderPage): IncomingSharedItem =
        json.decodeFromString(page.checked.share.metadataJson)

    private suspend fun requireCurrent(
        page: SharedFolderPage,
        permit: () -> Boolean,
    ) {
        currentCoroutineContext().ensureActive()
        if (!permit() || !browser.isCurrent(page)) stale()
    }

    private fun stale(): Nothing = throw OpenCloudException(OpenCloudError.PreconditionFailed)
}

internal fun describeIncomingFolder(
    page: SharedFolderPage,
    item: IncomingSharedItem,
    itemId: String,
): IncomingFolderDetails {
    val root = page.path == "/"
    val grants = item.remoteItem.permissions.orEmpty()
    val link =
        EndpointPolicy()
            .endpoint(page.checked.lease.account.serverUrl, allowQuery = false)
            .newBuilder()
            .addPathSegment("f")
            .addPathSegment(itemId)
            .build()
            .toString()
    return IncomingFolderDetails(
        name = if (root) page.location.name else page.path.substringAfterLast('/'),
        path = page.path,
        shareName = page.location.name,
        owner =
            item.remoteItem.createdBy
                ?.user
                ?.displayName,
        sharedBy =
            grants
                .mapNotNull {
                    it.invitation
                        ?.invitedBy
                        ?.user
                        ?.displayName
                }.distinct(),
        sharedAt = grants.mapNotNull { it.createdDateTime }.distinct(),
        expiresAt = grants.mapNotNull { it.expirationDateTime }.distinct(),
        modifiedAt = if (root) item.lastModifiedDateTime else null,
        size = if (root) item.size?.takeIf { it >= 0 } else null,
        visibleItems = page.items.size,
        access = page.location.access,
        permanentLink = link,
        hidden = item.hidden,
        canChangeVisibility = root && !item.parentReference?.driveId.isNullOrBlank(),
    )
}
