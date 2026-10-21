package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.StaleResourceException
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.network.GraphFavoriteClient
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.TransferClient
import eu.opencloud.android.next.core.network.WebDavFeatureClient
import eu.opencloud.android.next.core.security.TlsPolicy
import okhttp3.OkHttpClient

internal class TransferMutationOperations(
    private val context: Context,
    private val store: FileBrowserStore,
    private val refreshFolder: suspend (String, String, String?) -> Unit,
) {
    suspend fun createFolder(
        accountId: String,
        spaceId: String,
        parentId: String?,
        name: String,
    ) {
        val normalizedName = name.trim().requireValidSegment()
        val account = requireNotNull(store.account(accountId)) { "The account is unavailable." }
        val space = requireNotNull(store.space(accountId, spaceId)) { "The space is unavailable." }
        require(!space.isDisabled && !space.isDeleted) { "The space is unavailable." }
        val parent =
            parentId?.let { id ->
                val cached =
                    requireNotNull(store.resource(accountId, spaceId, id)) {
                        "The parent folder is unavailable."
                    }
                requireCurrent(cached, includeDescendants = false).also {
                    require(it.kind == ResourceKind.FOLDER) { "Choose a folder as the parent." }
                }
            }
        val destinationPath = "${parent?.path?.trimEnd('/').orEmpty()}/$normalizedName"
        try {
            store.requireAllowedFolderDestination(accountId, spaceId, parentId, parent?.path, destinationPath)
        } catch (_: StaleResourceException) {
            stale()
        }
        val root = webDavRoot(space)
        val client = TransferClient(TlsPolicy(context).applyTo(OkHttpClient.Builder().build(), account.serverUrl))
        val authorization = WorkerAuthorizationProvider(context).authorization(account)
        client.createCollection(root.mutationChildUrl(destinationPath), authorization)
        refreshFolder(accountId, spaceId, parentId)
    }

    suspend fun setFavorite(
        resource: ResourceEntity,
        favorite: Boolean,
    ) {
        val current = requireCurrent(resource, includeDescendants = false)
        val account = requireNotNull(store.account(current.accountId))
        val authorization = WorkerAuthorizationProvider(context).authorization(account)
        GraphFavoriteClient(TlsPolicy(context).applyTo(OkHttpClient.Builder().build(), account.serverUrl))
            .setFavorite(account.serverUrl, current.remoteId, authorization, favorite)
        store.setFavorite(current, favorite)
    }

    suspend fun delete(resource: ResourceEntity) {
        val current = requireCurrent(resource)
        val account = requireNotNull(store.account(current.accountId))
        val space = requireNotNull(store.space(current.accountId, current.spaceId))
        val authorization = WorkerAuthorizationProvider(context).authorization(account)
        WebDavFeatureClient(TlsPolicy(context).applyTo(OkHttpClient.Builder().build(), account.serverUrl))
            .delete(webDavRoot(space).mutationChildUrl(current.path), authorization, current.eTag)
        store.delete(current.accountId, current.spaceId, current.remoteId)
    }

    suspend fun renameFile(
        resource: ResourceEntity,
        name: String,
    ) {
        require(resource.kind == ResourceKind.FILE) { "Folder rename is not available yet." }
        val current = requireCurrent(resource)
        val account = requireNotNull(store.account(current.accountId))
        val space = requireNotNull(store.space(current.accountId, current.spaceId))
        val normalizedName = name.trim().requireValidSegment()
        val destinationPath = "${current.path.substringBeforeLast('/', "")}/$normalizedName"
        store.requireAllowedVaultPath(current.accountId, current.spaceId, destinationPath)
        val authorization = WorkerAuthorizationProvider(context).authorization(account)
        WebDavFeatureClient(TlsPolicy(context).applyTo(OkHttpClient(), account.serverUrl))
            .renameFile(webDavRoot(space).mutationChildUrl(current.path), normalizedName, current.eTag, authorization)
        refreshFolder(current.accountId, current.spaceId, current.parentId)
    }

    private suspend fun requireCurrent(
        resource: ResourceEntity,
        includeDescendants: Boolean = true,
    ): ResourceEntity =
        try {
            store.requireCurrentMutableResource(resource, includeDescendants)
        } catch (_: StaleResourceException) {
            stale()
        }

    private fun stale(): Nothing = throw OpenCloudException(OpenCloudError.PreconditionFailed)
}
