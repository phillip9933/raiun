package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.network.RemoteTrashResource
import eu.opencloud.android.next.core.network.TransferHttpException
import eu.opencloud.android.next.core.network.WebDavFeatureClient
import eu.opencloud.android.next.core.security.TlsPolicy
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient

class TrashManager(
    private val context: Context,
    private val store: FileBrowserStore = FileBrowserStore(FileBrowserDatabase.create(context)),
) {
    data class SpaceTrash(
        val spaceId: String,
        val name: String,
        val isPersonal: Boolean,
        val resources: List<RemoteTrashResource>,
        val supported: Boolean,
        val error: Throwable? = null,
    )

    suspend fun loadBySpace(accountId: String): List<SpaceTrash> {
        val account = requireNotNull(store.account(accountId)) { "The account is unavailable." }
        val authorization = WorkerAuthorizationProvider(context).authorization(account)
        val client = WebDavFeatureClient(httpClient(account.serverUrl))
        val spaces =
            store.spaces(accountId).filter {
                !it.isDisabled &&
                    !it.isDeleted &&
                    (it.type.equals("personal", true) || it.type.equals("project", true))
            }
        return spaces.map { space ->
            requestSpaceTrash(space, authorization, client)
        }
    }

    suspend fun loadSpace(
        accountId: String,
        spaceId: String,
    ): SpaceTrash {
        val account = requireNotNull(store.account(accountId)) { "The account is unavailable." }
        val space = requireNotNull(store.space(accountId, spaceId)) { "The space is unavailable." }
        check(!space.isDisabled && !space.isDeleted) { "The space is unavailable." }
        val authorization = WorkerAuthorizationProvider(context).authorization(account)
        val client = WebDavFeatureClient(httpClient(account.serverUrl))
        return requestSpaceTrash(space, authorization, client)
    }

    suspend fun load(
        accountId: String,
        spaceId: String,
    ): List<RemoteTrashResource>? {
        val bin = loadSpace(accountId, spaceId)
        bin.error?.let { throw it }
        return bin.resources.takeIf { bin.supported }
    }

    @Suppress("TooGenericExceptionCaught") // This is the per-space failure boundary; other bins still load.
    private fun requestSpaceTrash(
        space: SpaceEntity,
        authorization: String,
        client: WebDavFeatureClient,
    ): SpaceTrash {
        val isPersonal = space.type.equals("personal", true)
        val root = space.rootWebDavUrl ?: return SpaceTrash(space.driveId, space.name, isPersonal, emptyList(), false)
        return try {
            SpaceTrash(space.driveId, space.name, isPersonal, client.trash(root, space.driveId, authorization), true)
        } catch (cancelled: kotlinx.coroutines.CancellationException) {
            throw cancelled
        } catch (error: TransferHttpException) {
            if (error.statusCode in UNSUPPORTED_STATUS_CODES) {
                SpaceTrash(space.driveId, space.name, isPersonal, emptyList(), false)
            } else {
                SpaceTrash(space.driveId, space.name, isPersonal, emptyList(), true, error)
            }
        } catch (error: Exception) {
            SpaceTrash(space.driveId, space.name, isPersonal, emptyList(), true, error)
        }
    }

    suspend fun load(accountId: String): List<RemoteTrashResource>? {
        val account = requireNotNull(store.account(accountId)) { "The account is unavailable." }
        val authorization = WorkerAuthorizationProvider(context).authorization(account)
        val httpClient = httpClient(account.serverUrl)
        val client = WebDavFeatureClient(httpClient)
        val spaces =
            store
                .spaces(accountId)
                .filterNot { it.isDisabled || it.isDeleted }
        if (spaces.isEmpty()) return if (account.trashSupported) emptyList() else null

        var supportedEndpointFound = false
        val resources =
            spaces.flatMap { space ->
                val root = space.rootWebDavUrl ?: return@flatMap emptyList()
                try {
                    client.trash(root, space.driveId, authorization).also { supportedEndpointFound = true }
                } catch (exception: TransferHttpException) {
                    if (exception.statusCode in UNSUPPORTED_STATUS_CODES) emptyList() else throw exception
                }
            }
        return resources
            .distinctBy { "${it.spaceId}:${it.id}" }
            .sortedByDescending(RemoteTrashResource::deletedAtEpochMillis)
            .takeIf { supportedEndpointFound || account.trashSupported }
    }

    suspend fun restore(
        accountId: String,
        resource: RemoteTrashResource,
    ) {
        val account = requireNotNull(store.account(accountId)) { "The account is unavailable." }
        val space = requireNotNull(store.space(accountId, resource.spaceId)) { "The space is unavailable." }
        check(!space.isDisabled && !space.isDeleted) { "The space is unavailable." }
        store.requireAllowedVaultPath(accountId, resource.spaceId, resource.originalPath, resource.folder)
        val root = requireNotNull(space.rootWebDavUrl) { "The destination WebDAV URL is unavailable." }
        val authorization = WorkerAuthorizationProvider(context).authorization(account)
        val httpClient = httpClient(account.serverUrl)
        WebDavFeatureClient(httpClient).restore(
            root,
            resource.id,
            root.childUrl(resource.originalPath),
            authorization,
        )
        val parentPath = resource.originalPath.substringBeforeLast('/', "").ifBlank { "/" }
        val parent = store.resourceAtPath(accountId, resource.spaceId, parentPath)
        TransferManager(context, store).refreshFolder(accountId, resource.spaceId, parent?.remoteId)
    }

    suspend fun permanentlyDelete(
        accountId: String,
        resource: RemoteTrashResource,
    ) {
        val account = requireNotNull(store.account(accountId)) { "The account is unavailable." }
        val space = requireNotNull(store.space(accountId, resource.spaceId)) { "The space is unavailable." }
        check(!space.isDisabled && !space.isDeleted) { "The space is unavailable." }
        val root = requireNotNull(space.rootWebDavUrl) { "The space WebDAV URL is unavailable." }
        val authorization = WorkerAuthorizationProvider(context).authorization(account)
        val httpClient = httpClient(account.serverUrl)
        WebDavFeatureClient(httpClient).permanentlyDelete(
            root,
            resource.id,
            authorization,
        )
    }

    private fun httpClient(serverUrl: String) = TlsPolicy(context).applyTo(OkHttpClient.Builder().build(), serverUrl)

    private companion object {
        val UNSUPPORTED_STATUS_CODES = setOf(404, 405, 501)
    }
}

private fun String.childUrl(path: String): String =
    toHttpUrl()
        .newBuilder()
        .apply {
            path
                .trim('/')
                .split('/')
                .filter(String::isNotBlank)
                .forEach(::addPathSegment)
        }.build()
        .toString()
