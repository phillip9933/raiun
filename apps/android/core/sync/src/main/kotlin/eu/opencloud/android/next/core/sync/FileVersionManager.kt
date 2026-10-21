package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.network.FileVersionsClient
import eu.opencloud.android.next.core.network.RemoteFileVersion
import eu.opencloud.android.next.core.security.AppLock
import eu.opencloud.android.next.core.security.TlsPolicy
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import java.util.concurrent.TimeUnit

class FileVersionManager(
    private val context: Context,
    private val store: FileBrowserStore = FileBrowserStore(FileBrowserDatabase.create(context)),
) {
    suspend fun list(resource: ResourceEntity): List<RemoteFileVersion> {
        val allowed = AppLock(context).beginAppAction()
        val current = checked(resource)
        val account = requireNotNull(store.account(current.accountId))
        val root = webDavRoot(requireNotNull(store.space(current.accountId, current.spaceId)))
        val authorization = WorkerAuthorizationProvider(context).authorization(account)
        check(allowed())
        return client(account.serverUrl).list(root, current.remoteId, authorization).also {
            check(allowed())
            checked(current)
        }
    }

    suspend fun restore(
        resource: ResourceEntity,
        version: RemoteFileVersion,
    ) = ProviderFolderOperations.namespaceGate.withLock {
        val allowed = AppLock(context).beginAppAction()
        val current = checked(resource)
        requireNoPendingWrites(current)
        ProviderFolderOperations(context, store).refresh(current.accountId, current.spaceId, current.parentId, allowed)
        checked(current)
        val account = requireNotNull(store.account(current.accountId))
        val root = webDavRoot(requireNotNull(store.space(current.accountId, current.spaceId)))
        val authorization = WorkerAuthorizationProvider(context).authorization(account)
        val client = client(account.serverUrl)
        check(client.list(root, current.remoteId, authorization).any { it.id == version.id })
        checked(current)
        requireNoPendingWrites(current)
        check(allowed())
        // A cancelled screen must not skip cache invalidation after a possibly committed server request.
        withContext(NonCancellable) {
            try {
                client.restore(
                    root,
                    current.remoteId,
                    version.id,
                    root.mutationChildUrl(current.path),
                    requireNotNull(current.eTag),
                    authorization,
                )
            } finally {
                store.invalidateFileContent(current)
                TransferManager(context, store).refreshFolder(current.accountId, current.spaceId, current.parentId)
            }
        }
    }

    private suspend fun checked(resource: ResourceEntity): ResourceEntity {
        require(resource.kind == ResourceKind.FILE)
        val space = requireNotNull(store.space(resource.accountId, resource.spaceId))
        require(space.type in setOf("personal", "project"))
        return store.requireCurrentMutableResource(resource, false)
    }

    private suspend fun requireNoPendingWrites(resource: ResourceEntity) {
        val inventory = DocumentEditStore(context).inventory(resource.accountId)
        check(
            inventory.unreadableCount == 0 &&
                inventory.edits.none {
                    it.spaceId == resource.spaceId && it.resourceId == resource.remoteId
                },
        ) { "Finish or recover pending edits before restoring." }
        check(
            store.activeTransfers(resource.accountId).none {
                it.spaceId == resource.spaceId &&
                    it.destinationPath == resource.path &&
                    it.direction == "UPLOAD" &&
                    it.state !in setOf("SUCCEEDED", "CANCELLED")
            },
        ) { "Finish or cancel pending uploads before restoring." }
    }

    private fun client(server: String) =
        FileVersionsClient(
            TlsPolicy(context).applyTo(OkHttpClient.Builder().callTimeout(30, TimeUnit.SECONDS).build(), server),
        )
}
