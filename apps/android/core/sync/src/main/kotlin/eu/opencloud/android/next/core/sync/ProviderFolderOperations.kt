package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.network.DavOperationClient
import eu.opencloud.android.next.core.network.RemoteDiscoveryClient
import eu.opencloud.android.next.core.network.TransferClient
import eu.opencloud.android.next.core.network.WebDavFeatureClient
import eu.opencloud.android.next.core.security.TlsPolicy
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import okhttp3.OkHttpClient
import java.io.FileNotFoundException
import java.util.concurrent.TimeUnit

/** Online namespace operations for SAF. Never return a synthetic ID or overwrite an existing child. */
class ProviderFolderOperations(
    private val context: Context,
    private val store: FileBrowserStore,
    private val authorization: suspend (
        AccountEntity,
    ) -> String = { WorkerAuthorizationProvider(context).authorization(it) },
    private val client: (String) -> OkHttpClient = {
        TlsPolicy(context).applyTo(OkHttpClient.Builder().callTimeout(30, TimeUnit.SECONDS).build(), it)
    },
) {
    private val drafts = DocumentEditStore(context)

    suspend fun refresh(
        accountId: String,
        spaceId: String,
        parentId: String?,
        allowed: () -> Boolean,
    ) {
        check(allowed()) { "Document access is locked." }
        val account = requireNotNull(store.account(accountId)?.takeIf { it.isActive })
        val space = requireNotNull(store.space(accountId, spaceId))
        val parent = parentId?.let { requireNotNull(store.resource(accountId, spaceId, it)) }
        require(parent == null || parent.kind == ResourceKind.FOLDER)
        store.requireAllowedVaultPath(accountId, spaceId, parent?.path ?: "/")
        val token = authorization(account)
        check(allowed()) { "Document access is locked." }
        refreshFolder(
            FolderRefresh(
                store,
                RemoteDiscoveryClient(client(account.serverUrl)),
                accountId,
                space,
                parentId,
                parent?.path ?: "/",
                token,
            ),
        )
        check(allowed() && store.account(accountId)?.isActive == true) { "Document access was revoked." }
    }

    @Suppress("LongParameterList") // Explicit SAF parent identity, content type and access lease.
    suspend fun create(
        accountId: String,
        spaceId: String,
        parentId: String?,
        name: String,
        mimeType: String,
        allowed: () -> Boolean,
    ): ResourceEntity =
        namespaceGate.withLock {
            val safeName = name.requireValidSegment()
            refresh(accountId, spaceId, parentId, allowed)
            check(
                store.children(accountId, spaceId, parentId).none {
                    it.name == safeName
                },
            ) { "A document with that name already exists." }
            val account = requireNotNull(store.account(accountId)?.takeIf { it.isActive })
            val space = requireNotNull(store.space(accountId, spaceId))
            val parent = parentId?.let { requireNotNull(store.resource(accountId, spaceId, it)) }
            val path = "${parent?.path?.trimEnd('/').orEmpty()}/$safeName"
            store.requireAllowedFolderDestination(accountId, spaceId, parentId, parent?.path, path)
            val http = client(account.serverUrl)
            val token = authorization(account)
            check(allowed()) { "Document access is locked." }
            store.requireAllowedFolderDestination(accountId, spaceId, parentId, parent?.path, path)
            val url = webDavRoot(space).mutationChildUrl(path)
            val createdVersion =
                if (mimeType == "vnd.android.document/directory") {
                    // Unlike recursive backup MKCOL, SAF creation must not adopt somebody else's existing folder.
                    TransferClient(http).createCollection(url, token, acceptExisting = false)
                    null
                } else {
                    TransferClient(http).upload(url, token, mimeType, 0, false, { byteArrayOf().inputStream() }) {}
                }
            refresh(accountId, spaceId, parentId, allowed)
            val created =
                store.children(accountId, spaceId, parentId).singleOrNull { it.name == safeName }
                    ?: throw FileNotFoundException(
                        "The server has not confirmed the new document. Refresh before retrying.",
                    )
            if (mimeType != "vnd.android.document/directory") {
                check(created.kind == ResourceKind.FILE && created.sizeBytes == 0L && created.eTag == createdVersion) {
                    "The newly created file changed. Refresh before retrying."
                }
                check(
                    eu.opencloud.android.next.core.network
                        .DownloadExpectation(0, createdVersion)
                        .strongETag != null,
                ) {
                    "The server did not return a safe version for editing this file."
                }
            }
            created
        }

    suspend fun rename(
        resource: ResourceEntity,
        name: String,
        allowed: () -> Boolean,
    ): ResourceEntity =
        namespaceGate.withLock {
            require(resource.kind == ResourceKind.FILE) { "Folder rename is not supported." }
            val safeName = name.requireValidSegment()
            val current = settled(resource, allowed)
            if (safeName == current.name) return@withLock current
            val account = requireNotNull(store.account(current.accountId))
            val space = requireNotNull(store.space(current.accountId, current.spaceId))
            val destination = "${current.path.substringBeforeLast('/', "")}/$safeName"
            store.requireAllowedVaultPath(current.accountId, current.spaceId, destination)
            val token = authorization(account)
            check(allowed()) { "Document access is locked." }
            store.requireCurrentMutableResource(current, false)
            WebDavFeatureClient(
                client(account.serverUrl),
            ).renameFile(webDavRoot(space).mutationChildUrl(current.path), safeName, current.eTag, token)
            refresh(current.accountId, current.spaceId, current.parentId, allowed)
            store.children(current.accountId, current.spaceId, current.parentId).singleOrNull { it.name == safeName }
                ?: throw FileNotFoundException("The server has not confirmed the renamed document.")
        }

    suspend fun delete(
        resource: ResourceEntity,
        allowed: () -> Boolean,
    ) = namespaceGate.withLock {
        // Restrict this first version to file retention; recursive folder removal needs subtree writer coordination.
        require(resource.kind == ResourceKind.FILE) { "Folder deletion is not supported." }
        val current = settled(resource, allowed)
        val account = requireNotNull(store.account(current.accountId))
        val space = requireNotNull(store.space(current.accountId, current.spaceId))
        val token = authorization(account)
        check(allowed()) { "Document access is locked." }
        store.requireCurrentMutableResource(current, false)
        DavOperationClient(
            client(account.serverUrl),
        ).deleteVerifiedSource(webDavRoot(space).mutationChildUrl(current.path), requireNotNull(current.eTag), token)
        store.delete(current.accountId, current.spaceId, current.remoteId)
    }

    /** Do not rename/delete/read an old remote version while a closed descriptor is still being uploaded. */
    suspend fun settled(
        resource: ResourceEntity,
        allowed: () -> Boolean,
    ): ResourceEntity {
        var hadPendingWrite = false
        awaitProviderWrites(
            pending = {
                val inventory = drafts.inventory(resource.accountId)
                check(inventory.unreadableCount == 0) { "Recover unreadable document edits in Raiun first." }
                inventory.edits
                    .filter {
                        it.spaceId == resource.spaceId &&
                            it.resourceId == resource.remoteId
                    }.also { if (it.isNotEmpty()) hadPendingWrite = true }
            },
            transferState = { store.transfer(it)?.state },
            allowed = allowed,
            reconcile = { DocumentEditReconciler(context, store).reconcile(resource.accountId) },
        )
        check(allowed()) { "Document access is locked." }
        if (hadPendingWrite) refresh(resource.accountId, resource.spaceId, resource.parentId, allowed)
        val current = requireNotNull(store.resource(resource.accountId, resource.spaceId, resource.remoteId))
        check(current.path == resource.path) { "The document moved. Select it again." }
        return store.requireCurrentMutableResource(
            current,
            false,
        )
    }

    companion object {
        // A provider descriptor must reserve its journal under the same gate as namespace mutations.
        val namespaceGate = Mutex()
    }
}

internal suspend fun awaitProviderWrites(
    pending: suspend () -> List<DocumentEdit>,
    transferState: suspend (String) -> String?,
    allowed: () -> Boolean,
    reconcile: suspend () -> Unit,
) = withTimeout(30_000L) {
    while (true) {
        check(allowed()) { "Document access is locked." }
        val edits = pending()
        if (edits.isEmpty()) return@withTimeout
        edits.forEach { edit ->
            check(edit.state != DocumentEditState.REVIEW) { "Recover this file in Raiun before continuing." }
            if (edit.state == DocumentEditState.SUBMITTED) {
                check(transferState(edit.id) in setOf("QUEUED", "RUNNING", "RETRY", "SUCCEEDED")) {
                    "The file has not uploaded. Check Transfers in Raiun."
                }
            }
        }
        reconcile()
        delay(100)
    }
}
