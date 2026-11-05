package eu.opencloud.android.next.ui

import android.app.Application
import android.content.ContentResolver
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.system.StructPollfd
import eu.opencloud.android.next.core.security.VaultIdentity
import eu.opencloud.android.next.core.sync.VaultFolder
import eu.opencloud.android.next.core.sync.withCancellableVaultUploadSource
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.withContext

/** Session admission, action leases and failure policy remain with the route. */
internal interface VaultPickedTransferOwner {
    fun isCurrent(
        opened: VaultRouteSession,
        token: Long,
        account: String,
    ): Boolean

    fun isCurrentTransferSession(
        opened: VaultRouteSession,
        identity: VaultIdentity,
        token: Long,
        account: String,
    ): Boolean

    suspend fun verifyUploadDirectory(
        opened: VaultRouteSession,
        path: String,
    )

    suspend fun revalidateExportSource(
        opened: VaultRouteSession,
        path: String,
        request: PendingVaultTransfer.Export,
    ): VaultFolder

    suspend fun publishTransferListing(
        opened: VaultRouteSession,
        path: String,
        token: Long,
        account: String,
    )
}

/** Executes a consumed picker request without owning the route, session, key or job. */
internal class VaultPickedTransferExecution(
    private val application: Application,
    private val ioDispatcher: CoroutineDispatcher,
    private val uploadPollReady: (StructPollfd, Int) -> Boolean,
    private val state: MutableStateFlow<VaultRouteState>,
    private val owner: VaultPickedTransferOwner,
) {
    suspend fun exportWithCleanup(
        opened: VaultRouteSession,
        request: PendingVaultTransfer.Export,
        token: Long,
        account: String,
    ) {
        var completed = false
        try {
            exportPicked(opened, request, token, account)
            completed = true
        } finally {
            if (!completed) discardIncompleteExport(requireNotNull(request.uri))
        }
    }

    private suspend fun discardIncompleteExport(uri: Uri) {
        withContext(NonCancellable + ioDispatcher) {
            // ACTION_CREATE_DOCUMENT creates a new destination. A provider may refuse deletion;
            // the export error deliberately still tells the user to check for an incomplete copy.
            runCatching { DocumentsContract.deleteDocument(application.contentResolver, uri) }
        }
    }

    suspend fun uploadPicked(
        opened: VaultRouteSession,
        request: PendingVaultTransfer.Upload,
        token: Long,
        account: String,
    ) {
        val uri = requireNotNull(request.uri)
        val parentPath = opened.decodeDirectoryPath(request.encryptedParentPath)
        val resolver = application.contentResolver
        val metadata = withContext(ioDispatcher) { readDocumentMetadata(resolver, uri) }
        if (!owner.isCurrentTransferSession(opened, request.identity, token, account)) return
        owner.verifyUploadDirectory(opened, parentPath)
        if (!owner.isCurrentTransferSession(opened, request.identity, token, account)) return
        state.value = state.value.copy(preparingUpload = true)
        try {
            withContext(ioDispatcher) {
                withCancellableVaultUploadSource(application, uri, uploadPollReady) { source ->
                    opened.queueUpload(
                        parentPath,
                        metadata.name,
                        source,
                        metadata.size?.takeIf { it >= 0 } ?: -1L,
                        metadata.mimeType,
                    )
                }
            }
            if (owner.isCurrent(opened, token, account)) {
                state.value =
                    state.value.copy(queuedUploadCount = state.value.queuedUploadCount + 1)
            }
        } finally {
            if (owner.isCurrent(opened, token, account)) {
                state.value = state.value.copy(preparingUpload = false)
            }
        }
        owner.publishTransferListing(opened, parentPath, token, account)
    }

    // Reject identity, size and destination failures before exposing plaintext.
    @Suppress("ThrowsCount")
    private suspend fun exportPicked(
        opened: VaultRouteSession,
        request: PendingVaultTransfer.Export,
        token: Long,
        account: String,
    ) {
        val uri = requireNotNull(request.uri)
        val parentPath = opened.decodeDirectoryPath(request.encryptedParentPath)
        val source = owner.revalidateExportSource(opened, parentPath, request)
        if (!owner.isCurrentTransferSession(opened, request.identity, token, account)) return
        val resolver = application.contentResolver
        withContext(ioDispatcher) {
            resolver.openOutputStream(uri, "wt")?.use { sink ->
                opened.download(source, sink, Long.MAX_VALUE)
            } ?: error("The selected destination is unavailable.")
        }
        owner.publishTransferListing(opened, parentPath, token, account)
    }
}

internal sealed class PendingVaultTransfer(
    open val identity: VaultIdentity,
    open val uri: Uri?,
) {
    data class Upload(
        override val identity: VaultIdentity,
        val encryptedParentPath: String,
        override val uri: Uri? = null,
    ) : PendingVaultTransfer(identity, uri)

    data class Export(
        override val identity: VaultIdentity,
        val encryptedParentPath: String,
        val id: String,
        val encryptedPath: String,
        val strongETag: String?,
        val observedSize: Long,
        override val uri: Uri? = null,
    ) : PendingVaultTransfer(identity, uri)

    fun withUri(value: Uri): PendingVaultTransfer =
        when (this) {
            is Upload -> copy(uri = value)
            is Export -> copy(uri = value)
        }
}

private data class VaultDocumentMetadata(
    val name: String,
    val size: Long?,
    val mimeType: String?,
)

private fun readDocumentMetadata(
    resolver: ContentResolver,
    uri: Uri,
): VaultDocumentMetadata {
    var name: String? = null
    var size: Long? = null
    resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { cursor ->
        if (cursor.moveToFirst()) {
            val nameColumn = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (nameColumn >= 0) name = cursor.getString(nameColumn)
            val sizeColumn = cursor.getColumnIndex(OpenableColumns.SIZE)
            if (sizeColumn >= 0 && !cursor.isNull(sizeColumn)) size = cursor.getLong(sizeColumn)
        }
    }
    return VaultDocumentMetadata(
        name = name?.takeIf(String::isNotBlank) ?: "upload",
        size = size,
        mimeType = resolver.getType(uri),
    )
}
