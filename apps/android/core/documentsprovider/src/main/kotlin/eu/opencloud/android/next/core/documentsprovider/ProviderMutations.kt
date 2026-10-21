package eu.opencloud.android.next.core.documentsprovider

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.sync.ProviderFolderOperations
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import java.io.FileNotFoundException

internal class ProviderMutations(
    private val context: Context,
    private val store: FileBrowserStore,
    private val folders: ProviderFolderOperations,
    private val requireUnlocked: () -> Unit,
    private val requireAvailable: suspend (DocumentId) -> Unit,
) {
    fun createDocument(
        parentDocumentId: String,
        mimeType: String,
        displayName: String,
    ): String =
        databaseCall {
            requireUnlocked()
            val parent = DocumentId.decode(parentDocumentId)
            requireAvailable(parent)
            val created =
                when (parent) {
                    is DocumentId.Account -> throw FileNotFoundException(
                        "Choose a folder inside Personal files or a Space.",
                    )
                    is DocumentId.Space ->
                        folders.create(
                            parent.accountId,
                            parent.spaceId,
                            null,
                            displayName,
                            mimeType,
                            documentPermit(),
                        )
                    is DocumentId.Resource ->
                        folders.create(
                            parent.accountId,
                            parent.spaceId,
                            parent.resourceId,
                            displayName,
                            mimeType,
                            documentPermit(),
                        )
                }
            notifyFolder(parentDocumentId)
            DocumentId.Resource(created.accountId, created.spaceId, created.remoteId).encode()
        }

    fun renameDocument(
        documentId: String,
        displayName: String,
    ): String =
        databaseCall {
            val resource = mutableDocument(documentId)
            val renamed = folders.rename(resource, displayName, documentPermit())
            notifyFolder(parentDocumentId(resource))
            DocumentId.Resource(renamed.accountId, renamed.spaceId, renamed.remoteId).encode()
        }

    fun deleteDocument(documentId: String) =
        databaseCall {
            val resource = mutableDocument(documentId)
            folders.delete(resource, documentPermit())
            notifyFolder(parentDocumentId(resource))
        }

    private suspend fun mutableDocument(documentId: String): ResourceEntity {
        requireUnlocked()
        val id = DocumentId.decode(documentId) as? DocumentId.Resource ?: throw FileNotFoundException("Choose a file.")
        requireAvailable(id)
        return requireNotNull(store.resource(id.accountId, id.spaceId, id.resourceId))
    }

    private fun parentDocumentId(resource: ResourceEntity): String =
        resource.parentId?.let {
            DocumentId.Resource(resource.accountId, resource.spaceId, it).encode()
        } ?: DocumentId.Space(resource.accountId, resource.spaceId).encode()

    private fun documentPermit(): () -> Boolean =
        eu.opencloud.android.next.core.security
            .AppLock(requireNotNull(context))
            .beginDocumentEdit()

    private fun notifyFolder(documentId: String) {
        val owner = requireNotNull(context)
        val authority = "${owner.packageName}.documents"
        owner.contentResolver.notifyChange(
            android.provider.DocumentsContract.buildChildDocumentsUri(authority, documentId),
            null,
        )
        owner.contentResolver.notifyChange(
            android.provider.DocumentsContract.buildDocumentUri(authority, documentId),
            null,
        )
    }

    private fun <T> databaseCall(block: suspend () -> T): T = runBlocking { withContext(Dispatchers.IO) { block() } }
}
