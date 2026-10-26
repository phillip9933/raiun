package eu.opencloud.android.next.core.documentsprovider

import android.content.Context
import android.database.Cursor
import android.provider.DocumentsContract.Document
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.SharedFolderEntry
import eu.opencloud.android.next.core.security.AppLock
import eu.opencloud.android.next.core.sync.SharedDownloadResolver
import eu.opencloud.android.next.core.sync.SharedFolderBrowser
import eu.opencloud.android.next.core.sync.SharedFolderPage
import eu.opencloud.android.next.core.sync.SharedFolderRequest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext

internal class SharedProviderFolders(
    context: Context,
) {
    private val app = context.applicationContext
    private val database = FileBrowserDatabase.create(app)
    private val browser = SharedFolderBrowser.create(app)
    private val resolver = SharedDownloadResolver.create(app)

    suspend fun isChild(
        parent: String,
        child: String,
    ): Boolean =
        SharedDocumentHierarchy(::node, AppLock(app).beginDocumentRead()).isChild(
            SharedDocumentId.decode(parent),
            SharedDocumentId.decode(child),
        )

    private suspend fun node(id: SharedDocumentId): SharedHierarchyNode {
        val folder = selection(id)
        if (folder != null) {
            val page = browser.refreshFolder(folder)
            return SharedHierarchyNode(folder.path, true) {
                browser.isCurrent(page) && selection(id) == folder
            }
        }
        val cache = database.sharedFolderCacheDao()
        val scope = cache.scope(id.account, id.scope) ?: unavailableSharedDocument()
        val entry = cache.entry(id.account, id.scope, id.remote) ?: unavailableSharedDocument()
        val source = resolver.prepare(id.request(scope, entry))
        return SharedHierarchyNode(source.item.path, false) {
            resolver.isCurrent(source) && cache.entry(id.account, id.scope, id.remote) == entry
        }
    }

    suspend fun query(
        encoded: String,
        columns: Array<out String>,
        children: Boolean,
    ): Cursor? {
        val permit = AppLock(app).beginDocumentRead()
        val id = SharedDocumentId.decode(encoded)
        val request = selection(id) ?: return null
        val page = browser.refreshFolder(request)
        if (!browser.isCurrent(page) || !permit()) unavailableSharedDocument()
        return if (children) {
            childrenCursor(id, request, page, columns, permit)
        } else {
            folderCursor(id, request, page, columns, permit)
        }
    }

    private fun childrenCursor(
        id: SharedDocumentId,
        request: SharedFolderRequest,
        page: SharedFolderPage,
        columns: Array<out String>,
        permit: () -> Boolean,
    ): Cursor {
        val snapshot = databaseCall { browser.captureDisplaySnapshot(page) }
        return PagedDocumentCursor(
            columns.map { it }.toTypedArray(),
            snapshot.total,
            256,
            validator(id, request, page, permit, snapshot.revision),
        ) { offset ->
            databaseCall {
                validateSelection(id, request, page, permit, snapshot.revision)
                browser
                    .displayPage(page, offset, snapshot.revision)
                    .map { item -> childRow(id, item, columns) }
                    .also { validateSelection(id, request, page, permit, snapshot.revision) }
            }
        }
    }

    private suspend fun folderCursor(
        id: SharedDocumentId,
        request: SharedFolderRequest,
        page: SharedFolderPage,
        columns: Array<out String>,
        permit: () -> Boolean,
    ): Cursor {
        val name = folderName(id, request)
        val values =
            mapOf<String, Any?>(
                Document.COLUMN_DOCUMENT_ID to id.encode(),
                Document.COLUMN_DISPLAY_NAME to name,
                Document.COLUMN_MIME_TYPE to Document.MIME_TYPE_DIR,
                Document.COLUMN_FLAGS to 0,
            )
        val row = columns.map { values[it] }.toTypedArray()
        validateLease(page, permit)
        return PagedDocumentCursor(
            columns.map { it }.toTypedArray(),
            1,
            validate = validator(id, request, page, permit),
        ) { listOf(row) }
    }

    private suspend fun folderName(
        id: SharedDocumentId,
        request: SharedFolderRequest,
    ): String =
        if (request.path == "/") {
            database.incomingShareDao().find(id.account, id.share)?.name ?: unavailableSharedDocument()
        } else {
            request.path.substringAfterLast('/')
        }

    private fun childRow(
        id: SharedDocumentId,
        item: SharedFolderEntry,
        columns: Array<out String>,
    ): Array<Any?> {
        val values =
            mapOf<String, Any?>(
                Document.COLUMN_DOCUMENT_ID to id.copy(remote = item.remoteId).encode(),
                Document.COLUMN_DISPLAY_NAME to item.name,
                Document.COLUMN_MIME_TYPE to
                    if (item.isFolder) Document.MIME_TYPE_DIR else (item.mimeType ?: "application/octet-stream"),
                Document.COLUMN_SIZE to if (item.isFolder) null else item.sizeBytes,
                Document.COLUMN_LAST_MODIFIED to item.modifiedAtEpochMillis,
                Document.COLUMN_FLAGS to 0,
            )
        return columns.map { values[it] }.toTypedArray()
    }

    private fun validator(
        id: SharedDocumentId,
        request: SharedFolderRequest,
        page: SharedFolderPage,
        permit: () -> Boolean,
        revision: Long? = null,
    ): () -> Unit = { databaseCall { validateSelection(id, request, page, permit, revision) } }

    private suspend fun validateSelection(
        id: SharedDocumentId,
        request: SharedFolderRequest,
        page: SharedFolderPage,
        permit: () -> Boolean,
        revision: Long? = null,
    ) {
        if (!permit() || !browser.isCurrent(page) || selection(id) != request) unavailableSharedDocument()
        if (revision != null && !browser.isDisplaySnapshotCurrent(page, revision)) unavailableSharedDocument()
    }

    private suspend fun validateLease(
        page: eu.opencloud.android.next.core.sync.SharedFolderPage,
        permit: () -> Boolean,
    ) {
        if (!permit() || !browser.isCurrent(page)) unavailableSharedDocument()
    }

    private fun <T> databaseCall(block: suspend () -> T): T =
        runBlocking {
            withContext(Dispatchers.IO) { block() }
        }

    private suspend fun selection(id: SharedDocumentId): SharedFolderRequest? {
        if (database.accountDao().findById(id.account)?.isActive != true) unavailableSharedDocument()
        val cache = database.sharedFolderCacheDao()
        val scope = cache.scope(id.account, id.scope) ?: unavailableSharedDocument()
        if (scope.shareId != id.share) unavailableSharedDocument()
        val path =
            if (id.remote == scope.rootItemId) {
                "/"
            } else {
                val entry = cache.entry(id.account, id.scope, id.remote) ?: unavailableSharedDocument()
                if (!entry.isFolder) return null
                entry.path
            }
        return SharedFolderRequest(id.account, id.share, id.scope, id.remote, path)
    }
}
