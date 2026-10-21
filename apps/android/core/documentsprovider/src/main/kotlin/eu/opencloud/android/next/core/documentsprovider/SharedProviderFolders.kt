package eu.opencloud.android.next.core.documentsprovider

import android.content.Context
import android.database.Cursor
import android.database.MatrixCursor
import android.provider.DocumentsContract.Document
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.security.AppLock
import eu.opencloud.android.next.core.sync.SharedDownloadResolver
import eu.opencloud.android.next.core.sync.SharedFolderBrowser
import eu.opencloud.android.next.core.sync.SharedFolderRequest

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
            val page = browser.openFolder(folder)
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
        val page = browser.openFolder(request)
        if (!browser.isCurrent(page) || !permit()) unavailableSharedDocument()
        return MatrixCursor(columns).apply {
            if (children) {
                page.items.forEach { item ->
                    val values =
                        mapOf<String, Any?>(
                            Document.COLUMN_DOCUMENT_ID to id.copy(remote = item.id).encode(),
                            Document.COLUMN_DISPLAY_NAME to item.name,
                            Document.COLUMN_MIME_TYPE to
                                if (item.folder) {
                                    Document.MIME_TYPE_DIR
                                } else {
                                    (item.mimeType ?: "application/octet-stream")
                                },
                            Document.COLUMN_SIZE to if (item.folder) null else item.size,
                            Document.COLUMN_LAST_MODIFIED to item.modifiedAtEpochMillis,
                            Document.COLUMN_FLAGS to 0,
                        )
                    addRow(columns.map { values[it] }.toTypedArray())
                }
            } else {
                val name =
                    if (request.path == "/") {
                        database.incomingShareDao().find(id.account, id.share)?.name ?: unavailableSharedDocument()
                    } else {
                        request.path.substringAfterLast('/')
                    }
                val values =
                    mapOf<String, Any?>(
                        Document.COLUMN_DOCUMENT_ID to encoded,
                        Document.COLUMN_DISPLAY_NAME to name,
                        Document.COLUMN_MIME_TYPE to Document.MIME_TYPE_DIR,
                        Document.COLUMN_FLAGS to 0,
                    )
                addRow(columns.map { values[it] }.toTypedArray())
            }
            if (!browser.isCurrent(page) || !permit()) unavailableSharedDocument()
        }
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
