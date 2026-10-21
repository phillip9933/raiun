package eu.opencloud.android.next.core.documentsprovider

import android.content.Context
import android.database.Cursor
import android.database.MatrixCursor
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract.Document
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.security.AppLock
import eu.opencloud.android.next.core.sync.SharedDownloadRequest
import eu.opencloud.android.next.core.sync.SharedDownloadResolver

/** File-only routing; shared folder enumeration remains separate and must never fall back to ordinary spaces. */
internal class SharedProviderFiles(
    context: Context,
) {
    private val app = context.applicationContext
    private val database = FileBrowserDatabase.create(app)
    private val resolver = SharedDownloadResolver.create(app)
    private val reads = SharedDocumentReads.create(app)
    private val folders = SharedProviderFolders(app)

    suspend fun query(
        encoded: String,
        columns: Array<out String>,
    ): Cursor {
        folders.query(encoded, columns, children = false)?.let { return it }
        val permit = AppLock(app).beginDocumentRead()
        val source = resolver.prepare(request(encoded))
        if (!resolver.isCurrent(source) || !permit()) unavailableSharedDocument()
        val values =
            mapOf<String, Any?>(
                Document.COLUMN_DOCUMENT_ID to encoded,
                Document.COLUMN_DISPLAY_NAME to source.item.name,
                Document.COLUMN_MIME_TYPE to (source.item.mimeType ?: "application/octet-stream"),
                Document.COLUMN_SIZE to source.item.size,
                Document.COLUMN_LAST_MODIFIED to source.item.modifiedAtEpochMillis,
                Document.COLUMN_FLAGS to 0,
            )
        return MatrixCursor(columns).apply { addRow(columns.map { values[it] }.toTypedArray()) }
    }

    suspend fun open(
        encoded: String,
        mode: String,
        signal: CancellationSignal?,
    ): ParcelFileDescriptor {
        if (mode != "r") unavailableSharedDocument()
        signal?.throwIfCanceled()
        return reads.open(request(encoded), signal)
    }

    suspend fun children(
        encoded: String,
        columns: Array<out String>,
    ): Cursor = folders.query(encoded, columns, children = true) ?: unavailableSharedDocument()

    suspend fun childRelation(
        parent: String,
        child: String,
    ): Boolean? {
        val parentShared = SharedDocumentId.recognizes(parent)
        val childShared = SharedDocumentId.recognizes(child)
        if (!parentShared && !childShared) return null
        return parentShared && childShared && folders.isChild(parent, child)
    }

    private suspend fun request(encoded: String): SharedDownloadRequest {
        val id = SharedDocumentId.decode(encoded)
        if (!AppLock(app).canOpenDocuments() || database.accountDao().findById(id.account)?.isActive != true) {
            unavailableSharedDocument()
        }
        val cache = database.sharedFolderCacheDao()
        val scope = cache.scope(id.account, id.scope) ?: unavailableSharedDocument()
        val entry = cache.entry(id.account, id.scope, id.remote) ?: unavailableSharedDocument()
        return id.request(scope, entry)
    }
}
