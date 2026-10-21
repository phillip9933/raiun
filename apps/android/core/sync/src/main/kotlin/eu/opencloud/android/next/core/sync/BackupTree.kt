package eu.opencloud.android.next.core.sync

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException

/** Files are delivered in bounded batches; a normal return means every included directory was read. */
internal suspend fun scanBackupTree(
    context: Context,
    tree: Uri,
    checkActive: () -> Unit = {},
    exclusions: BackupExclusions = BackupExclusions.parse(""),
    onBatch: suspend (List<BackupDocument>) -> Unit,
) {
    BackupDirectoryQueue(context).use { pending ->
        val traversal = BackupTraversal(tree, pending, checkActive, exclusions, onBatch)
        pending.add(DocumentsContract.getTreeDocumentId(tree), "")
        while (true) {
            checkActive()
            val (id, path) = pending.take() ?: break
            val children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, id)
            val cursor =
                context.contentResolver.query(children, BACKUP_PROJECTION, null, null, null)
                    ?: throw OpenCloudException(OpenCloudError.SourceUnavailable)
            readBackupChildren(cursor, path, traversal)
        }
    }
}

private data class BackupTraversal(
    val tree: Uri,
    val pending: BackupDirectoryQueue,
    val checkActive: () -> Unit,
    val exclusions: BackupExclusions,
    val onBatch: suspend (List<BackupDocument>) -> Unit,
)

private suspend fun readBackupChildren(
    cursor: android.database.Cursor,
    path: String,
    traversal: BackupTraversal,
) {
    val result = mutableListOf<BackupDocument>()
    cursor.use {
        requireCompleteBackupCursor(it)
        while (it.moveToNext()) {
            traversal.checkActive()
            val document = readBackupChild(it, path, traversal) ?: continue
            result += document
            if (result.size == BACKUP_BATCH_SIZE) deliverBackupBatch(result, traversal)
        }
        requireCompleteBackupCursor(it)
    }
    if (result.isNotEmpty()) traversal.onBatch(result.toList())
}

private fun requireCompleteBackupCursor(cursor: android.database.Cursor) {
    val extras = cursor.extras
    if (extras.getBoolean(DocumentsContract.EXTRA_LOADING, false) ||
        extras.containsKey(DocumentsContract.EXTRA_ERROR)
    ) {
        throw OpenCloudException(OpenCloudError.SourceUnavailable)
    }
}

private fun readBackupChild(
    cursor: android.database.Cursor,
    path: String,
    traversal: BackupTraversal,
): BackupDocument? {
    val childId = cursor.getString(0)
    val name = validBackupName(cursor.getString(1))
    val mime = cursor.getString(2).orEmpty()
    val relative = listOf(path, name).filter(String::isNotEmpty).joinToString("/")
    val directory = mime == DocumentsContract.Document.MIME_TYPE_DIR
    val skipped =
        name.startsWith(".trashed-", true) ||
            name.startsWith(".pending-", true) ||
            traversal.exclusions.excludes(relative, directory)
    return when {
        skipped -> null
        directory -> {
            traversal.pending.add(childId, relative)
            null
        }
        else ->
            BackupDocument(
                DocumentsContract.buildDocumentUriUsingTree(traversal.tree, childId),
                name,
                path,
                mime,
                if (cursor.isNull(3)) 0 else cursor.getLong(3),
                if (cursor.isNull(4)) -1 else cursor.getLong(4),
            )
    }
}

private suspend fun deliverBackupBatch(
    result: MutableList<BackupDocument>,
    traversal: BackupTraversal,
) {
    traversal.onBatch(result.toList())
    result.clear()
}

private fun validBackupName(name: String): String {
    requireBackupListing(name.isNotBlank() && name !in setOf(".", ".."))
    requireBackupListing(name.none { it == '/' || it == '\\' || it.isISOControl() })
    return name
}

private fun requireBackupListing(valid: Boolean) {
    if (!valid) throw OpenCloudException(OpenCloudError.InvalidResponse)
}

internal const val BACKUP_BATCH_SIZE = 256

private val BACKUP_PROJECTION =
    arrayOf(
        DocumentsContract.Document.COLUMN_DOCUMENT_ID,
        DocumentsContract.Document.COLUMN_DISPLAY_NAME,
        DocumentsContract.Document.COLUMN_MIME_TYPE,
        DocumentsContract.Document.COLUMN_LAST_MODIFIED,
        DocumentsContract.Document.COLUMN_SIZE,
    )
