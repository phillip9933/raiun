package eu.opencloud.android.next.core.sync

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException

internal fun queryBackupTree(
    context: Context,
    tree: Uri,
    checkActive: () -> Unit = {},
    exclusions: BackupExclusions = BackupExclusions.parse(""),
): List<BackupDocument> {
    val result = mutableListOf<BackupDocument>()
    val pending = java.util.ArrayDeque<Pair<String, String>>()
    val traversal = BackupTraversal(tree, pending, checkActive, exclusions)
    val visited = mutableSetOf<String>()
    pending.add(DocumentsContract.getTreeDocumentId(tree) to "")
    while (pending.isNotEmpty()) {
        checkActive()
        val (id, path) = pending.removeFirst()
        requireBackupListing(visited.add(id) && visited.size <= 100_000)
        val children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, id)
        val cursor =
            context.contentResolver.query(children, BACKUP_PROJECTION, null, null, null)
                ?: throw OpenCloudException(OpenCloudError.SourceUnavailable)
        readBackupChildren(cursor, path, traversal).also { result.addAll(it) }
        requireBackupListing(result.size <= 100_000)
    }
    return result
}

private data class BackupTraversal(
    val tree: Uri,
    val pending: java.util.ArrayDeque<Pair<String, String>>,
    val checkActive: () -> Unit,
    val exclusions: BackupExclusions,
)

private fun readBackupChildren(
    cursor: android.database.Cursor,
    path: String,
    traversal: BackupTraversal,
): List<BackupDocument> {
    val result = mutableListOf<BackupDocument>()
    cursor.use {
        while (it.moveToNext()) {
            traversal.checkActive()
            val childId = it.getString(0)
            val name = validBackupName(it.getString(1))
            val mime = it.getString(2).orEmpty()
            val relative = listOf(path, name).filter(String::isNotEmpty).joinToString("/")
            val directory = mime == DocumentsContract.Document.MIME_TYPE_DIR
            val skipped =
                name.startsWith(".trashed-", true) ||
                    name.startsWith(".pending-", true) ||
                    traversal.exclusions.excludes(relative, directory)
            if (skipped) continue
            if (directory) {
                traversal.pending.add(childId to relative)
            } else {
                result +=
                    BackupDocument(
                        DocumentsContract.buildDocumentUriUsingTree(traversal.tree, childId),
                        name,
                        path,
                        mime,
                        if (it.isNull(3)) 0 else it.getLong(3),
                        if (it.isNull(4)) -1 else it.getLong(4),
                    )
                requireBackupListing(result.size <= 100_000)
            }
        }
    }
    return result
}

private fun validBackupName(name: String): String {
    requireBackupListing(name.isNotBlank() && name !in setOf(".", ".."))
    requireBackupListing(name.none { it == '/' || it == '\\' || it.isISOControl() })
    return name
}

private fun requireBackupListing(valid: Boolean) {
    if (!valid) throw OpenCloudException(OpenCloudError.InvalidResponse)
}

private val BACKUP_PROJECTION =
    arrayOf(
        DocumentsContract.Document.COLUMN_DOCUMENT_ID,
        DocumentsContract.Document.COLUMN_DISPLAY_NAME,
        DocumentsContract.Document.COLUMN_MIME_TYPE,
        DocumentsContract.Document.COLUMN_LAST_MODIFIED,
        DocumentsContract.Document.COLUMN_SIZE,
    )
