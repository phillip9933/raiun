package eu.opencloud.android.next

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import eu.opencloud.android.next.core.sync.VaultExternalCopyMetadata
import eu.opencloud.android.next.core.sync.VaultExternalCopyStore
import java.io.FileNotFoundException

/** Read-only URI bridge for short-lived plaintext files explicitly handed to another app. */
class VaultExternalCopyProvider : ContentProvider() {
    override fun onCreate(): Boolean = true

    override fun getType(uri: Uri): String? = context?.let { app -> VaultExternalCopyStore.find(app, uri)?.mimeType }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor? =
        context?.let { app ->
            VaultExternalCopyStore.find(app, uri)?.let { metadata ->
                createCursor(projection, metadata)
            }
        }

    private fun createCursor(
        projection: Array<out String>?,
        metadata: VaultExternalCopyMetadata,
    ): Cursor? {
        val columns = projection?.toList() ?: DEFAULT_COLUMNS
        return columns
            .takeIf { requested -> requested.all { it in ALLOWED_COLUMNS } }
            ?.let { requested ->
                MatrixCursor(requested.toTypedArray()).apply {
                    addRow(
                        requested
                            .map<String, Any?> { column ->
                                when (column) {
                                    OpenableColumns.DISPLAY_NAME -> metadata.displayName
                                    OpenableColumns.SIZE -> metadata.size
                                    else -> null
                                }
                            }.toTypedArray(),
                    )
                }
            }
    }

    override fun openFile(
        uri: Uri,
        mode: String,
    ): ParcelFileDescriptor {
        if (mode != "r") throw FileNotFoundException("Export is read-only.")
        val app = context ?: throw FileNotFoundException("Export is unavailable.")
        val file = VaultExternalCopyStore.openReadOnly(app, uri) ?: throw FileNotFoundException("Export expired.")
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
    }

    override fun insert(
        uri: Uri,
        values: ContentValues?,
    ): Uri? = throw UnsupportedOperationException("Export provider is read-only.")

    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?,
    ): Int = throw UnsupportedOperationException("Export provider is read-only.")

    override fun delete(
        uri: Uri,
        selection: String?,
        selectionArgs: Array<out String>?,
    ): Int = throw UnsupportedOperationException("Export provider is read-only.")

    private companion object {
        val DEFAULT_COLUMNS = listOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)
        val ALLOWED_COLUMNS = DEFAULT_COLUMNS.toSet()
    }
}
