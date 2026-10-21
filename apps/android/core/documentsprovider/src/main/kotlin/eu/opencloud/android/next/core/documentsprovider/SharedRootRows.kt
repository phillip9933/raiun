package eu.opencloud.android.next.core.documentsprovider

import android.content.Context
import android.database.Cursor
import android.database.MatrixCursor
import android.os.Bundle
import android.provider.DocumentsContract
import android.provider.DocumentsContract.Document
import eu.opencloud.android.next.core.security.AppLock
import eu.opencloud.android.next.core.sync.SharedRootDiscovery

internal data class SharedRootRow(
    val id: SharedDocumentId,
    val name: String,
)

internal class SharedRootListing(
    val roots: List<SharedRootRow>,
    val unavailableCount: Int,
    val current: suspend () -> Boolean,
)

/** Builds directory rows only from a checked catalog. It does not turn unresolved shares into navigable folders. */
internal class SharedRootRows(
    private val load: suspend (String) -> SharedRootListing,
    private val grant: () -> (() -> Boolean),
) {
    suspend fun query(
        account: String,
        columns: Array<out String>,
    ): Cursor {
        val permit = grant()
        if (!permit()) unavailableSharedDocument()
        val listing = load(account)
        validate(account, listing)
        if (!listing.current() || !permit()) unavailableSharedDocument()
        val cursor = MatrixCursor(columns)
        listing.roots.forEach { root ->
            val values =
                mapOf<String, Any?>(
                    Document.COLUMN_DOCUMENT_ID to root.id.encode(),
                    Document.COLUMN_DISPLAY_NAME to root.name,
                    Document.COLUMN_MIME_TYPE to Document.MIME_TYPE_DIR,
                    Document.COLUMN_FLAGS to 0,
                )
            cursor.addRow(columns.map { values[it] }.toTypedArray())
        }
        if (listing.unavailableCount > 0) {
            cursor.extras =
                Bundle().apply {
                    putString(DocumentsContract.EXTRA_ERROR, "Some shared folders are currently unavailable.")
                }
        }
        if (!listing.current() || !permit()) {
            cursor.close()
            unavailableSharedDocument()
        }
        return cursor
    }

    private fun validate(
        account: String,
        listing: SharedRootListing,
    ) {
        val unique =
            listing.roots
                .map { it.id }
                .toSet()
                .size == listing.roots.size
        val valid = listing.roots.all { it.id.account == account && it.name.isNotBlank() }
        if (!unique || !valid || listing.unavailableCount < 0) unavailableSharedDocument()
    }

    companion object {
        fun create(context: Context): SharedRootRows {
            val app = context.applicationContext
            val discovery = SharedRootDiscovery.create(app)
            return SharedRootRows({ account ->
                val catalog = discovery.discover(account)
                val roots =
                    catalog.roots.map {
                        SharedRootRow(SharedDocumentId(it.accountId, it.shareId, it.scopeId, it.rootItemId), it.name)
                    }
                SharedRootListing(roots, catalog.unavailable.size) { discovery.isCurrent(catalog) }
            }, { AppLock(app).beginDocumentRead() })
        }
    }
}
