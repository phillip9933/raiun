package eu.opencloud.android.next.core.database

import androidx.sqlite.db.SupportSQLiteDatabase

/** A cursor pins both its row count and the cache generation it reads. */
data class SharedFolderDisplaySnapshot(
    val total: Int,
    val revision: Long,
)

/** Connection-local bookkeeping; revisions roll back with the page-marker transaction. */
internal fun ensureSharedFolderPageRevisionTracking(database: SupportSQLiteDatabase) {
    database.execSQL(
        "CREATE TEMP TABLE IF NOT EXISTS raiun_shared_folder_page_revisions (" +
            "accountId TEXT NOT NULL, scopeId TEXT NOT NULL, path TEXT NOT NULL, revision INTEGER NOT NULL, " +
            "PRIMARY KEY(accountId, scopeId, path))",
    )
    // Room replaces page markers. Its outer REPLACE policy can override trigger INSERT OR IGNORE,
    // so seed absent counters with a predicate rather than a conflicting insert.
    database.execSQL(
        "CREATE TEMP TRIGGER IF NOT EXISTS raiun_shared_folder_page_revision_insert " +
            "AFTER INSERT ON main.shared_folder_pages BEGIN " +
            "INSERT INTO raiun_shared_folder_page_revisions(accountId, scopeId, path, revision) " +
            "SELECT NEW.accountId, NEW.scopeId, NEW.path, 0 WHERE NOT EXISTS (" +
            "SELECT 1 FROM raiun_shared_folder_page_revisions WHERE accountId = NEW.accountId " +
            "AND scopeId = NEW.scopeId AND path = NEW.path); " +
            "UPDATE raiun_shared_folder_page_revisions SET revision = revision + 1 " +
            "WHERE accountId = NEW.accountId AND scopeId = NEW.scopeId AND path = NEW.path; END",
    )
}

internal fun ensureSharedFolderPageRevision(
    database: SupportSQLiteDatabase,
    accountId: String,
    scopeId: String,
    path: String,
) {
    ensureSharedFolderPageRevisionTracking(database)
    database.execSQL(
        "INSERT OR IGNORE INTO temp.raiun_shared_folder_page_revisions(accountId, scopeId, path, revision) " +
            "SELECT accountId, scopeId, path, 0 FROM main.shared_folder_pages " +
            "WHERE accountId = ? AND scopeId = ? AND path = ?",
        arrayOf(accountId, scopeId, path),
    )
}

internal fun readSharedFolderPageRevision(
    database: SupportSQLiteDatabase,
    accountId: String,
    scopeId: String,
    path: String,
): Long? =
    database
        .query(
            "SELECT revision FROM temp.raiun_shared_folder_page_revisions " +
                "WHERE accountId = ? AND scopeId = ? AND path = ?",
            arrayOf(accountId, scopeId, path),
        ).use { cursor ->
            if (cursor.moveToFirst()) cursor.getLong(0) else null
        }
