package eu.opencloud.android.next.core.sync

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteException
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import java.io.Closeable
import java.io.IOException

/** Private disposable traversal state. IDs remain on disk after dequeue to reject cycles.
 * Constructor failures, including cancellation, must release private traversal files.
 */
@Suppress("TooGenericExceptionCaught")
internal class BackupDirectoryQueue(
    context: Context,
) : Closeable {
    private val temporary = localStorage { BackupTraversalFile(context) }
    private val database =
        try {
            localStorage {
                SQLiteDatabase.openOrCreateDatabase(temporary.file, null).also { db ->
                    try {
                        // Disposable state is never resumed after a crash; avoid per-directory fsync.
                        db.execSQL("PRAGMA synchronous = OFF")
                        db.execSQL(
                            "CREATE TABLE directory (sequence INTEGER PRIMARY KEY, id TEXT UNIQUE NOT NULL, path TEXT NOT NULL, pending INTEGER NOT NULL)",
                        )
                        db.execSQL("CREATE INDEX next_directory ON directory(pending, sequence)")
                    } catch (failure: Throwable) {
                        db.close()
                        throw failure
                    }
                }
            }
        } catch (failure: Throwable) {
            temporary.close()
            throw failure
        }
    private val additions = mutableListOf<Pair<String, String>>()

    fun add(
        id: String,
        path: String,
    ) {
        additions += id to path
        if (additions.size == BACKUP_BATCH_SIZE) flush()
    }

    fun take(): Pair<String, String>? =
        localStorage {
            flush()
            database
                .rawQuery(
                    "SELECT sequence, id, path FROM directory WHERE pending = 1 ORDER BY sequence LIMIT 1",
                    null,
                ).use { cursor ->
                    if (!cursor.moveToFirst()) return@localStorage null
                    val next = cursor.getString(1) to cursor.getString(2)
                    database.execSQL("UPDATE directory SET pending = 0 WHERE sequence = ?", arrayOf(cursor.getLong(0)))
                    next
                }
        }

    private fun flush() =
        localStorage {
            if (additions.isNotEmpty()) {
                database.beginTransaction()
                try {
                    database
                        .compileStatement(
                            "INSERT OR IGNORE INTO directory (id, path, pending) VALUES (?, ?, 1)",
                        ).use { statement ->
                            additions.forEach { (id, path) ->
                                statement.bindString(1, id)
                                statement.bindString(2, path)
                                if (statement.executeInsert() ==
                                    -1L
                                ) {
                                    throw OpenCloudException(OpenCloudError.InvalidResponse)
                                }
                            }
                        }
                    database.setTransactionSuccessful()
                    additions.clear()
                } finally {
                    database.endTransaction()
                }
            }
        }

    override fun close() {
        try {
            database.close()
        } finally {
            temporary.close()
        }
    }
}

private inline fun <T> localStorage(block: () -> T): T =
    try {
        block()
    } catch (_: SQLiteException) {
        throw OpenCloudException(OpenCloudError.LocalStorageWriteFailed)
    } catch (_: IOException) {
        throw OpenCloudException(OpenCloudError.LocalStorageWriteFailed)
    }
