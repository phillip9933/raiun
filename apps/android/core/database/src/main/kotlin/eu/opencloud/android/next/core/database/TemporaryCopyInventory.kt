package eu.opencloud.android.next.core.database

import android.content.ContentValues
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import androidx.room.withTransaction
import androidx.sqlite.db.SimpleSQLiteQuery
import eu.opencloud.android.next.core.model.ResourceKind
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.Closeable
import java.io.File
import java.io.IOException

const val TEMPORARY_COPY_PAGE_SIZE = 128

fun FileBrowserStore.temporaryCopies(): TemporaryCopyInventory = TemporaryCopyInventory(database)

data class TemporaryCopyKey(
    val spaceId: String,
    val remoteId: String,
)

/** Frozen original descriptors, owned by one maintenance pass and one database instance. */
class TemporaryCopyScope internal constructor(
    val account: AccountEntity,
    internal val owner: FileBrowserDatabase,
    internal val token: SnapshotToken,
    internal val snapshot: TemporaryCopySnapshot,
) : Closeable {
    internal val gate = Mutex()
    internal var closed = false

    /** Call after the last page/deletion; waits for any already admitted operation before removing only our file. */
    override fun close() {
        runBlocking(Dispatchers.IO) {
            gate.withLock {
                if (!closed) {
                    closed = true
                    snapshot.close()
                }
            }
        }
    }
}

/**
 * The application holds at most one 128-row window. Original full-row CAS descriptors are staged in an
 * independent private FILE database, independent of Android's potentially memory-backed TEMP settings.
 * No Room transaction/cursor survives a return to the caller, nor waits for its cache-use gate.
 */
class TemporaryCopyInventory(
    private val database: FileBrowserDatabase,
) {
    /**
     * [directory] must be application-private. Old unlocked stages are reclaimed by later captures.
     * The cleanup-only catch rethrows every failure, including dispatcher-return cancellation.
     */
    @Suppress("TooGenericExceptionCaught")
    suspend fun capture(
        accountId: String,
        directory: File,
    ): TemporaryCopyScope? {
        var staged: TemporaryCopySnapshot? = null
        try {
            val scope =
                withContext(Dispatchers.IO) {
                    if (database.accountDao().findById(accountId)?.isActive != true) return@withContext null
                    val snapshot = TemporaryCopySnapshot.create(directory)
                    staged = snapshot
                    database.withTransaction {
                        val account =
                            database.accountDao().findById(accountId)?.takeIf { it.isActive }
                                ?: return@withTransaction null
                        val token = database.temporaryCopyVersions.capture(accountId)
                        copyOriginalRows(accountId, snapshot)
                        TemporaryCopyScope(account, database, token, snapshot)
                    }
                }
            if (scope == null) staged?.close()
            return scope
        } catch (failure: Throwable) {
            // Includes prompt cancellation while returning a newly captured scope across dispatchers.
            withContext(NonCancellable + Dispatchers.IO) { staged?.close() }
            throw failure
        }
    }

    private suspend fun copyOriginalRows(
        accountId: String,
        snapshot: TemporaryCopySnapshot,
    ) {
        var after: TemporaryCopyKey? = null
        while (true) {
            currentCoroutineContext().ensureActive()
            val rows =
                database.resourceDao().collectionRows(
                    SimpleSQLiteQuery(
                        "SELECT r.*, 0 AS keptOffline FROM resources r " +
                            "JOIN spaces s ON s.accountId = r.accountId AND s.driveId = r.spaceId " +
                            "WHERE r.accountId = ? AND r.hasLocalCopy = 1 AND r.localPath IS NOT NULL " +
                            "AND s.isDisabled = 0 AND s.isDeleted = 0 AND $AFTER_KEY " +
                            "ORDER BY r.spaceId COLLATE BINARY, r.remoteId COLLATE BINARY LIMIT ?",
                        arrayOf<Any?>(
                            accountId,
                            after?.spaceId,
                            after?.spaceId,
                            after?.spaceId,
                            after?.remoteId,
                            TEMPORARY_COPY_PAGE_SIZE,
                        ),
                    ),
                )
            if (rows.isEmpty()) break
            currentCoroutineContext().ensureActive()
            snapshot.insertBatch(rows.map { it.resource })
            after = rows.last().resource.temporaryCopyKey()
        }
    }

    suspend fun page(
        scope: TemporaryCopyScope,
        after: TemporaryCopyKey? = null,
    ): List<ResourceEntity> =
        scope.gate.withLock {
            database.withTransaction {
                if (!isCurrent(scope)) throw IOException("The temporary-copy account changed during this action.")
                currentCoroutineContext().ensureActive()
                scope.snapshot.page(after)
            }
        }

    /** Caller must acquire its canonical cache-use gate BEFORE entering this transaction. */
    suspend fun expire(
        scope: TemporaryCopyScope,
        expected: ResourceEntity,
        deleteIfOld: () -> Boolean,
    ): Boolean =
        scope.gate.withLock {
            database.withTransaction {
                if (!isCurrent(scope) || expected.accountId != scope.account.id) return@withTransaction false
                if (scope.snapshot.find(expected.temporaryCopyKey()) != expected) return@withTransaction false
                val resources = database.resourceDao()
                val current = resources.findById(expected.accountId, expected.spaceId, expected.remoteId)
                if (current != expected || current.offlinePinned) return@withTransaction false
                if (database.offlineTraversalDao().coveringRoot(
                        current.accountId,
                        current.spaceId,
                        current.remoteId,
                        current.path,
                    ) != null ||
                    database.transferDao().findActiveDownload(current.accountId, current.spaceId, current.remoteId) !=
                    null
                ) {
                    return@withTransaction false
                }
                currentCoroutineContext().ensureActive()
                if (!deleteIfOld()) return@withTransaction false
                resources.updateLocalCopy(current.accountId, current.spaceId, current.remoteId, false, null)
                true
            }
        }

    private suspend fun isCurrent(scope: TemporaryCopyScope): Boolean =
        scope.owner === database &&
            !scope.closed &&
            database.temporaryCopyVersions.isCurrent(scope.token) &&
            database.accountDao().findById(scope.account.id) == scope.account &&
            scope.account.isActive
}

private fun ResourceEntity.temporaryCopyKey() = TemporaryCopyKey(spaceId, remoteId)

/** No cursors escape this file store. A locked owner proof protects its file from stale maintenance. */
internal class TemporaryCopySnapshot private constructor(
    private val stage: TemporaryCopyStage,
    private val sql: SQLiteDatabase,
) : Closeable {
    /** Thread-affine SQLite transactions never cross a suspension, even during Room's frozen capture. */
    fun insertBatch(rows: List<ResourceEntity>) = insertRemovalBatch(rows.map { it to true })

    /** Only explicit removal uses this disposition; ordinary temporary snapshots retain their existing selector. */
    fun insertRemovalBatch(rows: List<Pair<ResourceEntity, Boolean>>) {
        require(rows.size <= TEMPORARY_COPY_PAGE_SIZE)
        sql.beginTransaction()
        try {
            rows.forEach { (row, removeCopy) -> insert(row, removeCopy) }
            sql.setTransactionSuccessful()
        } finally {
            sql.endTransaction()
        }
    }

    private fun insert(
        row: ResourceEntity,
        removeCopy: Boolean,
    ) {
        val values =
            ContentValues().apply {
                put("accountId", row.accountId)
                put("spaceId", row.spaceId)
                put("remoteId", row.remoteId)
                put("parentId", row.parentId)
                put("path", row.path)
                put("name", row.name)
                put("kind", row.kind.name)
                put("mimeType", row.mimeType)
                put("sizeBytes", row.sizeBytes)
                put("eTag", row.eTag)
                put("modifiedAtEpochMillis", row.modifiedAtEpochMillis)
                put("createdAtEpochMillis", row.createdAtEpochMillis)
                put("isFavorite", row.isFavorite)
                put("hasLocalCopy", row.hasLocalCopy)
                put("localPath", row.localPath)
                put("offlinePinned", row.offlinePinned)
                put("removeCopy", removeCopy)
            }
        sql.insertOrThrow("entries", null, values)
    }

    fun page(after: TemporaryCopyKey?): List<ResourceEntity> {
        val predicate =
            if (after == null) {
                ""
            } else {
                "WHERE r.spaceId COLLATE BINARY > ? OR " +
                    "(r.spaceId COLLATE BINARY = ? AND r.remoteId COLLATE BINARY > ?) "
            }
        val args = after?.let { arrayOf(it.spaceId, it.spaceId, it.remoteId) }
        return sql
            .rawQuery(
                "SELECT r.* FROM entries r $predicate" +
                    "ORDER BY r.spaceId COLLATE BINARY, r.remoteId COLLATE BINARY LIMIT $TEMPORARY_COPY_PAGE_SIZE",
                args,
            ).use { cursor ->
                buildList {
                    while (cursor.moveToNext()) add(cursor.resource())
                }
            }
    }

    fun find(key: TemporaryCopyKey): ResourceEntity? =
        sql
            .rawQuery(
                "SELECT * FROM entries WHERE spaceId = ? COLLATE BINARY AND remoteId = ? COLLATE BINARY",
                arrayOf(key.spaceId, key.remoteId),
            ).use { cursor -> if (cursor.moveToFirst()) cursor.resource() else null }

    fun removalEligible(key: TemporaryCopyKey): Boolean =
        sql
            .rawQuery(
                "SELECT removeCopy FROM entries WHERE spaceId = ? COLLATE BINARY AND remoteId = ? COLLATE BINARY",
                arrayOf(key.spaceId, key.remoteId),
            ).use { it.moveToFirst() && it.getInt(0) == 1 }

    override fun close() {
        try {
            sql.close()
        } finally {
            stage.close()
        }
    }

    companion object {
        @Suppress("TooGenericExceptionCaught") // Close only this staging database and rethrow initialization failures.
        fun create(directory: File): TemporaryCopySnapshot {
            val stage = TemporaryCopyStage.create(directory)
            var sql: SQLiteDatabase? = null
            try {
                sql = SQLiteDatabase.openDatabase(stage.file.path, null, SQLiteDatabase.OPEN_READWRITE)
                sql.execSQL(
                    "CREATE TABLE entries (accountId TEXT NOT NULL, spaceId TEXT COLLATE BINARY NOT NULL, " +
                        "remoteId TEXT COLLATE BINARY NOT NULL, parentId TEXT, path TEXT NOT NULL, " +
                        "name TEXT NOT NULL, " +
                        "kind TEXT NOT NULL, mimeType TEXT, sizeBytes INTEGER NOT NULL, eTag TEXT, " +
                        "modifiedAtEpochMillis INTEGER NOT NULL, createdAtEpochMillis INTEGER NOT NULL, " +
                        "isFavorite INTEGER NOT NULL, hasLocalCopy INTEGER NOT NULL, localPath TEXT, " +
                        "offlinePinned INTEGER NOT NULL, removeCopy INTEGER NOT NULL, PRIMARY KEY(spaceId, remoteId))",
                )
                return TemporaryCopySnapshot(stage, sql)
            } catch (failure: Throwable) {
                try {
                    sql?.close()
                } finally {
                    stage.close()
                }
                throw failure
            }
        }
    }
}

private fun Cursor.resource(): ResourceEntity =
    ResourceEntity(
        accountId = getString(0),
        spaceId = getString(1),
        remoteId = getString(2),
        parentId = if (isNull(3)) null else getString(3),
        path = getString(4),
        name = getString(5),
        kind = ResourceKind.valueOf(getString(6)),
        mimeType = if (isNull(7)) null else getString(7),
        sizeBytes = getLong(8),
        eTag = if (isNull(9)) null else getString(9),
        modifiedAtEpochMillis = getLong(10),
        createdAtEpochMillis = getLong(11),
        isFavorite = getInt(12) != 0,
        hasLocalCopy = getInt(13) != 0,
        localPath = if (isNull(14)) null else getString(14),
        offlinePinned = getInt(15) != 0,
    )

private const val AFTER_KEY =
    "(? IS NULL OR r.spaceId COLLATE BINARY > ? OR " +
        "(r.spaceId COLLATE BINARY = ? AND r.remoteId COLLATE BINARY > ?))"
