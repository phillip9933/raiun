package eu.opencloud.android.next.core.database

import androidx.room.Embedded
import androidx.room.withTransaction
import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.SupportSQLiteStatement
import kotlinx.coroutines.flow.Flow

const val RESOURCE_DIRECTORY_PAGE_SIZE = 128

/** Locked roots remain transient descriptors; they are never inserted into ordinary resources. */
data class DirectoryOverlay(
    val id: String,
    val name: String,
    val remoteId: String? = null,
    val path: String? = null,
)

enum class DirectorySort { Name, DateModified, DateOpened, Size, Type }

data class ResourceDirectoryItem(
    val resource: ResourceEntity? = null,
    val overlayId: String? = null,
)

/** A synthetic root row is only a SQL sort key and is never exposed as an ordinary resource. */
data class ResourceDirectoryRow(
    @Embedded val resource: ResourceEntity,
    val overlayId: String?,
)

data class ResourceDirectoryPage(
    val offset: Int,
    val total: Int,
    val entries: List<ResourceDirectoryItem>,
    val accessible: Boolean = true,
) {
    val hasPrevious: Boolean get() = offset > 0
    val hasNext: Boolean get() = offset.toLong() + entries.size < total
}

/** One transactional, globally ordered window. No full directory list enters application memory. */
class ResourceDirectoryPaging(
    private val database: FileBrowserDatabase,
) {
    fun invalidations(
        account: String,
        space: String,
        parent: String?,
    ): Flow<Int> =
        database.resourceDao().observeDirectoryInvalidation(
            SimpleSQLiteQuery(
                "SELECT COUNT(*) FROM resources WHERE accountId = ? AND spaceId = ? AND parentId IS ?",
                arrayOf(account, space, parent),
            ),
        )

    @Suppress("LongParameterList") // Identity, display policy and location are independent inputs.
    suspend fun load(
        account: String,
        space: String,
        parent: String?,
        requestedOffset: Int,
        sort: DirectorySort,
        ascending: Boolean,
        showHidden: Boolean,
        overlays: List<DirectoryOverlay>,
        onlyFolders: Boolean = false,
        includeOverlays: Boolean = true,
    ): ResourceDirectoryPage =
        database.withTransaction {
            val active = database.accountDao().findById(account)?.isActive == true
            val source = database.spaceDao().findById(account, space)
            val available = source?.let { !it.isDisabled && !it.isDeleted } == true
            if (!active || !available) {
                return@withTransaction ResourceDirectoryPage(0, 0, emptyList(), accessible = false)
            }
            val sql = database.openHelper.writableDatabase
            createTransientRoots(sql, overlays)
            try {
                queryPage(
                    account,
                    space,
                    parent,
                    requestedOffset,
                    sort,
                    ascending,
                    showHidden,
                    onlyFolders,
                    includeOverlays,
                )
            } finally {
                sql.execSQL("DROP TABLE temp.raiun_directory_roots")
            }
        }

    @Suppress("LongParameterList") // Same validated identity/display inputs as load, inside its transaction.
    private suspend fun queryPage(
        account: String,
        space: String,
        parent: String?,
        requestedOffset: Int,
        sort: DirectorySort,
        ascending: Boolean,
        showHidden: Boolean,
        onlyFolders: Boolean,
        includeOverlays: Boolean,
    ): ResourceDirectoryPage {
        val dao = database.resourceDao()
        val visibility = if (showHidden) 1 else 0
        val resourceArgs = listOf<Any?>(account, space, parent, visibility, if (onlyFolders) 1 else 0)
        val ordinaryCount =
            dao.directoryCount(
                SimpleSQLiteQuery("SELECT COUNT(*)$RESOURCE_FILTER", resourceArgs.toTypedArray()),
            )
        val rootCount =
            if (!includeOverlays) {
                0
            } else {
                dao.directoryCount(
                    SimpleSQLiteQuery(
                        "SELECT COUNT(*) FROM temp.raiun_directory_roots WHERE ? = 1 OR substr(name, 1, 1) <> '.'",
                        arrayOf(visibility),
                    ),
                )
            }
        val total = Math.addExact(ordinaryCount, rootCount)
        val lastPage = (total - 1).coerceAtLeast(0) / RESOURCE_DIRECTORY_PAGE_SIZE * RESOURCE_DIRECTORY_PAGE_SIZE
        val offset = minOf(requestedOffset.coerceAtLeast(0), lastPage)
        val direction = if (ascending) "ASC" else "DESC"
        val query =
            "SELECT * FROM (SELECT $RESOURCE_COLUMNS, NULL AS overlayId, 0 AS overlayOrder$RESOURCE_FILTER UNION ALL " +
                "SELECT ?, ?, t.overlayId, ?, coalesce(t.path, ''), t.name, 'FOLDER', NULL, 0, NULL, " +
                "0, 0, 0, 0, NULL, 0, t.overlayId, 1 FROM temp.raiun_directory_roots t " +
                "WHERE ? = 1 AND (? = 1 OR substr(t.name, 1, 1) <> '.')) r " +
                "ORDER BY CASE r.kind WHEN 'FOLDER' THEN 0 ELSE 1 END, ${sortExpression(sort)} $direction, " +
                "r.name COLLATE NOCASE $direction, overlayOrder, r.remoteId LIMIT ? OFFSET ?"
        val queryArgs =
            buildList<Any?> {
                addAll(resourceArgs)
                add(account)
                add(space)
                add(parent)
                add(if (includeOverlays) 1 else 0)
                add(visibility)
                add(RESOURCE_DIRECTORY_PAGE_SIZE)
                add(offset)
            }
        val rows = dao.directoryRows(SimpleSQLiteQuery(query, queryArgs.toTypedArray()))
        return ResourceDirectoryPage(
            offset,
            total,
            rows.map { row ->
                row.overlayId?.let { ResourceDirectoryItem(overlayId = it) }
                    ?: ResourceDirectoryItem(resource = row.resource)
            },
        )
    }
}

/** Transaction-owned TEMP metadata, indexed by both identities; no permanent schema or cache changes. */
private fun createTransientRoots(
    sql: SupportSQLiteDatabase,
    overlays: List<DirectoryOverlay>,
) {
    sql.execSQL(
        "CREATE TEMP TABLE raiun_directory_roots " +
            "(overlayId TEXT NOT NULL PRIMARY KEY, name TEXT NOT NULL, remoteId TEXT, path TEXT)",
    )
    var ready = false
    try {
        sql.execSQL("CREATE INDEX temp.raiun_directory_roots_id ON raiun_directory_roots(remoteId)")
        sql.execSQL("CREATE INDEX temp.raiun_directory_roots_path ON raiun_directory_roots(path)")
        sql
            .compileStatement(
                "INSERT OR IGNORE INTO temp.raiun_directory_roots(overlayId, name, remoteId, path) VALUES (?, ?, ?, ?)",
            ).use { insert ->
                overlays.forEach { insertTransientRoot(insert, it) }
            }
        ready = true
    } finally {
        if (!ready) sql.execSQL("DROP TABLE temp.raiun_directory_roots")
    }
}

private fun insertTransientRoot(
    insert: SupportSQLiteStatement,
    overlay: DirectoryOverlay,
) {
    insert.clearBindings()
    insert.bindString(1, overlay.id)
    insert.bindString(2, overlay.name)
    overlay.remoteId?.let { insert.bindString(3, it) }
    overlay.path?.let { insert.bindString(4, it.trim('/')) }
    insert.executeInsert()
}

/** SQLite NOCASE is shared by resource and root rows, so page boundaries use one consistent order. */
private fun sortExpression(sort: DirectorySort): String =
    when (sort) {
        DirectorySort.Name -> "r.name COLLATE NOCASE"
        DirectorySort.DateModified -> "r.modifiedAtEpochMillis"
        DirectorySort.DateOpened -> "r.createdAtEpochMillis"
        DirectorySort.Size -> "r.sizeBytes"
        DirectorySort.Type ->
            "(CASE WHEN instr(r.name, '.') > 0 AND substr(r.name, -1) <> '.' " +
                "THEN substr(r.name, length(rtrim(r.name, replace(r.name, '.', ''))) + 1) " +
                "ELSE coalesce(r.mimeType, '') END) COLLATE NOCASE"
    }

private const val RESOURCE_COLUMNS =
    "r.accountId, r.spaceId, r.remoteId, r.parentId, r.path, r.name, r.kind, r.mimeType, " +
        "r.sizeBytes, r.eTag, r.modifiedAtEpochMillis, r.createdAtEpochMillis, r.isFavorite, " +
        "r.hasLocalCopy, r.localPath, r.offlinePinned"

private const val RESOURCE_FILTER =
    " FROM resources r WHERE r.accountId = ? AND r.spaceId = ? AND r.parentId IS ? " +
        "AND (? = 1 OR substr(r.name, 1, 1) <> '.') AND (? = 0 OR r.kind = 'FOLDER') " +
        "AND NOT EXISTS (SELECT 1 FROM vault_exclusions v WHERE v.accountId = r.accountId " +
        "AND v.spaceId = r.spaceId AND (trim(v.path, '/') = '' OR trim(r.path, '/') = trim(v.path, '/') " +
        "OR substr(trim(r.path, '/'), 1, length(trim(v.path, '/')) + 1) = trim(v.path, '/') || '/')) " +
        "AND NOT EXISTS (SELECT 1 FROM temp.raiun_directory_roots t WHERE t.remoteId = r.remoteId) " +
        "AND NOT EXISTS (SELECT 1 FROM temp.raiun_directory_roots t WHERE t.path = trim(r.path, '/'))"
