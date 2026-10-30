package eu.opencloud.android.next.core.database

import androidx.room.Embedded
import androidx.room.withTransaction
import androidx.sqlite.db.SimpleSQLiteQuery
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow

enum class ResourceCollection { Favorites, Offline }

enum class ResourceOfflineFilter { All, Temporary, Pinned }

data class ResourceCollectionOptions(
    val offset: Int = 0,
    val sort: DirectorySort = DirectorySort.Name,
    val ascending: Boolean = true,
    val showHidden: Boolean = false,
    val query: String = "",
    val offlineFilter: ResourceOfflineFilter = ResourceOfflineFilter.All,
    val roots: List<ResourceCollectionRoot> = emptyList(),
)

data class ResourceCollectionRoot(
    val spaceId: String,
    val remoteId: String,
    val path: String,
)

data class ResourceCollectionRow(
    @Embedded val resource: ResourceEntity,
    val keptOffline: Boolean,
)

data class ResourceCollectionPage(
    val page: ResourceDirectoryPage,
    /** Effective pin metadata for this window only, including descendants of pinned folders. */
    val keptOffline: List<ResourceEntity>,
)

/** Cached ordinary inventories. Count, filtering and ordering share a transactional snapshot. */
class ResourceCollectionPaging(
    private val database: FileBrowserDatabase,
) {
    fun invalidations(account: String): Flow<Int> =
        database.resourceDao().observeDirectoryInvalidation(
            SimpleSQLiteQuery("SELECT COUNT(*) FROM resources WHERE accountId = ?", arrayOf(account)),
        )

    suspend fun load(
        account: String,
        collection: ResourceCollection,
        options: ResourceCollectionOptions,
    ): ResourceCollectionPage =
        database.withTransaction {
            val active = database.accountDao().findById(account)?.isActive == true
            if (!active) {
                return@withTransaction ResourceCollectionPage(
                    ResourceDirectoryPage(0, 0, emptyList(), false),
                    emptyList(),
                )
            }
            withRoots(options.roots) {
                val baseFilter = filter(collection, options)
                val args = arrayOf<Any?>(account, if (options.showHidden) 1 else 0)
                val query =
                    options.query
                        .takeUnless { collection == ResourceCollection.Favorites && it.isBlank() }
                        .orEmpty()
                if (query.isNotEmpty()) createSearchMatches(baseFilter, args, query)
                try {
                    val filter = baseFilter + if (query.isEmpty()) "" else SEARCH_MATCH
                    val dao = database.resourceDao()
                    val total = dao.directoryCount(SimpleSQLiteQuery("SELECT COUNT(*)$filter", args))
                    val last =
                        (total - 1).coerceAtLeast(0) / RESOURCE_DIRECTORY_PAGE_SIZE * RESOURCE_DIRECTORY_PAGE_SIZE
                    val offset = options.offset.coerceIn(0, last)
                    val direction = if (options.ascending) "ASC" else "DESC"
                    val order =
                        " ORDER BY CASE r.kind WHEN 'FOLDER' THEN 0 ELSE 1 END, ${sortExpression(
                            options.sort,
                        )} $direction, " +
                            "r.name COLLATE NOCASE $direction, r.spaceId, r.remoteId LIMIT ? OFFSET ?"
                    val rows =
                        dao.collectionRows(
                            SimpleSQLiteQuery(
                                "SELECT r.*, ($PINNED) AS keptOffline$filter$order",
                                args.plus(elements = arrayOf<Any?>(RESOURCE_DIRECTORY_PAGE_SIZE, offset)),
                            ),
                        )
                    ResourceCollectionPage(
                        ResourceDirectoryPage(
                            offset,
                            total,
                            rows.map { ResourceDirectoryItem(resource = it.resource) },
                        ),
                        rows.filter { it.keptOffline }.map { it.resource },
                    )
                } finally {
                    if (query.isNotEmpty()) {
                        database.openHelper.writableDatabase.execSQL(
                            "DROP TABLE temp.raiun_collection_matches",
                        )
                    }
                }
            }
        }

    /** Resolve pin state only for resources currently held by a browser, never the entire pin inventory. */
    suspend fun keptOffline(resources: List<ResourceEntity>): List<ResourceEntity> =
        database.withTransaction {
            resources.distinctBy { Triple(it.accountId, it.spaceId, it.remoteId) }.chunked(128).flatMap { batch ->
                if (batch.isEmpty()) return@flatMap emptyList()
                val identities = batch.joinToString(" OR ") { "(r.accountId = ? AND r.spaceId = ? AND r.remoteId = ?)" }
                val args = batch.flatMap { listOf(it.accountId, it.spaceId, it.remoteId) }.toTypedArray()
                database
                    .resourceDao()
                    .collectionRows(
                        SimpleSQLiteQuery(
                            "SELECT r.*, 1 AS keptOffline$ACCESSIBLE WHERE ($identities) AND ($PINNED)$EXCLUDE_VAULTS",
                            args,
                        ),
                    ).map { it.resource }
            }
        }

    /** Bounded file validation with disk-backed canonical-path deduplication, including malformed aliases. */
    suspend fun offlineBytes(
        account: String,
        roots: List<ResourceCollectionRoot> = emptyList(),
        validate: (ResourceEntity) -> Pair<String, Long>?,
    ): Long =
        database.withTransaction {
            withRoots(roots) {
                val sql = database.openHelper.writableDatabase
                sql.execSQL("CREATE TEMP TABLE raiun_collection_cache_paths(path TEXT NOT NULL PRIMARY KEY)")
                try {
                    sql
                        .compileStatement(
                            "INSERT OR IGNORE INTO temp.raiun_collection_cache_paths VALUES (?)",
                        ).use { insert ->
                            var space = ""
                            var remote = ""
                            var total = 0L
                            while (true) {
                                currentCoroutineContext().ensureActive()
                                val rows =
                                    database.resourceDao().collectionRows(
                                        SimpleSQLiteQuery(
                                            "SELECT r.*, 0 AS keptOffline$ACCESSIBLE " +
                                                "WHERE r.accountId = ? AND $OFFLINE " +
                                                "AND (r.spaceId > ? OR (r.spaceId = ? AND r.remoteId > ?)) " +
                                                "$EXCLUDE_VAULTS${if (roots.isEmpty()) "" else EXCLUDE_ROOTS} " +
                                                "ORDER BY r.spaceId, r.remoteId LIMIT ?",
                                            arrayOf(account, space, space, remote, RESOURCE_DIRECTORY_PAGE_SIZE),
                                        ),
                                    )
                                if (rows.isEmpty()) break
                                rows.forEach { row ->
                                    currentCoroutineContext().ensureActive()
                                    validate(row.resource)?.let { (path, bytes) ->
                                        insert.clearBindings()
                                        insert.bindString(1, path)
                                        if (insert.executeInsert() != -1L) total += bytes
                                    }
                                }
                                space = rows.last().resource.spaceId
                                remote = rows.last().resource.remoteId
                            }
                            total
                        }
                } finally {
                    sql.execSQL("DROP TABLE temp.raiun_collection_cache_paths")
                }
            }
        }

    private suspend fun <T> withRoots(
        roots: List<ResourceCollectionRoot>,
        block: suspend () -> T,
    ): T {
        if (roots.isEmpty()) return block()
        val sql = database.openHelper.writableDatabase
        sql.execSQL(
            "CREATE TEMP TABLE raiun_collection_roots(spaceId TEXT NOT NULL, remoteId TEXT NOT NULL, path TEXT NOT NULL)",
        )
        try {
            sql.compileStatement("INSERT INTO temp.raiun_collection_roots VALUES (?, ?, ?)").use { insert ->
                roots.forEach { root ->
                    insert.clearBindings()
                    insert.bindString(1, root.spaceId)
                    insert.bindString(2, root.remoteId)
                    insert.bindString(3, root.path.trim('/'))
                    insert.executeInsert()
                }
            }
            return block()
        } finally {
            sql.execSQL("DROP TABLE temp.raiun_collection_roots")
        }
    }

    /** Kotlin preserves the existing Unicode ignore-case/literal substring contract; only keys enter TEMP storage. */
    private suspend fun createSearchMatches(
        filter: String,
        args: Array<Any?>,
        query: String,
    ) {
        val sql = database.openHelper.writableDatabase
        sql.execSQL(
            "CREATE TEMP TABLE raiun_collection_matches(spaceId TEXT NOT NULL, remoteId TEXT NOT NULL, " +
                "PRIMARY KEY(spaceId, remoteId))",
        )
        var ready = false
        try {
            scanSearchMatches(filter, args, query)
            ready = true
        } finally {
            if (!ready) sql.execSQL("DROP TABLE temp.raiun_collection_matches")
        }
    }

    private suspend fun scanSearchMatches(
        filter: String,
        args: Array<Any?>,
        query: String,
    ) {
        val sql = database.openHelper.writableDatabase
        sql.compileStatement("INSERT INTO temp.raiun_collection_matches VALUES (?, ?)").use { insert ->
            var space = ""
            var remote = ""
            while (true) {
                currentCoroutineContext().ensureActive()
                val rows =
                    database.resourceDao().collectionRows(
                        SimpleSQLiteQuery(
                            "SELECT r.*, 0 AS keptOffline$filter " +
                                "AND (r.spaceId > ? OR (r.spaceId = ? AND r.remoteId > ?)) " +
                                "ORDER BY r.spaceId, r.remoteId LIMIT ?",
                            args.plus(elements = arrayOf<Any?>(space, space, remote, RESOURCE_DIRECTORY_PAGE_SIZE)),
                        ),
                    )
                if (rows.isEmpty()) break
                recordSearchMatches(rows, query, insert)
                space = rows.last().resource.spaceId
                remote = rows.last().resource.remoteId
            }
        }
    }

    private fun recordSearchMatches(
        rows: List<ResourceCollectionRow>,
        query: String,
        insert: androidx.sqlite.db.SupportSQLiteStatement,
    ) {
        rows.forEach { row ->
            if (row.resource.name.contains(query, ignoreCase = true)) {
                insert.clearBindings()
                insert.bindString(1, row.resource.spaceId)
                insert.bindString(2, row.resource.remoteId)
                insert.executeInsert()
            }
        }
    }

    private fun filter(
        collection: ResourceCollection,
        options: ResourceCollectionOptions,
    ): String {
        val inventory = if (collection == ResourceCollection.Favorites) "r.isFavorite = 1" else OFFLINE
        val pinned =
            if (collection != ResourceCollection.Offline || options.offlineFilter == ResourceOfflineFilter.All) {
                ""
            } else {
                " AND " + if (options.offlineFilter == ResourceOfflineFilter.Pinned) "($PINNED)" else "NOT ($PINNED)"
            }
        return "$ACCESSIBLE WHERE r.accountId = ? AND $inventory AND (? = 1 OR substr(r.name, 1, 1) <> '.') " +
            "$EXCLUDE_VAULTS${if (options.roots.isEmpty()) "" else EXCLUDE_ROOTS}$pinned"
    }
}

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

private const val ACCESSIBLE =
    " FROM resources r JOIN accounts a ON a.id = r.accountId AND a.isActive = 1 " +
        "JOIN spaces s ON s.accountId = r.accountId AND s.driveId = r.spaceId AND s.isDisabled = 0 AND s.isDeleted = 0"

private const val OFFLINE = "r.hasLocalCopy = 1 AND r.localPath IS NOT NULL"

private const val PINNED =
    "r.offlinePinned = 1 OR EXISTS (SELECT 1 FROM resources p WHERE p.accountId = r.accountId " +
        "AND p.spaceId = r.spaceId AND p.offlinePinned = 1 AND (p.remoteId = r.remoteId " +
        "OR (p.kind = 'FOLDER' AND substr(r.path, 1, length(rtrim(p.path, '/')) + 1) = rtrim(p.path, '/') || '/')))"

private const val EXCLUDE_VAULTS =
    " AND NOT EXISTS (SELECT 1 FROM vault_exclusions v WHERE v.accountId = r.accountId " +
        "AND v.spaceId = r.spaceId AND (trim(v.path, '/') = '' OR trim(r.path, '/') = trim(v.path, '/') " +
        "OR substr(trim(r.path, '/'), 1, length(trim(v.path, '/')) + 1) = trim(v.path, '/') || '/'))"

private const val SEARCH_MATCH =
    " AND EXISTS (SELECT 1 FROM temp.raiun_collection_matches m WHERE m.spaceId = r.spaceId AND m.remoteId = r.remoteId)"

private const val EXCLUDE_ROOTS =
    " AND NOT EXISTS (SELECT 1 FROM temp.raiun_collection_roots v WHERE v.spaceId = r.spaceId " +
        "AND (v.remoteId = r.remoteId OR v.path = '' OR trim(r.path, '/') = v.path " +
        "OR substr(trim(r.path, '/'), 1, length(v.path) + 1) = v.path || '/'))"
