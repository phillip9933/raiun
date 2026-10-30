package eu.opencloud.android.next.core.database

import androidx.room.Dao
import androidx.room.RawQuery
import androidx.room.withTransaction
import androidx.sqlite.db.SimpleSQLiteQuery
import androidx.sqlite.db.SupportSQLiteQuery
import androidx.sqlite.db.SupportSQLiteStatement
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow

const val TRANSFER_INVENTORY_PAGE_SIZE = 128

enum class TransferInventoryStatus { All, Active, Attention, Succeeded, Cancelled }

enum class TransferInventoryFileType { All, Images, Videos, Documents, Audio, Other }

enum class TransferBulkKind { All, RetryUploads, History }

data class TransferInventoryFilter(
    val direction: String? = null,
    val status: TransferInventoryStatus = TransferInventoryStatus.All,
    val fileType: TransferInventoryFileType = TransferInventoryFileType.All,
    val startEpochMillisInclusive: Long? = null,
    val endEpochMillisExclusive: Long? = null,
    val matchNone: Boolean = false,
)

data class TransferInventoryCounts(
    val active: Int = 0,
    val attention: Int = 0,
    val history: Int = 0,
) {
    val total: Int get() = Math.addExact(Math.addExact(active, attention), history)
}

data class TransferAccountActions(
    val total: Int = 0,
    val uploadRetryCount: Int = 0,
    val uploadConflictCount: Int = 0,
)

data class TransferInventoryPage(
    val offset: Int,
    val total: Int,
    val entries: List<TransferEntity>,
    val counts: TransferInventoryCounts,
    val actions: TransferAccountActions,
    val accessible: Boolean = true,
) {
    val hasPrevious: Boolean get() = offset > 0
    val hasNext: Boolean get() = offset.toLong() + entries.size < total
}

data class BackupTransferStats(
    val pending: Int = 0,
    val attention: Int = 0,
    val lastCompleted: Long? = null,
)

data class TransferBrowserOverview(
    val representative: TransferEntity? = null,
    val uploadConflict: TransferEntity? = null,
    val uploadConflictCount: Int = 0,
    val backupStats: Map<String, BackupTransferStats> = emptyMap(),
)

data class BackupTransferStatsRow(
    val backupId: String,
    val pending: Int,
    val attention: Int,
    val lastCompleted: Long?,
)

/** Queue sequence is monotonic across retries; backdated or lower-ID new rows cannot join an old bulk action. */
class TransferBulkScope internal constructor(
    val account: AccountEntity,
    val watermark: Long,
    internal val token: SnapshotToken,
)

@Dao
interface TransferInventoryDao {
    @RawQuery(observedEntities = [TransferEntity::class, AccountEntity::class, FolderBackupEntity::class])
    fun invalidations(query: SupportSQLiteQuery): Flow<Int>

    @RawQuery suspend fun rows(query: SupportSQLiteQuery): List<TransferEntity>

    @RawQuery suspend fun count(query: SupportSQLiteQuery): Int

    @RawQuery suspend fun watermark(query: SupportSQLiteQuery): Long

    @RawQuery suspend fun counts(query: SupportSQLiteQuery): TransferInventoryCounts

    @RawQuery suspend fun actions(query: SupportSQLiteQuery): TransferAccountActions

    @RawQuery suspend fun backupStats(query: SupportSQLiteQuery): List<BackupTransferStatsRow>
}

/** Query-only snapshots: no complete account history enters application memory. */
class TransferInventory(
    private val database: FileBrowserDatabase,
) {
    private val dao get() = database.transferInventoryDao()

    fun invalidations(account: String): Flow<Int> =
        dao.invalidations(query("SELECT COUNT(*) FROM transfers WHERE accountId = ?", account))

    suspend fun load(
        account: String,
        filter: TransferInventoryFilter = TransferInventoryFilter(),
        requestedOffset: Int = 0,
    ): TransferInventoryPage =
        database.withTransaction {
            if (database.accountDao().findById(account)?.isActive != true) {
                return@withTransaction TransferInventoryPage(
                    0,
                    0,
                    emptyList(),
                    TransferInventoryCounts(),
                    TransferAccountActions(),
                    false,
                )
            }
            val selection = selection(account, filter)
            withTypeMatches(selection, filter.fileType) { selected ->
                val counts = dao.counts(selected.query("SELECT $COUNT_COLUMNS"))
                val total = counts.total
                val last = (total - 1).coerceAtLeast(0) / TRANSFER_INVENTORY_PAGE_SIZE * TRANSFER_INVENTORY_PAGE_SIZE
                val offset = requestedOffset.coerceIn(0, last)
                val rows =
                    dao.rows(
                        selected.query(
                            "SELECT t.*",
                            "$ORDER LIMIT ? OFFSET ?",
                            TRANSFER_INVENTORY_PAGE_SIZE,
                            offset,
                        ),
                    )
                TransferInventoryPage(offset, total, rows, counts, accountActions(account))
            }
        }

    suspend fun overview(account: String): TransferBrowserOverview =
        database.withTransaction {
            if (database.accountDao().findById(account)?.isActive !=
                true
            ) {
                return@withTransaction TransferBrowserOverview()
            }
            val representative =
                dao
                    .rows(
                        query(
                            "SELECT t.*$ACCOUNT_FROM WHERE t.accountId = ? " +
                                "AND t.state IN ('RUNNING','QUEUED','RETRY','FAILED','CONFLICT') " +
                                "ORDER BY CASE WHEN t.state = 'RUNNING' THEN 0 " +
                                "WHEN t.state IN ('QUEUED','RETRY') THEN 1 ELSE 2 END, " +
                                "t.createdAtEpochMillis DESC, t.id DESC LIMIT 1",
                            account,
                        ),
                    ).singleOrNull()
            val conflict =
                dao
                    .rows(
                        query(
                            "SELECT t.*$ACCOUNT_FROM WHERE t.accountId = ? AND t.direction = 'UPLOAD' " +
                                "AND t.state = 'CONFLICT' AND t.locationKind != 'VAULT' " +
                                "ORDER BY t.createdAtEpochMillis DESC, t.id DESC LIMIT 1",
                            account,
                        ),
                    ).singleOrNull()
            val stats =
                dao.backupStats(query(BACKUP_STATS, account)).associate { row ->
                    row.backupId to BackupTransferStats(row.pending, row.attention, row.lastCompleted)
                }
            TransferBrowserOverview(representative, conflict, accountActions(account).uploadConflictCount, stats)
        }

    suspend fun captureScope(account: String): TransferBulkScope? =
        database.withTransaction {
            val active = database.accountDao().findById(account)?.takeIf { it.isActive } ?: return@withTransaction null
            val watermark =
                dao.watermark(
                    query(
                        "SELECT coalesce(MAX(q.sequence),0) FROM transfer_queue q " +
                            "JOIN transfers t ON t.id = q.transferId WHERE t.accountId = ?",
                        account,
                    ),
                )
            TransferBulkScope(active, watermark, database.transferInventoryVersions.capture(account))
        }

    suspend fun bulkPage(
        scope: TransferBulkScope,
        afterId: String? = null,
        kind: TransferBulkKind = TransferBulkKind.All,
    ): List<TransferEntity> =
        database.withTransaction {
            requireCurrent(scope)
            val predicate =
                when (kind) {
                    TransferBulkKind.All -> ""
                    TransferBulkKind.RetryUploads ->
                        " AND t.direction = 'UPLOAD' AND t.state IN ('FAILED','RETRY','CONFLICT')"
                    TransferBulkKind.History -> " AND t.state IN ('SUCCEEDED','CANCELLED')"
                }
            dao.rows(
                query(
                    "SELECT t.* FROM transfers t JOIN transfer_queue q ON q.transferId = t.id " +
                        "WHERE t.accountId = ? AND q.sequence <= ? AND (? IS NULL OR t.id > ?)$predicate " +
                        "ORDER BY t.id LIMIT ?",
                    scope.account.id,
                    scope.watermark,
                    afterId,
                    afterId,
                    TRANSFER_INVENTORY_PAGE_SIZE,
                ),
            )
        }

    suspend fun countBulk(
        scope: TransferBulkScope,
        kind: TransferBulkKind,
    ): Int =
        database.withTransaction {
            requireCurrent(scope)
            val predicate =
                when (kind) {
                    TransferBulkKind.All -> ""
                    TransferBulkKind.RetryUploads ->
                        " AND t.direction = 'UPLOAD' AND t.state IN ('FAILED','RETRY','CONFLICT')"
                    TransferBulkKind.History -> " AND t.state IN ('SUCCEEDED','CANCELLED')"
                }
            dao.count(
                query(
                    "SELECT COUNT(*) FROM transfers t JOIN transfer_queue q ON q.transferId = t.id " +
                        "WHERE t.accountId = ? AND q.sequence <= ?$predicate",
                    scope.account.id,
                    scope.watermark,
                ),
            )
        }

    /** Returns the admitted worker identity; a retry/new queue admission cannot be cancelled by this old scope. */
    suspend fun cancelForClear(
        scope: TransferBulkScope,
        id: String,
    ): TransferEntity? =
        database.withTransaction {
            requireCurrent(scope)
            val current =
                dao
                    .rows(
                        query(
                            "SELECT t.* FROM transfers t JOIN transfer_queue q ON q.transferId = t.id " +
                                "WHERE t.accountId = ? AND t.id = ? AND q.sequence <= ?",
                            scope.account.id,
                            id,
                            scope.watermark,
                        ),
                    ).singleOrNull() ?: return@withTransaction null
            if (current.locationKind == VAULT_GROUP_LOCATION_KIND) {
                if (!database.cancelOfflineGroupParent(current)) return@withTransaction null
            } else {
                database.transferDao().cancel(current.id)
            }
            current
        }

    /** Deletes terminal history after an explicit clear, preserving active and awaiting-verification rows. */
    suspend fun deleteScopedHistory(scope: TransferBulkScope): Int =
        database.withTransaction {
            requireCurrent(scope)
            // Removing admission history invalidates any older explicit/temporary copy deletion proof.
            database.temporaryCopyVersions.begin(scope.account.id)
            val deleted =
                database.openHelper.writableDatabase
                    .compileStatement(
                        "DELETE FROM transfers WHERE accountId = ? AND state IN ('SUCCEEDED','CANCELLED') " +
                            "AND id IN (SELECT transferId FROM transfer_queue WHERE sequence <= ?)",
                    ).use { statement ->
                        statement.bindString(1, scope.account.id)
                        statement.bindLong(2, scope.watermark)
                        statement.executeUpdateDelete()
                    }
            database.compactTerminalOfflineGroupHistory(scope.account.id)
            deleted
        }

    /** Invoke after location-specific guards, inside their transaction, before admitting a new retry worker. */
    suspend fun retryScoped(
        scope: TransferBulkScope,
        expected: TransferEntity,
        replacement: TransferEntity,
    ): TransferEntity? =
        database.withTransaction {
            require(replacement.accountId == expected.accountId)
            if (expected.locationKind == VAULT_GROUP_LOCATION_KIND) return@withTransaction null
            if (expected.accountId != scope.account.id || !isCurrent(scope)) return@withTransaction null
            val admitted =
                dao
                    .rows(
                        query(
                            "SELECT t.* FROM transfers t JOIN transfer_queue q ON q.transferId = t.id " +
                                "WHERE t.accountId = ? AND t.id = ? AND q.sequence <= ?",
                            scope.account.id,
                            expected.id,
                            scope.watermark,
                        ),
                    ).singleOrNull()
            if (admitted != expected) return@withTransaction null
            database.transferDao().retry(expected, replacement)
        }

    private suspend fun isCurrent(scope: TransferBulkScope): Boolean {
        val currentAdmission = database.transferInventoryVersions.isCurrent(scope.token)
        val sameAccount = database.accountDao().findById(scope.account.id) == scope.account
        return currentAdmission && sameAccount && scope.account.isActive
    }

    private suspend fun requireCurrent(scope: TransferBulkScope) {
        check(isCurrent(scope)) { "The transfer account changed during this action." }
    }

    private suspend fun accountActions(account: String): TransferAccountActions =
        dao.actions(
            query(
                "SELECT COUNT(*) AS total, " +
                    "coalesce(SUM(CASE WHEN t.direction = 'UPLOAD' AND t.state IN ('FAILED','RETRY') " +
                    "THEN 1 ELSE 0 END),0) AS uploadRetryCount, " +
                    "coalesce(SUM(CASE WHEN t.direction = 'UPLOAD' AND t.state = 'CONFLICT' " +
                    "THEN 1 ELSE 0 END),0) AS uploadConflictCount" +
                    "$ACCOUNT_FROM WHERE t.accountId = ? AND t.state IN ($KNOWN_STATES)",
                account,
            ),
        )

    private suspend fun <T> withTypeMatches(
        selection: Selection,
        type: TransferInventoryFileType,
        block: suspend (Selection) -> T,
    ): T {
        if (type == TransferInventoryFileType.All) return block(selection)
        val sql = database.openHelper.writableDatabase
        sql.execSQL("CREATE TEMP TABLE raiun_transfer_matches(id TEXT NOT NULL PRIMARY KEY)")
        try {
            populateTypeMatches(selection, type)
            val matches =
                selection.copy(
                    sql = selection.sql + " AND t.id IN (SELECT id FROM temp.raiun_transfer_matches)",
                )
            return block(matches)
        } finally {
            sql.execSQL("DROP TABLE temp.raiun_transfer_matches")
        }
    }

    private suspend fun populateTypeMatches(
        selection: Selection,
        type: TransferInventoryFileType,
    ) {
        val sql = database.openHelper.writableDatabase
        sql.compileStatement("INSERT INTO temp.raiun_transfer_matches VALUES (?)").use { insert ->
            var after: String? = null
            while (true) {
                currentCoroutineContext().ensureActive()
                val rows =
                    dao.rows(
                        selection.query(
                            "SELECT t.*",
                            " AND (? IS NULL OR t.id > ?) ORDER BY t.id LIMIT ?",
                            after,
                            after,
                            TRANSFER_INVENTORY_PAGE_SIZE,
                        ),
                    )
                if (rows.isEmpty()) break
                insertTypeMatches(insert, rows, type)
                after = rows.last().id
            }
        }
    }

    private fun insertTypeMatches(
        insert: SupportSQLiteStatement,
        rows: List<TransferEntity>,
        type: TransferInventoryFileType,
    ) {
        for (row in rows) {
            if (inventoryFileType(row) == type) {
                insert.clearBindings()
                insert.bindString(1, row.id)
                insert.executeInsert()
            }
        }
    }
}

private data class Selection(
    val sql: String,
    val args: List<Any?>,
) {
    fun query(
        prefix: String,
        suffix: String = "",
        vararg extra: Any?,
    ): SupportSQLiteQuery = SimpleSQLiteQuery(prefix + sql + suffix, (args + extra.toList()).toTypedArray())
}

private fun query(
    sql: String,
    vararg args: Any?,
): SupportSQLiteQuery = SimpleSQLiteQuery(sql, args)

private fun selection(
    account: String,
    filter: TransferInventoryFilter,
): Selection {
    val args = mutableListOf<Any?>(account)
    val clauses = mutableListOf("t.accountId = ?", "t.state IN ($KNOWN_STATES)")
    filter.direction?.let {
        clauses += "t.direction = ?"
        args += it
    }
    filter.startEpochMillisInclusive?.let {
        clauses += "t.createdAtEpochMillis >= ?"
        args += it
    }
    filter.endEpochMillisExclusive?.let {
        clauses += "t.createdAtEpochMillis < ?"
        args += it
    }
    if (filter.matchNone) clauses += "0"
    when (filter.status) {
        TransferInventoryStatus.All -> Unit
        TransferInventoryStatus.Active -> clauses += "t.state IN ($ACTIVE_STATES)"
        TransferInventoryStatus.Attention -> clauses += "t.state IN ('FAILED','CONFLICT')"
        TransferInventoryStatus.Succeeded -> clauses += "t.state = 'SUCCEEDED'"
        TransferInventoryStatus.Cancelled -> clauses += "t.state = 'CANCELLED'"
    }
    return Selection("$ACCOUNT_FROM WHERE " + clauses.joinToString(" AND "), args)
}

private const val ACTIVE_STATES = "'QUEUED','RUNNING','RETRY','AWAITING_UNLOCK'"
private const val KNOWN_STATES = "$ACTIVE_STATES,'FAILED','CONFLICT','SUCCEEDED','CANCELLED'"
private const val ACCOUNT_FROM = " FROM transfers t JOIN accounts a ON a.id = t.accountId AND a.isActive = 1"
private const val ORDER =
    " ORDER BY CASE WHEN t.state IN ($ACTIVE_STATES) THEN 0 WHEN t.state IN ('FAILED','CONFLICT') THEN 1 ELSE 2 END, " +
        "t.createdAtEpochMillis DESC, t.id DESC"
private const val COUNT_COLUMNS =
    "coalesce(SUM(CASE WHEN t.state IN ($ACTIVE_STATES) THEN 1 ELSE 0 END),0) AS active, " +
        "coalesce(SUM(CASE WHEN t.state IN ('FAILED','CONFLICT') THEN 1 ELSE 0 END),0) AS attention, " +
        "coalesce(SUM(CASE WHEN t.state IN ('SUCCEEDED','CANCELLED') THEN 1 ELSE 0 END),0) AS history"
private const val BACKUP_STATS =
    "SELECT b.id AS backupId, " +
        "coalesce(SUM(CASE WHEN t.state IN ('QUEUED','RUNNING','RETRY') THEN 1 ELSE 0 END),0) AS pending, " +
        "coalesce(SUM(CASE WHEN t.state IN ('FAILED','CONFLICT') THEN 1 ELSE 0 END),0) AS attention, " +
        "MAX(CASE WHEN t.state = 'SUCCEEDED' THEN t.updatedAtEpochMillis ELSE NULL END) AS lastCompleted " +
        "FROM folder_backups b JOIN accounts a ON a.id = b.accountId AND a.isActive = 1 LEFT JOIN transfers t " +
        "ON t.accountId = b.accountId AND t.spaceId = b.spaceId AND t.direction = 'UPLOAD' " +
        "AND substr(t.sourceUri,1,length(rtrim(b.sourceTreeUri,'/') || '/document/')) " +
        "= rtrim(b.sourceTreeUri,'/') || '/document/' " +
        "AND substr(t.destinationPath,1,length(rtrim(b.destinationPath,'/') || '/')) " +
        "= rtrim(b.destinationPath,'/') || '/' " +
        "WHERE b.accountId = ? GROUP BY b.id"
