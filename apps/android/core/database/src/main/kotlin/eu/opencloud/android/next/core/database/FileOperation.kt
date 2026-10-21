package eu.opencloud.android.next.core.database

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.migration.Migration
import androidx.room.withTransaction
import androidx.sqlite.db.SupportSQLiteDatabase
import kotlinx.coroutines.flow.Flow

@Entity(tableName = "file_operations", indices = [Index(value = ["accountId", "state"])])
data class FileOperationEntity(
    @PrimaryKey val id: String,
    val accountId: String,
    val sourceSpaceId: String,
    val destinationSpaceId: String,
    val sourceId: String,
    val sourceParentId: String?,
    val destinationParentId: String?,
    val sourceRoot: String,
    val destinationRoot: String,
    val sourcePath: String,
    val destinationPath: String,
    val sourceETag: String,
    val move: Boolean,
    val sourceFolder: Boolean = false,
    val state: String = "QUEUED",
    val fingerprint: String? = null,
    val error: String? = null,
    val lease: String? = null,
)

@Dao
interface FileOperationDao {
    @Query(
        "SELECT COUNT(*) FROM file_operations WHERE accountId = :accountId AND destinationSpaceId = :spaceId " +
            "AND destinationPath = :path AND state != 'SUCCEEDED'",
    )
    suspend fun destinationReserved(
        accountId: String,
        spaceId: String,
        path: String,
    ): Int

    @Query(
        "UPDATE file_operations SET state = 'BLOCKED_VAULT', lease = NULL, " +
            "error = 'Stopped because this location is encrypted. Check the server for any changes already sent.' " +
            "WHERE accountId = :accountId AND state != 'SUCCEEDED' AND (" +
            "(sourceSpaceId = :spaceId AND (:path IS NULL OR sourcePath = :path " +
            "OR substr(sourcePath, 1, length(:path) + 1) = :path || '/' " +
            "OR substr(:path, 1, length(sourcePath) + 1) = sourcePath || '/')) OR " +
            "(destinationSpaceId = :spaceId AND (:path IS NULL OR destinationPath = :path " +
            "OR substr(destinationPath, 1, length(:path) + 1) = :path || '/' " +
            "OR substr(:path, 1, length(destinationPath) + 1) = destinationPath || '/')))",
    )
    suspend fun blockVault(
        accountId: String,
        spaceId: String,
        path: String?,
    )

    @Insert suspend fun insert(operation: FileOperationEntity)

    @Query("SELECT * FROM file_operations WHERE id = :id")
    suspend fun find(id: String): FileOperationEntity?

    @Query(
        "SELECT * FROM file_operations WHERE state IN ('QUEUED', 'PREPARING', 'SENT', 'DELETING') " +
            "AND id > :after ORDER BY id LIMIT 128",
    )
    suspend fun pending(after: String): List<FileOperationEntity>

    @Query(
        "SELECT * FROM file_operations WHERE accountId = :accountId AND state != 'SUCCEEDED' " +
            "ORDER BY rowid DESC LIMIT 20",
    )
    fun observe(accountId: String): Flow<List<FileOperationEntity>>

    @Query(
        "UPDATE file_operations SET lease = :lease, " +
            "state = CASE WHEN state = 'QUEUED' THEN 'PREPARING' ELSE state END " +
            "WHERE id = :id AND state IN ('QUEUED', 'PREPARING', 'SENT', 'DELETING')",
    )
    suspend fun claim(
        id: String,
        lease: String,
    ): Int

    @Query(
        "UPDATE file_operations SET fingerprint = :fingerprint, state = 'SENT' " +
            "WHERE id = :id AND lease = :lease AND state = 'PREPARING'",
    )
    suspend fun sent(
        id: String,
        lease: String,
        fingerprint: String,
    ): Int

    @Query(
        "UPDATE file_operations SET state = 'DELETING' " +
            "WHERE id = :id AND lease = :lease AND state IN ('SENT', 'DELETING')",
    )
    suspend fun deleting(
        id: String,
        lease: String,
    ): Int

    @Query("UPDATE file_operations SET state = :state, error = :error WHERE id = :id AND lease = :lease")
    suspend fun finish(
        id: String,
        lease: String,
        state: String,
        error: String?,
    ): Int

    @Query(
        "UPDATE file_operations SET state = CASE WHEN fingerprint IS NULL THEN 'QUEUED' ELSE 'SENT' END, " +
            "error = NULL " +
            "WHERE id = :id AND accountId = :accountId AND state = 'NEEDS_ATTENTION'",
    )
    suspend fun retry(
        id: String,
        accountId: String,
    )

    @Query(
        "DELETE FROM file_operations WHERE id = :id AND accountId = :accountId AND state IN ('NEEDS_ATTENTION', 'BLOCKED_VAULT')",
    )
    suspend fun dismiss(
        id: String,
        accountId: String,
    )

    @Query("DELETE FROM file_operations WHERE accountId = :accountId")
    suspend fun deleteAccount(accountId: String)
}

class FileOperationStore(
    private val database: FileBrowserDatabase,
) {
    val dao = database.fileOperationDao()

    suspend fun dismiss(
        id: String,
        accountId: String,
    ) = database.withTransaction {
        val operation = dao.find(id)
        if (operation?.accountId == accountId && operation.state in setOf("NEEDS_ATTENTION", "BLOCKED_VAULT")) {
            database.pendingPinDao().clearOperation(id)
            dao.dismiss(id, accountId)
        }
    }

    suspend fun enqueue(operation: FileOperationEntity) =
        database.withTransaction {
            requireNotNull(database.accountDao().findById(operation.accountId)) { "The account is unavailable." }
            listOf(operation.sourceSpaceId, operation.destinationSpaceId).forEach { id ->
                val space = requireNotNull(database.spaceDao().findById(operation.accountId, id))
                require(!space.isDisabled && !space.isDeleted) { "The space is unavailable." }
            }
            val exclusions = database.vaultExclusionDao()
            require(
                !exclusions.denies(
                    operation.accountId,
                    operation.sourceSpaceId,
                    operation.sourcePath,
                    includeChildren = operation.sourceFolder,
                ),
            ) { "The source is inside or contains an encrypted location." }
            require(
                !exclusions.denies(
                    operation.accountId,
                    operation.destinationSpaceId,
                    operation.destinationPath,
                ),
            ) { "The destination is inside an encrypted location." }
            dao.insert(operation)
            if (operation.move) {
                database.pendingPinDao().preserve(
                    operation.accountId,
                    operation.sourceSpaceId,
                    operation.sourcePath,
                    operation.id,
                )
            }
        }

    suspend fun complete(
        operation: FileOperationEntity,
        lease: String,
    ): Boolean =
        database.withTransaction {
            if (database.accountDao().findById(operation.accountId) == null) return@withTransaction false
            if (dao.finish(operation.id, lease, "SUCCEEDED", null) != 1) return@withTransaction false
            val store = FileBrowserStore(database)
            if (operation.move) {
                database.pendingPinDao().activate(
                    operation.accountId,
                    operation.destinationSpaceId,
                    operation.destinationPath,
                    operation.id,
                )
            }
            database.pendingPinDao().clearOperation(operation.id)
            store.queueFolderRefresh(operation.accountId, operation.sourceSpaceId, operation.sourceParentId)
            store.queueFolderRefresh(operation.accountId, operation.destinationSpaceId, operation.destinationParentId)
            true
        }
}

val MIGRATION_13_14 =
    object : Migration(13, 14) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS file_operations (id TEXT NOT NULL PRIMARY KEY, accountId TEXT NOT NULL, " +
                    "sourceSpaceId TEXT NOT NULL, destinationSpaceId TEXT NOT NULL, sourceId TEXT NOT NULL, " +
                    "sourceParentId TEXT, destinationParentId TEXT, sourceRoot TEXT NOT NULL, " +
                    "destinationRoot TEXT NOT NULL, sourcePath TEXT NOT NULL, destinationPath TEXT NOT NULL, " +
                    "sourceETag TEXT NOT NULL, move INTEGER NOT NULL, " +
                    "sourceFolder INTEGER NOT NULL, " +
                    "state TEXT NOT NULL, fingerprint TEXT, error TEXT, lease TEXT)",
            )
            db.execSQL("CREATE INDEX index_file_operations_accountId_state ON file_operations (accountId, state)")
            db.execSQL(
                "CREATE TABLE pending_pins (accountId TEXT NOT NULL, spaceId TEXT NOT NULL, " +
                    "path TEXT NOT NULL, attemptedAt INTEGER NOT NULL, PRIMARY KEY(accountId, spaceId, path))",
            )
            db.execSQL(
                "CREATE TABLE operation_pins (operationId TEXT NOT NULL, relativePath TEXT NOT NULL, " +
                    "PRIMARY KEY(operationId, relativePath))",
            )
        }
    }
