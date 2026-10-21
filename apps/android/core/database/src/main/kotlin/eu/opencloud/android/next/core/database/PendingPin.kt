package eu.opencloud.android.next.core.database

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Query

@Entity(tableName = "pending_pins", primaryKeys = ["accountId", "spaceId", "path"])
data class PendingPinEntity(
    val accountId: String,
    val spaceId: String,
    val path: String,
    val attemptedAt: Long,
)

@Entity(tableName = "operation_pins", primaryKeys = ["operationId", "relativePath"])
data class OperationPinEntity(
    val operationId: String,
    val relativePath: String,
)

@Dao
interface PendingPinDao {
    @Query(
        "DELETE FROM pending_pins WHERE accountId = :accountId AND spaceId = :spaceId " +
            "AND (path = :path OR substr(path, 1, length(:path) + 1) = :path || '/')",
    )
    suspend fun deleteTree(
        accountId: String,
        spaceId: String,
        path: String,
    )

    @Query("DELETE FROM pending_pins WHERE accountId = :accountId AND spaceId = :spaceId")
    suspend fun deleteSpace(
        accountId: String,
        spaceId: String,
    )

    @Query("SELECT * FROM pending_pins ORDER BY attemptedAt, accountId, spaceId, path LIMIT 32")
    suspend fun pending(): List<PendingPinEntity>

    @Query(
        "SELECT EXISTS(SELECT 1 FROM pending_pins WHERE accountId = :accountId AND spaceId = :spaceId AND path = :path)",
    )
    suspend fun selected(
        accountId: String,
        spaceId: String,
        path: String,
    ): Boolean

    @Query("DELETE FROM pending_pins WHERE accountId = :accountId AND spaceId = :spaceId AND path = :path")
    suspend fun acknowledge(
        accountId: String,
        spaceId: String,
        path: String,
    )

    @Query(
        "UPDATE pending_pins SET attemptedAt = :now WHERE accountId = :accountId AND spaceId = :spaceId AND path = :path",
    )
    suspend fun attempted(
        accountId: String,
        spaceId: String,
        path: String,
        now: Long,
    )

    @Query("DELETE FROM pending_pins WHERE accountId = :accountId")
    suspend fun deleteAccount(accountId: String)

    @Query(
        "INSERT OR REPLACE INTO operation_pins (operationId, relativePath) " +
            "SELECT :operationId, substr(path, length(:sourcePath) + 1) " +
            "FROM resources WHERE accountId = :accountId AND spaceId = :sourceSpace AND offlinePinned = 1 " +
            "AND (path = :sourcePath OR substr(path, 1, length(:sourcePath) + 1) = :sourcePath || '/')",
    )
    suspend fun preserve(
        accountId: String,
        sourceSpace: String,
        sourcePath: String,
        operationId: String,
    )

    @Query(
        "INSERT OR REPLACE INTO pending_pins (accountId, spaceId, path, attemptedAt) " +
            "SELECT :accountId, :spaceId, :path || relativePath, 0 FROM operation_pins WHERE operationId = :operationId",
    )
    suspend fun activate(
        accountId: String,
        spaceId: String,
        path: String,
        operationId: String,
    )

    @Query(
        "DELETE FROM operation_pins WHERE operationId IN (SELECT id FROM file_operations WHERE accountId = :accountId)",
    )
    suspend fun deleteOperationPins(accountId: String)

    @Query(
        "DELETE FROM operation_pins WHERE operationId IN " +
            "(SELECT id FROM file_operations WHERE accountId = :accountId AND state = 'BLOCKED_VAULT')",
    )
    suspend fun clearBlockedOperations(accountId: String)

    @Query("DELETE FROM operation_pins WHERE operationId = :operationId")
    suspend fun clearOperation(operationId: String)
}
