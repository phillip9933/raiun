package eu.opencloud.android.next.core.database

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.Update
import kotlinx.coroutines.flow.Flow

@Entity(
    tableName = "transfers",
    indices = [
        Index(value = ["accountId", "state"]),
        Index(value = ["accountId", "spaceId", "resourceId", "direction"]),
        Index(
            name = "index_transfers_backup_lookup",
            value = ["accountId", "spaceId", "sourceUri", "destinationPath", "direction", "state"],
        ),
    ],
)
data class TransferEntity(
    @androidx.room.PrimaryKey val id: String,
    val accountId: String,
    val spaceId: String,
    val resourceId: String?,
    val direction: String,
    val sourceUri: String?,
    val destinationPath: String,
    val displayName: String,
    val mimeType: String?,
    val bytesTotal: Long,
    val bytesTransferred: Long = 0,
    val state: String = TransferState.QUEUED.persistedValue,
    val error: String? = null,
    val workId: String? = null,
    val overwrite: Boolean = false,
    val offlinePin: Boolean = false,
    val deleteSourceAfterSuccess: Boolean = false,
    val tusUrl: String? = null,
    val tusOffset: Long = 0,
    val attemptCount: Int = 0,
    val createdAtEpochMillis: Long,
    val updatedAtEpochMillis: Long,
    val errorCode: String? = null,
    @androidx.room.ColumnInfo(defaultValue = "0") val notBeforeEpochMillis: Long = 0,
    @androidx.room.ColumnInfo(defaultValue = "0") val verificationPending: Boolean = false,
    val expectedETag: String? = null,
    val verifiedETag: String? = null,
    @androidx.room.ColumnInfo(defaultValue = "'SPACE'") val locationKind: String = "SPACE",
)

enum class TransferDirection { UPLOAD, DOWNLOAD }

typealias TransferState = eu.opencloud.android.next.core.model.TransferState

@Dao
interface TransferDao {
    @Query(
        "UPDATE transfers SET state = 'CANCELLED', error = NULL, errorCode = NULL, " +
            "notBeforeEpochMillis = 0, attemptCount = 0, updatedAtEpochMillis = :now " +
            "WHERE accountId = :accountId AND direction = 'UPLOAD' AND state = 'CONFLICT'",
    )
    suspend fun cancelUploadConflicts(
        accountId: String,
        now: Long,
    ): Int

    @Query(
        "UPDATE transfers SET state = 'CANCELLED', error = NULL, errorCode = NULL " +
            "WHERE accountId = :accountId AND spaceId = :spaceId AND state IN ('QUEUED', 'RUNNING', 'RETRY') " +
            "AND (destinationPath = :path OR substr(destinationPath, 1, length(:path) + 1) = :path || '/')",
    )
    suspend fun cancelTree(
        accountId: String,
        spaceId: String,
        path: String,
    )

    @Query(
        "UPDATE transfers SET state = 'CANCELLED', error = NULL, errorCode = NULL " +
            "WHERE accountId = :accountId AND spaceId = :spaceId AND state IN ('QUEUED', 'RUNNING', 'RETRY')",
    )
    suspend fun cancelSpace(
        accountId: String,
        spaceId: String,
    )

    @Query(
        "SELECT EXISTS(SELECT 1 FROM transfers t JOIN transfer_queue q ON q.transferId = t.id " +
            "WHERE t.id != :id AND t.accountId = :account AND t.spaceId = :space " +
            "AND t.destinationPath = :path AND t.direction = 'UPLOAD' " +
            "AND (t.state = 'RUNNING' OR (t.state IN ('QUEUED', 'RETRY') " +
            "AND q.sequence < (SELECT sequence FROM transfer_queue WHERE transferId = :id))))",
    )
    suspend fun uploadDestinationBusy(
        id: String,
        account: String,
        space: String,
        path: String,
    ): Boolean

    @Transaction
    suspend fun retry(
        expected: TransferEntity,
        replacement: TransferEntity,
    ): TransferEntity? {
        val current = findById(expected.id)
        if (current == null ||
            current != expected ||
            !current.typedState.allowsExplicitRetry
        ) {
            return null
        }
        require(replacement.id == current.id && replacement.state == "QUEUED")
        update(replacement)
        removeQueueEntry(current.id)
        insertQueueEntry(TransferQueueEntry(transferId = current.id))
        return replacement
    }

    @Query(
        "UPDATE transfers SET bytesTransferred = :bytes, updatedAtEpochMillis = :now, " +
            "verificationPending = CASE WHEN direction = 'UPLOAD' AND :bytes = bytesTotal " +
            "THEN 1 ELSE verificationPending END " +
            "WHERE id = :id AND workId = :workerId AND state = 'RUNNING'",
    )
    suspend fun updateProgress(
        id: String,
        workerId: String?,
        bytes: Long,
        now: Long,
    ): Int

    @Transaction
    suspend fun claim(
        id: String,
        workerId: String,
        now: Long,
    ): TransferEntity? {
        val current = findById(id)
        val ownedByAnotherWorker = current?.workId != null && current.workId != workerId
        if (current == null ||
            !current.typedState.isRunnable ||
            ownedByAnotherWorker
        ) {
            return null
        }
        val running =
            current.copy(
                state = TransferState.RUNNING.persistedValue,
                workId = workerId,
                updatedAtEpochMillis = now,
            )
        val blocked =
            current.direction == "UPLOAD" &&
                uploadDestinationBusy(
                    current.id,
                    current.accountId,
                    current.spaceId,
                    current.destinationPath,
                )
        return if (blocked) {
            // This worker has not started network I/O. Release its persisted RUNNING marker
            // so overlapping intents left by an older process cannot wait on each other forever.
            if (current.state == TransferState.RUNNING.name) {
                update(current.copy(state = TransferState.RETRY.persistedValue, updatedAtEpochMillis = now))
            }
            null
        } else {
            update(running)
            running
        }
    }

    @Transaction
    suspend fun updateActive(transfer: TransferEntity): Boolean {
        val current = findById(transfer.id)
        val owned = current?.typedState?.isRunnable == true && current.workId == transfer.workId
        if (transfer.typedState == TransferState.UNKNOWN || !owned) return false
        update(transfer)
        return true
    }

    @Transaction
    suspend fun schedule(
        transfer: TransferEntity,
        workId: String,
        now: Long,
    ): Boolean {
        val current = findById(transfer.id)
        if (current == null ||
            !current.typedState.isRunnable ||
            current.workId != transfer.workId
        ) {
            return false
        }
        update(current.copy(workId = workId, updatedAtEpochMillis = now))
        return true
    }

    @Query(
        "UPDATE transfers SET state = 'CANCELLED', error = NULL, errorCode = NULL WHERE id = :id AND state != 'SUCCEEDED'",
    )
    suspend fun cancel(id: String)

    @Query("SELECT * FROM transfers WHERE accountId = :accountId ORDER BY createdAtEpochMillis DESC")
    fun observeForAccount(accountId: String): Flow<List<TransferEntity>>

    @Query("SELECT * FROM transfers WHERE id = :id LIMIT 1")
    suspend fun findById(id: String): TransferEntity?

    @Query(
        "SELECT t.* FROM transfers t JOIN accounts a ON a.id = t.accountId " +
            "WHERE t.accountId = :account AND t.id = :id AND a.isActive = 1 LIMIT 1",
    )
    fun observeById(
        account: String,
        id: String,
    ): Flow<TransferEntity?>

    @Query("SELECT * FROM transfers WHERE state IN ('QUEUED', 'RUNNING', 'RETRY')")
    suspend fun findPending(): List<TransferEntity>

    @Query(
        "SELECT id FROM transfers WHERE accountId = :account AND sourceUri = :scope AND locationKind = 'VAULT' AND direction = 'DOWNLOAD' AND state = 'AWAITING_UNLOCK' ORDER BY id LIMIT 1",
    )
    fun observeAwaitingCiphertextDownloads(
        account: String,
        scope: String,
    ): Flow<String?>

    @Query(
        "SELECT * FROM transfers WHERE accountId = :account AND sourceUri = :scope AND locationKind = 'VAULT' AND direction = 'DOWNLOAD' AND state = 'AWAITING_UNLOCK' AND id > :afterId ORDER BY id LIMIT :limit",
    )
    suspend fun awaitingCiphertextDownloadsPage(
        account: String,
        scope: String,
        afterId: String,
        limit: Int,
    ): List<TransferEntity>

    @Query(
        "SELECT * FROM transfers WHERE id > :afterId AND state IN ('QUEUED', 'RUNNING', 'RETRY') " +
            "ORDER BY id LIMIT :limit",
    )
    suspend fun findPendingPage(
        afterId: String,
        limit: Int,
    ): List<TransferEntity>

    @Query(
        "SELECT EXISTS(SELECT 1 FROM transfers WHERE accountId = :accountId AND spaceId = :spaceId " +
            "AND direction = 'UPLOAD' AND state IN ('QUEUED', 'RUNNING', 'RETRY') " +
            "AND sourceUri = :sourceUri AND destinationPath = :destinationPath)",
    )
    suspend fun hasActiveBackupUpload(
        accountId: String,
        spaceId: String,
        sourceUri: String,
        destinationPath: String,
    ): Boolean

    @Query("SELECT * FROM transfers WHERE accountId = :accountId")
    suspend fun findForAccount(accountId: String): List<TransferEntity>

    @Query(
        "SELECT * FROM transfers WHERE accountId = :accountId AND spaceId = :spaceId " +
            "AND resourceId = :resourceId AND direction = 'DOWNLOAD' " +
            "AND state IN ('QUEUED', 'RUNNING', 'RETRY') LIMIT 1",
    )
    suspend fun findActiveDownload(
        accountId: String,
        spaceId: String,
        resourceId: String,
    ): TransferEntity?

    @Query(
        "SELECT * FROM transfers WHERE accountId = :accountId AND spaceId = :spaceId " +
            "AND resourceId = :resourceId AND direction = 'DOWNLOAD' " +
            "AND destinationPath = :path AND bytesTotal = :size " +
            "AND state IN ('FAILED', 'CONFLICT') LIMIT 1",
    )
    suspend fun findBlockedDownload(
        accountId: String,
        spaceId: String,
        resourceId: String,
        path: String,
        size: Long,
    ): TransferEntity?

    @Query(
        "SELECT * FROM transfers WHERE accountId = :accountId AND spaceId = :spaceId " +
            "AND sourceUri = :sourceUri AND destinationPath = :destinationPath AND direction = 'UPLOAD' " +
            "AND state IN ('QUEUED', 'RUNNING', 'RETRY') LIMIT 1",
    )
    suspend fun findActiveUpload(
        accountId: String,
        spaceId: String,
        sourceUri: String,
        destinationPath: String,
    ): TransferEntity?

    @Transaction
    suspend fun insert(transfer: TransferEntity) {
        insertTransfer(transfer)
        insertQueueEntry(TransferQueueEntry(transferId = transfer.id))
    }

    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insertTransfer(transfer: TransferEntity)

    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insertQueueEntry(entry: TransferQueueEntry)

    @Query("DELETE FROM transfer_queue WHERE transferId = :id")
    suspend fun removeQueueEntry(id: String)

    @Update
    suspend fun update(transfer: TransferEntity)

    @Query("DELETE FROM transfers WHERE accountId = :accountId AND state IN ('SUCCEEDED', 'CANCELLED')")
    suspend fun deleteHistory(accountId: String)

    @Query("DELETE FROM transfers WHERE accountId = :accountId")
    suspend fun deleteAllForAccount(accountId: String)

    @Query("SELECT * FROM transfers WHERE state = 'CONFLICT' ORDER BY updatedAtEpochMillis DESC")
    fun observeConflicts(): Flow<List<TransferEntity>>
}
