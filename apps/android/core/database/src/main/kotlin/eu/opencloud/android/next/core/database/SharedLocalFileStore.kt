package eu.opencloud.android.next.core.database

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Query
import androidx.room.Upsert
import androidx.room.migration.Migration
import androidx.room.withTransaction
import androidx.sqlite.db.SupportSQLiteDatabase
import kotlinx.coroutines.flow.Flow

@Entity(
    tableName = "shared_local_files",
    primaryKeys = ["accountId", "scopeId", "remoteId"],
    foreignKeys = [
        ForeignKey(
            entity = SharedFolderScopeEntity::class,
            parentColumns = ["accountId", "scopeId"],
            childColumns = ["accountId", "scopeId"],
            onDelete = ForeignKey.CASCADE,
        ),
    ],
)
data class SharedLocalFile(
    val accountId: String,
    val scopeId: String,
    val remoteId: String,
    val path: String,
    val sizeBytes: Long,
    val eTag: String?,
    val localPath: String,
    val sha256: String,
    val downloadedAtEpochMillis: Long,
    val offlinePinned: Boolean,
)

@Dao
interface SharedLocalFileDao {
    @Query("SELECT * FROM shared_local_files WHERE accountId = :account ORDER BY scopeId, remoteId")
    fun observe(account: String): Flow<List<SharedLocalFile>>

    @Upsert suspend fun save(file: SharedLocalFile)

    @Delete suspend fun delete(file: SharedLocalFile): Int

    @Query(
        "DELETE FROM shared_local_files WHERE accountId = :account AND offlinePinned = 0 " +
            "AND localPath NOT IN (:protectedPaths) " +
            "AND (:before IS NULL OR downloadedAtEpochMillis < :before) " +
            "AND NOT EXISTS (SELECT 1 FROM transfers t WHERE t.accountId = shared_local_files.accountId " +
            "AND t.spaceId = shared_local_files.scopeId AND t.resourceId = shared_local_files.remoteId " +
            "AND t.locationKind = 'SHARED_FOLDER' AND t.direction = 'DOWNLOAD' " +
            "AND t.state IN ('QUEUED', 'RUNNING', 'RETRY'))",
    )
    suspend fun removeTemporary(
        account: String,
        before: Long?,
        protectedPaths: List<String>,
    ): Int

    @Query("SELECT localPath FROM shared_local_files WHERE accountId = :account")
    suspend fun retainedPaths(account: String): List<String>

    @Query(
        "DELETE FROM shared_local_files WHERE accountId = :account AND scopeId = :scope " +
            "AND ((:path = '/' AND substr(path, 1, 1) = '/') OR " +
            "path = :path OR substr(path, 1, length(:path) + 1) = :path || '/')",
    )
    suspend fun deleteSubtree(
        account: String,
        scope: String,
        path: String,
    ): Int

    @Query("SELECT * FROM shared_local_files WHERE accountId = :account AND scopeId = :scope AND remoteId = :remote")
    suspend fun find(
        account: String,
        scope: String,
        remote: String,
    ): SharedLocalFile?
}

/** Caller must validate the server response, length and private file bytes before constructing this evidence. */
data class SharedFileCommit(
    val localPath: String,
    val sizeBytes: Long,
    val sha256: String,
    val completedAtEpochMillis: Long,
)

data class SharedFilePublication(
    val previousLocalPath: String?,
)

/** Metadata publication gate, not a file writer or server/content authorization service. */
class SharedLocalFileStore(
    private val database: FileBrowserDatabase,
) {
    private val inventory = IncomingShareStore(database)
    private val downloads = SharedDownloadStore(database)
    private val cache = database.sharedFolderCacheDao()
    private val files = database.sharedLocalFileDao()

    suspend fun publish(
        lease: IncomingShareLease,
        expected: SharedDownloadRecord,
        commit: SharedFileCommit,
    ): SharedFilePublication? =
        database.withTransaction {
            require(commit.localPath.isNotBlank() && commit.sizeBytes >= 0)
            require(commit.sha256.matches(Regex("[0-9a-f]{64}")))
            val current = downloads.read(expected.transfer.id) ?: return@withTransaction null
            val entry = cache.entry(current.intent.accountId, current.intent.scopeId, current.intent.remoteId)
            val authorized =
                lease.account.id == current.scope.accountId &&
                    lease.share.id == current.scope.shareId &&
                    inventory.isCurrent(lease) &&
                    !database.vaultExclusionDao().denies(
                        current.scope.accountId,
                        current.scope.serverDriveId,
                        "",
                    ) &&
                    !database.sharedVaultExclusionDao().denies(
                        current.scope.accountId,
                        current.scope.scopeId,
                        current.intent.path,
                    )
            if (!authorized || !sameOwnedTransfer(expected, current) || !unchanged(entry, current.intent)) {
                return@withTransaction null
            }
            require(commit.sizeBytes == current.intent.sizeBytes)
            val intent = current.intent
            val previous = files.find(intent.accountId, intent.scopeId, intent.remoteId)
            files.save(
                SharedLocalFile(
                    intent.accountId,
                    intent.scopeId,
                    intent.remoteId,
                    intent.path,
                    intent.sizeBytes,
                    intent.eTag,
                    commit.localPath,
                    commit.sha256,
                    commit.completedAtEpochMillis,
                    current.transfer.offlinePin || previous?.offlinePinned == true,
                ),
            )
            database.transferDao().update(
                current.transfer.copy(
                    state = "SUCCEEDED",
                    bytesTransferred = intent.sizeBytes,
                    error = null,
                    errorCode = null,
                    notBeforeEpochMillis = 0,
                    updatedAtEpochMillis = commit.completedAtEpochMillis,
                ),
            )
            SharedFilePublication(previous?.localPath?.takeIf { it != commit.localPath })
        }

    /** Requires current access evidence; the caller must also revalidate server access and actual cached bytes. */
    suspend fun read(
        lease: IncomingShareLease,
        entry: SharedFolderEntry,
    ): SharedLocalFile? =
        database.withTransaction {
            val scope = cache.scope(entry.accountId, entry.scopeId) ?: return@withTransaction null
            val permitted =
                lease.account.id == entry.accountId &&
                    lease.share.id == scope.shareId &&
                    lease.share.remoteId == scope.rootItemId &&
                    inventory.isCurrent(lease) &&
                    !database.vaultExclusionDao().denies(entry.accountId, scope.serverDriveId, "") &&
                    !database.sharedVaultExclusionDao().denies(entry.accountId, entry.scopeId, entry.path)
            if (!permitted || cache.entry(entry.accountId, entry.scopeId, entry.remoteId) != entry) {
                return@withTransaction null
            }
            files.find(entry.accountId, entry.scopeId, entry.remoteId)?.takeIf {
                !entry.isFolder && it.path == entry.path && it.sizeBytes == entry.sizeBytes && it.eTag == entry.eTag
            }
        }

    /** Caller holds the content gate and has verified content authorization and bytes. */
    suspend fun setPinned(
        lease: IncomingShareLease,
        entry: SharedFolderEntry,
        expected: SharedLocalFile,
        pinned: Boolean,
    ): Boolean =
        database.withTransaction {
            if (read(lease, entry) != expected || busy(expected)) return@withTransaction false
            files.save(expected.copy(offlinePinned = pinned))
            true
        }

    /** Local-only removal: stale actions must not delete a replacement or race a queued download. */
    suspend fun remove(expected: SharedLocalFile): Boolean =
        database.withTransaction {
            val current = files.find(expected.accountId, expected.scopeId, expected.remoteId)
            if (current != expected || busy(expected)) return@withTransaction false
            files.delete(expected) == 1
        }

    private suspend fun busy(file: SharedLocalFile): Boolean =
        database.transferDao().findActiveDownload(file.accountId, file.scopeId, file.remoteId) != null

    private fun sameOwnedTransfer(
        expected: SharedDownloadRecord,
        current: SharedDownloadRecord,
    ): Boolean {
        val owner = expected.transfer.workId
        return !owner.isNullOrBlank() &&
            expected.transfer.state == "RUNNING" &&
            current.transfer.workId == owner &&
            current.transfer.state == "RUNNING" &&
            current.intent == expected.intent &&
            current.scope == expected.scope
    }

    private fun unchanged(
        entry: SharedFolderEntry?,
        intent: SharedDownloadIntent,
    ): Boolean =
        entry != null &&
            !entry.isFolder &&
            entry.path == intent.path &&
            entry.sizeBytes == intent.sizeBytes &&
            entry.eTag == intent.eTag
}

val MIGRATION_19_20 =
    object : Migration(19, 20) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS shared_local_files (accountId TEXT NOT NULL, scopeId TEXT NOT NULL, " +
                    "remoteId TEXT NOT NULL, path TEXT NOT NULL, sizeBytes INTEGER NOT NULL, eTag TEXT, " +
                    "localPath TEXT NOT NULL, sha256 TEXT NOT NULL, downloadedAtEpochMillis INTEGER NOT NULL, " +
                    "offlinePinned INTEGER NOT NULL, PRIMARY KEY(accountId, scopeId, remoteId), " +
                    "FOREIGN KEY(accountId, scopeId) REFERENCES shared_folder_scopes(accountId, scopeId) " +
                    "ON UPDATE NO ACTION ON DELETE CASCADE)",
            )
        }
    }
