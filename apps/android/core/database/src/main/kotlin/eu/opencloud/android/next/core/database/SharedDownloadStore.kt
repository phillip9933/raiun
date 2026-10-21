package eu.opencloud.android.next.core.database

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.Insert
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.migration.Migration
import androidx.room.withTransaction
import androidx.sqlite.db.SupportSQLiteDatabase

@Entity(
    tableName = "shared_download_intents",
    indices = [Index(value = ["accountId", "scopeId"])],
    foreignKeys = [
        ForeignKey(
            entity = TransferEntity::class,
            parentColumns = ["id"],
            childColumns = ["transferId"],
            onDelete = ForeignKey.CASCADE,
        ),
        ForeignKey(
            entity = SharedFolderScopeEntity::class,
            parentColumns = ["accountId", "scopeId"],
            childColumns = ["accountId", "scopeId"],
            onDelete = ForeignKey.CASCADE,
        ),
    ],
)
data class SharedDownloadIntent(
    @PrimaryKey val transferId: String,
    val accountId: String,
    val scopeId: String,
    val remoteId: String,
    val path: String,
    val sizeBytes: Long,
    val eTag: String?,
)

@Dao
interface SharedDownloadDao {
    @Insert suspend fun insert(intent: SharedDownloadIntent)

    @Query("SELECT * FROM shared_download_intents WHERE transferId = :id")
    suspend fun find(id: String): SharedDownloadIntent?
}

data class SharedDownloadRecord(
    val transfer: TransferEntity,
    val intent: SharedDownloadIntent,
    val scope: SharedFolderScopeEntity,
)

/** Durable intent only. Fresh server resolution and verified byte publication are separate worker obligations. */
class SharedDownloadStore(
    private val database: FileBrowserDatabase,
) {
    private val inventory = IncomingShareStore(database)
    private val cache = database.sharedFolderCacheDao()
    private val transfers = database.transferDao()
    private val intents = database.sharedDownloadDao()

    suspend fun enqueue(
        lease: IncomingShareLease,
        scope: SharedFolderScopeEntity,
        entry: SharedFolderEntry,
        transfer: TransferEntity,
    ): TransferEntity? =
        database.withTransaction {
            requireSelection(scope, entry, transfer)
            require(scope.accountId == lease.account.id && scope.shareId == lease.share.id)
            require(scope.rootItemId == lease.share.remoteId && lease.share.isFolder)
            if (excluded(scope, entry.path)) return@withTransaction null
            val current =
                inventory.isCurrent(lease) &&
                    cache.scope(scope.accountId, scope.scopeId) == scope &&
                    cache.entry(scope.accountId, scope.scopeId, entry.remoteId) == entry
            if (!current) return@withTransaction null
            val intent =
                SharedDownloadIntent(
                    transfer.id,
                    scope.accountId,
                    scope.scopeId,
                    entry.remoteId,
                    entry.path,
                    entry.sizeBytes,
                    entry.eTag,
                )
            val existing = transfers.findActiveDownload(scope.accountId, scope.scopeId, entry.remoteId)
            if (existing != null) {
                require(existing.locationKind == "SHARED_FOLDER")
                if (intents.find(existing.id) != intent.copy(transferId = existing.id)) return@withTransaction null
                val joined = existing.copy(offlinePin = existing.offlinePin || transfer.offlinePin)
                transfers.update(joined)
                joined
            } else {
                transfers.insert(transfer)
                intents.insert(intent)
                transfer
            }
        }

    /** Restores local ownership, not server authorization; a removed scope cannot fall back to a whole drive. */
    suspend fun read(id: String): SharedDownloadRecord? =
        database.withTransaction {
            val intent = intents.find(id) ?: return@withTransaction null
            val transfer = transfers.findById(id) ?: return@withTransaction null
            val scope = cache.scope(intent.accountId, intent.scopeId) ?: return@withTransaction null
            val lease = inventory.beginAccess(intent.accountId, scope.shareId) ?: return@withTransaction null
            val entry = cache.entry(intent.accountId, intent.scopeId, intent.remoteId)
            val currentScope =
                scope.rootItemId == lease.share.remoteId && lease.share.isFolder && matches(intent, transfer)
            val currentEntry = entry != null && !entry.isFolder && entry.matches(intent)
            if (!currentScope || !currentEntry || excluded(scope, intent.path)) {
                null
            } else {
                SharedDownloadRecord(transfer, intent, scope)
            }
        }

    suspend fun retry(
        lease: IncomingShareLease,
        expected: SharedDownloadRecord,
        workerId: String,
        now: Long,
    ): TransferEntity? =
        database.withTransaction {
            require(workerId.isNotBlank() && workerId != expected.transfer.workId)
            val current = read(expected.transfer.id) ?: return@withTransaction null
            val validLease =
                inventory.isCurrent(lease) &&
                    lease.account.id == current.intent.accountId &&
                    lease.share.id == current.scope.shareId
            if (current != expected ||
                !validLease ||
                current.transfer.state !in setOf("FAILED", "CANCELLED", "RETRY")
            ) {
                return@withTransaction null
            }
            val intent = current.intent
            if (transfers.findActiveDownload(intent.accountId, intent.scopeId, intent.remoteId) != null) {
                return@withTransaction null
            }
            val entry = cache.entry(intent.accountId, intent.scopeId, intent.remoteId) ?: return@withTransaction null
            val sameVersion =
                entry.path == intent.path && entry.sizeBytes == intent.sizeBytes && entry.eTag == intent.eTag
            if (entry.isFolder || !sameVersion) {
                return@withTransaction null
            }
            val replacement =
                current.transfer.copy(
                    state = "QUEUED",
                    workId = workerId,
                    attemptCount = 0,
                    bytesTransferred = 0,
                    error = null,
                    errorCode = null,
                    notBeforeEpochMillis = 0,
                    updatedAtEpochMillis = now,
                    tusUrl = null,
                    tusOffset = 0,
                    verificationPending = false,
                )
            transfers.retry(current.transfer, replacement)
        }

    private fun requireSelection(
        scope: SharedFolderScopeEntity,
        entry: SharedFolderEntry,
        transfer: TransferEntity,
    ) {
        require(!entry.isFolder && entry.sizeBytes >= 0)
        require(entry.accountId == scope.accountId && entry.scopeId == scope.scopeId)
        val intent =
            SharedDownloadIntent(
                transfer.id,
                entry.accountId,
                entry.scopeId,
                entry.remoteId,
                entry.path,
                entry.sizeBytes,
                entry.eTag,
            )
        require(matches(intent, transfer))
        require(transfer.state == "QUEUED" && transfer.workId == null && transfer.attemptCount == 0)
        require(transfer.sourceUri == null && !transfer.deleteSourceAfterSuccess && !transfer.overwrite)
    }

    private fun matches(
        intent: SharedDownloadIntent,
        transfer: TransferEntity,
    ): Boolean =
        transfer.locationKind == "SHARED_FOLDER" &&
            transfer.direction == "DOWNLOAD" &&
            transfer.accountId == intent.accountId &&
            transfer.spaceId == intent.scopeId &&
            transfer.resourceId == intent.remoteId &&
            transfer.destinationPath == intent.path &&
            transfer.bytesTotal == intent.sizeBytes &&
            transfer.expectedETag == intent.eTag

    private fun SharedFolderEntry.matches(intent: SharedDownloadIntent): Boolean =
        path == intent.path && sizeBytes == intent.sizeBytes && eTag == intent.eTag

    private suspend fun excluded(
        scope: SharedFolderScopeEntity,
        path: String,
    ): Boolean =
        database.vaultExclusionDao().denies(scope.accountId, scope.serverDriveId, "") ||
            database.sharedVaultExclusionDao().denies(scope.accountId, scope.scopeId, path)
}

val MIGRATION_18_19 =
    object : Migration(18, 19) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL("ALTER TABLE transfers ADD COLUMN locationKind TEXT NOT NULL DEFAULT 'SPACE'")
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS shared_download_intents (transferId TEXT NOT NULL, " +
                    "accountId TEXT NOT NULL, scopeId TEXT NOT NULL, remoteId TEXT NOT NULL, path TEXT NOT NULL, " +
                    "sizeBytes INTEGER NOT NULL, eTag TEXT, PRIMARY KEY(transferId), " +
                    "FOREIGN KEY(transferId) REFERENCES transfers(id) ON UPDATE NO ACTION ON DELETE CASCADE, " +
                    "FOREIGN KEY(accountId, scopeId) REFERENCES shared_folder_scopes(accountId, scopeId) " +
                    "ON UPDATE NO ACTION ON DELETE CASCADE)",
            )
            db.execSQL(
                "CREATE INDEX IF NOT EXISTS index_shared_download_intents_accountId_scopeId " +
                    "ON shared_download_intents(accountId, scopeId)",
            )
        }
    }
