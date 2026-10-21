package eu.opencloud.android.next.core.database

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.migration.Migration
import androidx.room.withTransaction
import androidx.sqlite.db.SupportSQLiteDatabase
import kotlinx.coroutines.flow.Flow
import java.util.UUID

@Entity(
    tableName = "incoming_shares",
    primaryKeys = ["accountId", "id"],
    foreignKeys = [
        ForeignKey(
            entity = AccountEntity::class,
            parentColumns = ["id"],
            childColumns = ["accountId"],
            onDelete = ForeignKey.CASCADE,
        ),
    ],
)
data class IncomingShareEntity(
    val accountId: String,
    val id: String,
    val remoteId: String,
    val name: String,
    val isFolder: Boolean,
    val webDavUrl: String?,
    val metadataJson: String,
)

@Entity(
    tableName = "incoming_share_refreshes",
    primaryKeys = ["accountId"],
    foreignKeys = [
        ForeignKey(
            entity = AccountEntity::class,
            parentColumns = ["id"],
            childColumns = ["accountId"],
            onDelete = ForeignKey.CASCADE,
        ),
    ],
)
data class IncomingShareRefresh(
    val accountId: String,
    val token: String,
)

@Dao
interface IncomingShareDao {
    @Query("SELECT * FROM incoming_shares WHERE accountId = :accountId ORDER BY name, id")
    fun observe(accountId: String): Flow<List<IncomingShareEntity>>

    @Query("SELECT * FROM incoming_shares WHERE accountId = :accountId ORDER BY name, id")
    suspend fun list(accountId: String): List<IncomingShareEntity>

    @Query("SELECT * FROM incoming_shares WHERE accountId = :accountId AND id = :id")
    suspend fun find(
        accountId: String,
        id: String,
    ): IncomingShareEntity?

    @Query("DELETE FROM incoming_shares WHERE accountId = :accountId")
    suspend fun clear(accountId: String)

    @Insert suspend fun insert(values: List<IncomingShareEntity>)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun begin(refresh: IncomingShareRefresh)

    @Query("SELECT token FROM incoming_share_refreshes WHERE accountId = :accountId")
    suspend fun token(accountId: String): String?

    @Query("DELETE FROM incoming_share_refreshes WHERE accountId = :accountId")
    suspend fun finish(accountId: String)
}

/** Independent durable generations prevent old share discovery from racing space/folder refreshes. */
class IncomingShareStore(
    private val database: FileBrowserDatabase,
) {
    private val dao = database.incomingShareDao()

    fun observe(accountId: String) = dao.observe(accountId)

    suspend fun snapshot(accountId: String): IncomingShareSnapshot? =
        database.withTransaction {
            val account = database.accountDao().findById(accountId) ?: return@withTransaction null
            if (!account.isActive || dao.token(accountId) != null) return@withTransaction null
            IncomingShareSnapshot(account, dao.list(accountId), database.incomingShareVersions.capture(accountId))
        }

    suspend fun isCurrent(snapshot: IncomingShareSnapshot): Boolean =
        database.withTransaction {
            database.incomingShareVersions.isCurrent(snapshot.token) &&
                database.accountDao().findById(snapshot.account.id) == snapshot.account &&
                dao.list(snapshot.account.id) == snapshot.shares
        }

    suspend fun list(accountId: String) = dao.list(accountId)

    suspend fun beginAccess(
        accountId: String,
        id: String,
    ): IncomingShareLease? =
        database.withTransaction {
            val account = database.accountDao().findById(accountId) ?: return@withTransaction null
            val share = dao.find(accountId, id) ?: return@withTransaction null
            IncomingShareLease(account, share, database.incomingShareVersions.capture(accountId))
        }

    suspend fun isCurrent(lease: IncomingShareLease): Boolean =
        database.withTransaction {
            database.incomingShareVersions.isCurrent(lease.token) &&
                database.accountDao().findById(lease.account.id) == lease.account &&
                dao.find(lease.account.id, lease.share.id) == lease.share
        }

    suspend fun beginRefresh(accountId: String): String =
        database.withTransaction {
            check(database.accountDao().findById(accountId)?.isActive == true)
            database.incomingShareVersions.begin(accountId)
            UUID.randomUUID().toString().also { dao.begin(IncomingShareRefresh(accountId, it)) }
        }

    suspend fun replace(
        accountId: String,
        token: String,
        values: List<IncomingShareEntity>,
    ): Boolean =
        database.withTransaction {
            if (database.accountDao().findById(accountId)?.isActive != true || dao.token(accountId) != token) {
                return@withTransaction false
            }
            require(values.all { it.accountId == accountId })
            require(values.map { it.id }.toSet().size == values.size)
            dao.clear(accountId)
            dao.insert(values)
            database.sharedFolderCacheDao().prune(accountId)
            dao.finish(accountId)
            database.incomingShareVersions.begin(accountId)
            true
        }
}

/** Process-local guard; callers must recheck before using asynchronously resolved access. */
class IncomingShareSnapshot internal constructor(
    val account: AccountEntity,
    val shares: List<IncomingShareEntity>,
    internal val token: SnapshotToken,
)

/** Process-local guard; callers must recheck before using asynchronously resolved access. */
class IncomingShareLease internal constructor(
    val account: AccountEntity,
    val share: IncomingShareEntity,
    internal val token: SnapshotToken,
)

val MIGRATION_16_17 =
    object : Migration(16, 17) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS incoming_shares " +
                    "(accountId TEXT NOT NULL, id TEXT NOT NULL, remoteId TEXT NOT NULL, name TEXT NOT NULL, " +
                    "isFolder INTEGER NOT NULL, webDavUrl TEXT, metadataJson TEXT NOT NULL, " +
                    "PRIMARY KEY(accountId, id), " +
                    "FOREIGN KEY(accountId) REFERENCES accounts(id) ON UPDATE NO ACTION ON DELETE CASCADE)",
            )
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS incoming_share_refreshes " +
                    "(accountId TEXT NOT NULL, token TEXT NOT NULL, PRIMARY KEY(accountId), " +
                    "FOREIGN KEY(accountId) REFERENCES accounts(id) ON UPDATE NO ACTION ON DELETE CASCADE)",
            )
        }
    }
