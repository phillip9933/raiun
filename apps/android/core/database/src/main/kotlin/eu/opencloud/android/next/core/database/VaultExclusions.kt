package eu.opencloud.android.next.core.database

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

/** Empty path marks an entire drive; folder paths have no trailing slash. */
@Entity(tableName = "vault_exclusions", primaryKeys = ["accountId", "spaceId", "path"])
data class VaultExclusion(
    val accountId: String,
    val spaceId: String,
    val path: String,
)

@Dao
interface VaultExclusionDao {
    @Query("SELECT * FROM vault_exclusions WHERE accountId = :accountId ORDER BY spaceId, path")
    fun observe(accountId: String): kotlinx.coroutines.flow.Flow<List<VaultExclusion>>

    @Query("SELECT * FROM vault_exclusions WHERE accountId = :accountId ORDER BY spaceId, path")
    suspend fun allForAccount(accountId: String): List<VaultExclusion>

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun record(exclusion: VaultExclusion)

    @Query(
        "SELECT EXISTS(SELECT 1 FROM vault_exclusions WHERE accountId = :accountId AND spaceId = :spaceId " +
            "AND (path = '' OR path = rtrim(:destination, '/') " +
            "OR substr(:destination, 1, length(path) + 1) = path || '/' " +
            "OR (:includeChildren = 1 AND substr(path, 1, length(rtrim(:destination, '/')) + 1) " +
            "= rtrim(:destination, '/') || '/')))",
    )
    suspend fun denies(
        accountId: String,
        spaceId: String,
        destination: String,
        includeChildren: Boolean = false,
    ): Boolean

    @Query("DELETE FROM vault_exclusions WHERE accountId = :accountId AND spaceId = :spaceId AND path = :path")
    suspend fun confirmPlain(
        accountId: String,
        spaceId: String,
        path: String,
    )

    @Query("DELETE FROM vault_exclusions WHERE accountId = :accountId")
    suspend fun deleteAccount(accountId: String)
}

val MIGRATION_21_22 =
    object : Migration(21, 22) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS vault_exclusions (accountId TEXT NOT NULL, spaceId TEXT NOT NULL, " +
                    "path TEXT NOT NULL, PRIMARY KEY(accountId, spaceId, path))",
            )
        }
    }

/** Caller owns the accepted discovery transaction. */
internal suspend fun FileBrowserDatabase.excludeVaultDrive(
    accountId: String,
    spaceId: String,
) {
    vaultExclusionDao().record(VaultExclusion(accountId, spaceId, ""))
    sharedFolderVersions.begin(accountId)
    sharedFolderCacheDao().cancelDriveTransfers(accountId, spaceId)
    sharedFolderCacheDao().excludeDrive(accountId, spaceId)
    folderBackupDao().disableVault(accountId, spaceId, null)
    excludedCacheDao().capture(accountId, spaceId, null)
    val spaces = spaceDao()
    spaces.findById(accountId, spaceId)?.let { spaces.upsertAll(listOf(it.copy(isDisabled = true))) }
    fileOperationDao().blockVault(accountId, spaceId, null)
    pendingPinDao().clearBlockedOperations(accountId)
    transferDao().cancelSpace(accountId, spaceId)
    offlineTraversalDao().cancelSpace(accountId, spaceId)
    pendingPinDao().deleteSpace(accountId, spaceId)
    resourceDao().deleteAll(accountId, spaceId)
}
