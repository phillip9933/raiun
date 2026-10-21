package eu.opencloud.android.next.core.database

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

@Entity(
    tableName = "pending_discoveries",
    primaryKeys = ["accountId", "spaceId", "folderKey"],
    indices = [Index(value = ["revision"], unique = true)],
)
data class PendingDiscoveryEntity(
    val accountId: String,
    val spaceId: String,
    val folderKey: String,
    val revision: String,
)

@Dao
interface PendingDiscoveryDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun save(discovery: PendingDiscoveryEntity)

    @Query("SELECT * FROM pending_discoveries WHERE revision > :after ORDER BY revision LIMIT 128")
    suspend fun page(after: String): List<PendingDiscoveryEntity>

    @Query("SELECT * FROM pending_discoveries WHERE revision = :revision LIMIT 1")
    suspend fun find(revision: String): PendingDiscoveryEntity?

    @Query("DELETE FROM pending_discoveries WHERE revision = :revision")
    suspend fun acknowledge(revision: String)

    @Query("DELETE FROM pending_discoveries WHERE accountId = :accountId")
    suspend fun deleteAccount(accountId: String)
}

val MIGRATION_12_13 =
    object : Migration(12, 13) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS pending_discoveries (accountId TEXT NOT NULL, spaceId TEXT NOT NULL, " +
                    "folderKey TEXT NOT NULL, revision TEXT NOT NULL, PRIMARY KEY(accountId, spaceId, folderKey))",
            )
            db.execSQL("CREATE UNIQUE INDEX index_pending_discoveries_revision ON pending_discoveries (revision)")
        }
    }
