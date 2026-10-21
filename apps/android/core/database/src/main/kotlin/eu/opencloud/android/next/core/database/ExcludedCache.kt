package eu.opencloud.android.next.core.database

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

/** Recorded in the same transaction that removes excluded resource metadata. */
@Entity(tableName = "excluded_cache")
data class ExcludedCacheEntity(
    @PrimaryKey val path: String,
)

@Dao
interface ExcludedCacheDao {
    @Query(
        "INSERT OR IGNORE INTO excluded_cache(path) SELECT localPath FROM resources " +
            "WHERE accountId = :accountId AND spaceId = :spaceId AND localPath IS NOT NULL " +
            "AND (:scope IS NULL OR path = :scope OR substr(path, 1, length(:scope) + 1) = :scope || '/')",
    )
    suspend fun capture(
        accountId: String,
        spaceId: String,
        scope: String?,
    )

    @Query("SELECT * FROM excluded_cache ORDER BY rowid LIMIT 512")
    suspend fun pending(): List<ExcludedCacheEntity>

    @Query("UPDATE excluded_cache SET rowid = (SELECT MAX(rowid) + 1 FROM excluded_cache) WHERE path = :path")
    suspend fun defer(path: String)

    @Query("DELETE FROM excluded_cache WHERE path = :path")
    suspend fun forget(path: String)
}

val MIGRATION_20_21 =
    object : Migration(20, 21) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL("CREATE TABLE IF NOT EXISTS excluded_cache (path TEXT NOT NULL PRIMARY KEY)")
        }
    }
