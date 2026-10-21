package eu.opencloud.android.next.core.database

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

@Entity(tableName = "favorite_cursors")
data class FavoriteCursorEntity(
    @PrimaryKey val accountId: String,
    val spaceId: String,
    val resourceId: String,
    val generation: String,
)

@Dao
interface FavoriteCursorDao {
    @Query("SELECT * FROM favorite_cursors WHERE accountId = :accountId")
    suspend fun find(accountId: String): FavoriteCursorEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun save(cursor: FavoriteCursorEntity)

    @Query("DELETE FROM favorite_cursors WHERE accountId = :accountId")
    suspend fun delete(accountId: String)
}

val MIGRATION_11_12 =
    object : Migration(11, 12) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS favorite_cursors (accountId TEXT NOT NULL, spaceId TEXT NOT NULL, " +
                    "resourceId TEXT NOT NULL, generation TEXT NOT NULL, PRIMARY KEY(accountId))",
            )
        }
    }
