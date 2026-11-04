package eu.opencloud.android.next.core.database

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Entity(
    tableName = "shares",
    primaryKeys = ["accountId", "remoteId"],
    indices = [Index(value = ["accountId", "sharedWithMe"]), Index(value = ["accountId", "path"])],
)
data class ShareEntity(
    val accountId: String,
    val remoteId: String,
    val resourceId: String?,
    val path: String,
    val shareType: Int,
    val shareWith: String?,
    val displayName: String?,
    val additionalInfo: String?,
    val permissions: Int,
    val sharedAtEpochSeconds: Long,
    val expiresAtEpochMillis: Long?,
    val label: String?,
    val isFolder: Boolean,
    val sharedWithMe: Boolean,
)

@Dao
interface ShareDao {
    @Query("SELECT * FROM shares WHERE accountId = :accountId ORDER BY sharedAtEpochSeconds DESC")
    fun observeForAccount(accountId: String): Flow<List<ShareEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAll(shares: List<ShareEntity>)

    @Query("DELETE FROM shares WHERE accountId = :accountId")
    suspend fun deleteForAccount(accountId: String)

    @Query("DELETE FROM shares WHERE accountId = :accountId AND remoteId = :shareId")
    suspend fun delete(
        accountId: String,
        shareId: String,
    )
}
