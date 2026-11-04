package eu.opencloud.android.next.core.database

import androidx.room.ColumnInfo
import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Entity(
    tableName = "folder_backups",
    indices = [Index(value = ["accountId", "sourceTreeUri", "mediaType"], unique = true)],
)
data class FolderBackupEntity(
    @androidx.room.PrimaryKey val id: String,
    val accountId: String,
    val spaceId: String,
    val sourceTreeUri: String,
    val sourceDisplayName: String = "",
    val destinationPath: String,
    val mediaType: String,
    val wifiOnly: Boolean,
    val chargingOnly: Boolean,
    val deleteAfterUpload: Boolean,
    val enabled: Boolean = true,
    val lastSafeScanEpochMillis: Long = 0,
    @androidx.room.ColumnInfo(defaultValue = "'NONE'") val dateOrganization: String = "NONE",
    @androidx.room.ColumnInfo(defaultValue = "'SPACE'") val destinationKind: String = "SPACE",
    val sharedShareId: String? = null,
    val sharedFolderId: String? = null,
    @androidx.room.ColumnInfo(defaultValue = "0") val destinationRevision: Long = 0,
    @androidx.room.ColumnInfo(defaultValue = "''") val exclusionPatterns: String = "",
)

@Dao
interface FolderBackupDao {
    @Query(
        "UPDATE folder_backups SET enabled = 0 WHERE accountId = :accountId AND spaceId = :spaceId " +
            "AND (:path IS NULL OR rtrim(destinationPath, '/') = :path " +
            "OR substr(destinationPath, 1, length(:path) + 1) = :path || '/' " +
            "OR substr(:path, 1, length(rtrim(destinationPath, '/')) + 1) = rtrim(destinationPath, '/') || '/')",
    )
    suspend fun disableVault(
        accountId: String,
        spaceId: String,
        path: String?,
    )

    @Query("SELECT * FROM folder_backups WHERE accountId = :accountId ORDER BY mediaType")
    fun observeForAccount(accountId: String): Flow<List<FolderBackupEntity>>

    @Query("SELECT * FROM folder_backups WHERE enabled = 1")
    suspend fun findEnabled(): List<FolderBackupEntity>

    @Query("SELECT * FROM folder_backups WHERE id = :id LIMIT 1")
    suspend fun findById(id: String): FolderBackupEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(configuration: FolderBackupEntity)

    @Query("DELETE FROM folder_backups WHERE id = :id")
    suspend fun delete(id: String)

    @Query("DELETE FROM folder_backups WHERE accountId = :accountId")
    suspend fun deleteForAccount(accountId: String)
}
