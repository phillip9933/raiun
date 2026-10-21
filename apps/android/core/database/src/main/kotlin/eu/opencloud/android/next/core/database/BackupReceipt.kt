package eu.opencloud.android.next.core.database

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

@Entity(tableName = "backup_receipts", primaryKeys = ["pairId", "sourceKey"])
data class BackupReceipt(
    val pairId: String,
    val sourceKey: String,
    val acceptedSignature: String? = null,
    val observedSignature: String? = null,
    val observedAt: Long = 0,
)

@Dao
interface BackupReceiptDao {
    @Query("SELECT * FROM backup_receipts WHERE pairId = :pairId AND sourceKey = :sourceKey")
    suspend fun find(
        pairId: String,
        sourceKey: String,
    ): BackupReceipt?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun save(receipt: BackupReceipt)

    @Query("DELETE FROM backup_receipts WHERE pairId = :pairId")
    suspend fun deletePair(pairId: String)

    @Query("DELETE FROM backup_receipts WHERE pairId IN (SELECT id FROM folder_backups WHERE accountId = :accountId)")
    suspend fun deleteAccount(accountId: String)
}
