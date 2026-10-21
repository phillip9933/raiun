package eu.opencloud.android.next.core.database

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

/** Stable scheduling order independent of wall-clock adjustments and random transfer IDs. */
@Entity(
    tableName = "transfer_queue",
    foreignKeys = [
        ForeignKey(
            entity = TransferEntity::class,
            parentColumns = ["id"],
            childColumns = ["transferId"],
            onDelete = ForeignKey.CASCADE,
        ),
    ],
    indices = [Index(value = ["transferId"], unique = true)],
)
data class TransferQueueEntry(
    @PrimaryKey(autoGenerate = true) val sequence: Long = 0,
    val transferId: String,
)

val MIGRATION_15_16 =
    object : Migration(15, 16) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS transfer_queue " +
                    "(sequence INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, transferId TEXT NOT NULL, " +
                    "FOREIGN KEY(transferId) REFERENCES transfers(id) ON UPDATE NO ACTION ON DELETE CASCADE)",
            )
            db.execSQL("CREATE UNIQUE INDEX index_transfer_queue_transferId ON transfer_queue(transferId)")
            // Preserve the previous deterministic ordering once; future enqueue order never uses the clock.
            db.execSQL(
                "INSERT INTO transfer_queue(transferId) SELECT id FROM transfers ORDER BY createdAtEpochMillis, id",
            )
        }
    }
