package eu.opencloud.android.next.core.database

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

val MIGRATION_14_15 =
    object : Migration(14, 15) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL("ALTER TABLE folder_backups ADD COLUMN dateOrganization TEXT NOT NULL DEFAULT 'NONE'")
            db.execSQL("ALTER TABLE transfers ADD COLUMN verificationPending INTEGER NOT NULL DEFAULT 0")
            db.execSQL("ALTER TABLE transfers ADD COLUMN expectedETag TEXT")
            db.execSQL("ALTER TABLE transfers ADD COLUMN verifiedETag TEXT")
            db.execSQL(
                "CREATE TABLE backup_receipts (pairId TEXT NOT NULL, sourceKey TEXT NOT NULL, " +
                    "acceptedSignature TEXT, observedSignature TEXT, observedAt INTEGER NOT NULL, PRIMARY KEY(pairId, sourceKey))",
            )
            db.execSQL(
                "UPDATE transfers SET verificationPending = 1 WHERE direction = 'UPLOAD' " +
                    "AND bytesTotal > 0 AND bytesTransferred = bytesTotal",
            )
        }
    }
