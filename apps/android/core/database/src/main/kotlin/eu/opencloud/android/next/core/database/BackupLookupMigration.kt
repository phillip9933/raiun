package eu.opencloud.android.next.core.database

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

/** Avoid scanning every pending upload for each file in a large backup. No existing rows are rewritten. */
val MIGRATION_25_26 =
    object : Migration(25, 26) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL(
                "CREATE INDEX IF NOT EXISTS index_transfers_backup_lookup " +
                    "ON transfers(accountId, spaceId, sourceUri, destinationPath, direction, state)",
            )
        }
    }
