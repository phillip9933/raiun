package eu.opencloud.android.next.core.database

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

val MIGRATION_24_25 =
    object : Migration(24, 25) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL("ALTER TABLE folder_backups ADD COLUMN exclusionPatterns TEXT NOT NULL DEFAULT ''")
        }
    }
