package eu.opencloud.android.next.core.database

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

val MIGRATION_23_24 =
    object : Migration(23, 24) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL("ALTER TABLE folder_backups ADD COLUMN destinationKind TEXT NOT NULL DEFAULT 'SPACE'")
            db.execSQL("ALTER TABLE folder_backups ADD COLUMN sharedShareId TEXT")
            db.execSQL("ALTER TABLE folder_backups ADD COLUMN sharedFolderId TEXT")
            db.execSQL("ALTER TABLE folder_backups ADD COLUMN destinationRevision INTEGER NOT NULL DEFAULT 0")
        }
    }
