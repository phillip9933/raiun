package eu.opencloud.android.next.core.database

import android.database.sqlite.SQLiteDatabase
import androidx.room.Room
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class HistoricalMigrationTest {
    @Test
    fun `every exported historical schema migrates and retains all seeded column values`() {
        for (version in 1..24) verifyMigration(version)
    }

    // Walks schema tables, rows and columns for exhaustive preservation.
    @Suppress("CyclomaticComplexMethod", "NestedBlockDepth")
    private fun verifyMigration(version: Int) {
        val context = RuntimeEnvironment.getApplication()
        val name = "history-$version.db"
        context.deleteDatabase(name)
        val path = context.getDatabasePath(name).also { it.parentFile?.mkdirs() }
        val schema =
            requireNotNull(
                javaClass.classLoader?.getResourceAsStream(
                    "eu.opencloud.android.next.core.database.FileBrowserDatabase/$version.json",
                ),
            ).bufferedReader().use { JSONObject(it.readText()).getJSONObject("database") }
        val expected = mutableMapOf<String, List<Map<String, String>>>()
        SQLiteDatabase.openOrCreateDatabase(path, null).use { db ->
            val entities = schema.getJSONArray("entities")
            for (index in 0 until entities.length()) {
                val entity = entities.getJSONObject(index)
                val table = entity.getString("tableName")
                db.execSQL(entity.getString("createSql").replace("\${TABLE_NAME}", table))
                val indices = entity.optJSONArray("indices") ?: JSONArray()
                for (item in 0 until indices.length()) {
                    db.execSQL(indices.getJSONObject(item).getString("createSql").replace("\${TABLE_NAME}", table))
                }
                val fields = entity.getJSONArray("fields")
                expected[table] =
                    (1..2).map { row ->
                        val values =
                            (0 until fields.length()).associate { fieldIndex ->
                                val field = fields.getJSONObject(fieldIndex)
                                val column = field.getString("columnName")
                                column to
                                    if (column == "path" && table == "excluded_cache") {
                                        "/cache/file-$row"
                                    } else if (column == "remoteId" && table == "shares") {
                                        "share-$row"
                                    } else if (column == "accountId" && table == "favorite_cursors") {
                                        "account-$row"
                                    } else if (column == "accountId" &&
                                        (
                                            table in setOf("incoming_shares", "incoming_share_refreshes") ||
                                                table.startsWith("shared_")
                                        )
                                    ) {
                                        "id-$row"
                                    } else {
                                        fixtureValue(column, field.getString("affinity"), row)
                                    }
                            }
                        val columns = values.keys.joinToString(",") { "`$it`" }
                        val placeholders = values.keys.joinToString(",") { "?" }
                        db.execSQL(
                            "INSERT INTO `$table` ($columns) VALUES ($placeholders)",
                            values.values.toTypedArray(),
                        )
                        values
                    }
            }
            val setup = schema.getJSONArray("setupQueries")
            for (index in 0 until setup.length()) db.execSQL(setup.getString(index))
            db.version = version
        }
        val database =
            Room
                .databaseBuilder(context, FileBrowserDatabase::class.java, name)
                .addMigrations(*FileBrowserDatabase.MIGRATIONS)
                .setJournalMode(androidx.room.RoomDatabase.JournalMode.TRUNCATE)
                .build()
        try {
            val db = database.openHelper.writableDatabase // Runs Room's full current-schema validation.
            expected.forEach { (table, rows) ->
                db.query("SELECT * FROM `$table` ORDER BY rowid").use { cursor ->
                    assertEquals("v$version $table row count", rows.size, cursor.count)
                    rows.forEach { row ->
                        check(cursor.moveToNext())
                        row.forEach { (column, value) ->
                            val preserved =
                                if (version < 10 && table == "transfers" && column == "error") {
                                    "The operation could not be completed."
                                } else {
                                    value
                                }
                            assertEquals(
                                "v$version $table.$column",
                                preserved,
                                cursor.getString(cursor.getColumnIndexOrThrow(column)),
                            )
                        }
                    }
                }
            }
            if (version < 24 && "folder_backups" in expected) {
                db
                    .query(
                        "SELECT destinationKind, sharedShareId, sharedFolderId, destinationRevision FROM folder_backups",
                    ).use {
                        while (it.moveToNext()) {
                            assertEquals("SPACE", it.getString(0))
                            assertEquals(null, it.getString(1))
                            assertEquals(null, it.getString(2))
                            assertEquals(0L, it.getLong(3))
                        }
                    }
            }
            db.query("SELECT exclusionPatterns FROM folder_backups").use {
                while (it.moveToNext()) assertEquals("", it.getString(0))
            }
            db.query("PRAGMA foreign_key_check").use { assertEquals(0, it.count) }
            db.query("SELECT transferId FROM transfer_queue ORDER BY sequence").use { cursor ->
                val transferRows = expected["transfers"].orEmpty()
                assertEquals(transferRows.size, cursor.count)
                transferRows.sortedWith(compareBy({ it["createdAtEpochMillis"]?.toLong() }, { it["id"] })).forEach {
                    check(cursor.moveToNext())
                    assertEquals(it["id"], cursor.getString(0))
                }
            }
        } finally {
            database.close()
            context.deleteDatabase(name)
        }
    }

    @Suppress("CyclomaticComplexMethod") // Explicit historical column fixtures preserve meaningful migration coverage.
    private fun fixtureValue(
        column: String,
        affinity: String,
        row: Int,
    ): String =
        when (column) {
            "transferId" -> "id-$row"
            "sequence" -> row.toString()
            "accountId" -> "account"
            "runId" -> "id-$row"
            "spaceId", "driveId" -> "space-$row"
            "remoteId" -> "same-remote-id"
            "path", "destinationPath" -> "/same-path"
            "kind" -> "FILE"
            "state" -> "RETRY"
            "direction" -> "UPLOAD"
            "sourceUri", "sourceTreeUri" -> "content://source/$row"
            "tusUrl" -> "https://cloud.example/tus/$row"
            "bytesTotal", "sizeBytes" -> "5368709120"
            "tusOffset", "bytesTransferred" -> "4294967296"
            else -> if (affinity == "INTEGER") "1" else "$column-$row"
        }
}
