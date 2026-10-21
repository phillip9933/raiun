package eu.opencloud.android.next.core.database

import android.database.sqlite.SQLiteDatabase
import androidx.room.Room
import kotlinx.coroutines.test.runTest
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class TransferMigrationTest {
    @Test fun `version nine migration preserves pending intent and removes historical secret errors`() =
        runTest {
            val context = RuntimeEnvironment.getApplication()
            val name = "migration-9-10.db"
            context.deleteDatabase(name)
            val path = context.getDatabasePath(name).also { it.parentFile?.mkdirs() }
            val schema =
                requireNotNull(
                    javaClass.classLoader?.getResourceAsStream(
                        "eu.opencloud.android.next.core.database.FileBrowserDatabase/9.json",
                    ),
                ).bufferedReader().use { JSONObject(it.readText()).getJSONObject("database") }
            SQLiteDatabase.openOrCreateDatabase(path, null).use { db ->
                val entities = schema.getJSONArray("entities")
                for (index in 0 until entities.length()) {
                    val entity = entities.getJSONObject(index)
                    val table = entity.getString("tableName")
                    db.execSQL(entity.getString("createSql").replace("\${TABLE_NAME}", table))
                    val indices = entity.optJSONArray("indices") ?: org.json.JSONArray()
                    for (item in 0 until indices.length()) {
                        db.execSQL(indices.getJSONObject(item).getString("createSql").replace("\${TABLE_NAME}", table))
                    }
                }
                val setup = schema.getJSONArray("setupQueries")
                for (index in 0 until setup.length()) db.execSQL(setup.getString(index))
                db.execSQL(
                    "INSERT INTO transfers (id,accountId,spaceId,resourceId,direction,sourceUri,destinationPath," +
                        "displayName,mimeType,bytesTotal,bytesTransferred,state,error,workId,overwrite,offlinePin," +
                        "tusUrl,tusOffset,attemptCount,createdAtEpochMillis,updatedAtEpochMillis," +
                        "deleteSourceAfterSuccess) " +
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    arrayOf<Any?>(
                        "intent",
                        "account",
                        "space",
                        null,
                        "UPLOAD",
                        "content://source",
                        "/file",
                        "file",
                        null,
                        5000L,
                        2000L,
                        "RETRY",
                        "Bearer secret",
                        "work-id",
                        0,
                        0,
                        "https://example.test/tus/1",
                        2000L,
                        2,
                        100L,
                        200L,
                        0,
                    ),
                )
                db.version = 9
            }
            val database =
                Room
                    .databaseBuilder(context, FileBrowserDatabase::class.java, name)
                    .addMigrations(*FileBrowserDatabase.MIGRATIONS)
                    .setJournalMode(androidx.room.RoomDatabase.JournalMode.TRUNCATE)
                    .build()
            try {
                val transfer = requireNotNull(database.transferDao().findById("intent"))
                assertEquals("RETRY", transfer.state)
                assertEquals(2000L, transfer.tusOffset)
                assertEquals("work-id", transfer.workId)
                assertEquals(0L, transfer.notBeforeEpochMillis)
                assertNull(transfer.errorCode)
                assertEquals("The operation could not be completed.", transfer.error)
            } finally {
                database.close()
                context.deleteDatabase(name)
            }
        }
}
