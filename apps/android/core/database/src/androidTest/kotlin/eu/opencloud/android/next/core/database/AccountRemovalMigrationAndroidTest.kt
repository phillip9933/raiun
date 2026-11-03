package eu.opencloud.android.next.core.database

import android.content.ContentValues
import android.database.sqlite.SQLiteDatabase
import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID

/** Real framework SQLite v27 fixture, followed by Room's complete v28 schema validation and reopen. */
@RunWith(AndroidJUnit4::class)
class AccountRemovalMigrationAndroidTest {
    @Test fun originalAccountSurvivesMigrationAndPendingRemovalSurvivesNextProcessOpen() =
        runBlocking {
            val instrumentation = InstrumentationRegistry.getInstrumentation()
            val context = instrumentation.targetContext
            val name = "account-removal-migration-${UUID.randomUUID()}.db"
            val file = context.getDatabasePath(name)
            val parent = requireNotNull(file.parentFile)
            check(parent.mkdirs() || parent.isDirectory)
            val schema =
                instrumentation.context.assets
                    .open("eu.opencloud.android.next.core.database.FileBrowserDatabase/27.json")
                    .bufferedReader()
                    .use { JSONObject(it.readText()).getJSONObject("database") }
            createVersion27Fixture(file.path, schema)

            fun open() =
                Room
                    .databaseBuilder(context, FileBrowserDatabase::class.java, name)
                    .addMigrations(MIGRATION_27_28)
                    .build()
            var database = open()
            val original = AccountEntity("a", "https://cloud.example", "user", "Original account", "OIDC", false)
            try {
                var store = FileBrowserStore(database)
                assertEquals(original, store.account("a"))
                assertEquals(listOf(original), store.activeAccounts())
                assertFalse(store.isAccountRemovalPending("a"))
                assertTrue(store.pendingAccountRemovals().isEmpty())
                assertEquals(28, database.openHelper.readableDatabase.version)
                assertTrue(store.beginAccountRemoval("a"))
                val owner = requireNotNull(store.accountRemovalOwner("a"))
                database.close()
                database = open()
                store = FileBrowserStore(database)
                assertNull(store.account("a"))
                assertTrue(store.isAccountRemovalPending("a"))
                assertEquals(owner, store.accountRemovalOwner("a"))
                assertEquals(
                    listOf(original.copy(isActive = false, removalPending = true)),
                    store.pendingAccountRemovals(),
                )
            } finally {
                database.close()
                context.deleteDatabase(name)
            }
        }

    private fun createVersion27Fixture(
        path: String,
        schema: JSONObject,
    ) {
        SQLiteDatabase.openOrCreateDatabase(path, null).use { sql ->
            val entities = schema.getJSONArray("entities")
            for (index in 0 until entities.length()) {
                val entity = entities.getJSONObject(index)
                val table = entity.getString("tableName")
                sql.execSQL(entity.getString("createSql").replace("\${TABLE_NAME}", table))
                val indices = entity.optJSONArray("indices") ?: org.json.JSONArray()
                for (item in 0 until indices.length()) {
                    sql.execSQL(indices.getJSONObject(item).getString("createSql").replace("\${TABLE_NAME}", table))
                }
                if (table == "accounts") insertOriginalAccount(sql, entity)
            }
            val setup = schema.getJSONArray("setupQueries")
            for (index in 0 until setup.length()) sql.execSQL(setup.getString(index))
            sql.version = 27
        }
    }

    private fun insertOriginalAccount(
        sql: SQLiteDatabase,
        entity: JSONObject,
    ) {
        val values = ContentValues()
        val fields = entity.getJSONArray("fields")
        for (index in 0 until fields.length()) {
            val field = fields.getJSONObject(index)
            val name = field.getString("columnName")
            if (!field.optBoolean("notNull", false)) {
                values.putNull(name)
            } else if (field.getString("affinity") == "INTEGER") {
                values.put(name, if (name == "isActive") 1 else 0)
            }
        }
        values.put("id", "a")
        values.put("serverUrl", "https://cloud.example")
        values.put("userId", "user")
        values.put("displayName", "Original account")
        values.put("authenticationType", "OIDC")
        sql.insertOrThrow("accounts", null, values)
    }
}
