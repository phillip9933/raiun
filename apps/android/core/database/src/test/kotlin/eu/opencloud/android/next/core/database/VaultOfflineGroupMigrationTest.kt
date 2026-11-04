package eu.opencloud.android.next.core.database

import android.database.sqlite.SQLiteDatabase
import androidx.room.Room
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
class VaultOfflineGroupMigrationTest {
    @Test fun version26MigrationPreservesOriginalRowsAndQueueWhileBackfilledOwnerSurvivesReopen() =
        runBlocking {
            val context = RuntimeEnvironment.getApplication()
            val name = "groups-migration-${UUID.randomUUID()}.db"
            val file = context.getDatabasePath(name).also { it.parentFile?.mkdirs() }
            val schema =
                requireNotNull(
                    javaClass.classLoader?.getResourceAsStream(
                        "eu.opencloud.android.next.core.database.FileBrowserDatabase/26.json",
                    ),
                ).bufferedReader().use { JSONObject(it.readText()).getJSONObject("database") }
            SQLiteDatabase.openOrCreateDatabase(file, null).use { sql ->
                val entities = schema.getJSONArray("entities")
                for (index in 0 until entities.length()) {
                    val entity = entities.getJSONObject(index)
                    val table = entity.getString("tableName")
                    sql.execSQL(entity.getString("createSql").replace("\${TABLE_NAME}", table))
                    val indices = entity.optJSONArray("indices") ?: org.json.JSONArray()
                    for (item in 0 until indices.length()) {
                        sql.execSQL(indices.getJSONObject(item).getString("createSql").replace("\${TABLE_NAME}", table))
                    }
                }
                val setup = schema.getJSONArray("setupQueries")
                for (index in 0 until setup.length()) sql.execSQL(setup.getString(index))
                insertFixture(
                    sql,
                    schema,
                    "accounts",
                    mapOf(
                        "id" to "a",
                        "serverUrl" to "https://example.test",
                        "userId" to "u",
                        "displayName" to "U",
                        "authenticationType" to "BASIC",
                        "isActive" to 1,
                    ),
                )
                insertFixture(
                    sql,
                    schema,
                    "transfers",
                    mapOf(
                        "id" to "old-transfer",
                        "accountId" to "a",
                        "spaceId" to "drive",
                        "direction" to "DOWNLOAD",
                        "state" to "RETRY",
                        "bytesTotal" to 100L,
                        "bytesTransferred" to 41L,
                        "locationKind" to "VAULT",
                        "sourceUri" to "vault-offline:vault",
                        "destinationPath" to "opaque/file",
                        "workId" to "old-worker",
                    ),
                )
                sql.execSQL("INSERT INTO transfer_queue(sequence,transferId) VALUES (137,'old-transfer')")
                insertFixture(
                    sql,
                    schema,
                    "resources",
                    mapOf(
                        "accountId" to "a",
                        "spaceId" to "drive",
                        "remoteId" to "resource",
                        "path" to "/opaque",
                        "name" to "opaque",
                        "kind" to "FILE",
                        "sizeBytes" to 7L,
                        "isFavorite" to 1,
                        "hasLocalCopy" to 1,
                        "localPath" to "/synthetic/private/cache",
                    ),
                )
                sql.version = 26
            }

            fun open() =
                Room
                    .databaseBuilder(context, FileBrowserDatabase::class.java, name)
                    .addMigrations(*FileBrowserDatabase.MIGRATIONS)
                    .build()
            var database = open()
            try {
                val store = FileBrowserStore(database)
                val owner = requireNotNull(store.vaultOfflineGroups().captureOwner("a"))
                assertTrue(owner.incarnation.matches(Regex("[a-f0-9]{32}")))
                val original = requireNotNull(store.transfer("old-transfer"))
                assertEquals("RETRY", original.state)
                assertEquals(41L, original.bytesTransferred)
                assertEquals("VAULT", original.locationKind)
                assertEquals("old-worker", original.workId)
                assertEquals(137L, queueSequence(database))
                val resource = requireNotNull(store.resource("a", "drive", "resource"))
                assertTrue(resource.isFavorite && resource.hasLocalCopy)
                assertEquals("/synthetic/private/cache", resource.localPath)
                database.close()
                database = open()
                val reopened = FileBrowserStore(database)
                assertEquals(owner, reopened.vaultOfflineGroups().captureOwner("a"))
                assertEquals(original, reopened.transfer("old-transfer"))
                assertEquals(resource, reopened.resource("a", "drive", "resource"))
                assertEquals(137L, queueSequence(database))
                reopened.removeAccount("a")
                database.accountDao().upsert(AccountEntity("a", "https://example.test", "u", "U", "BASIC", false))
                val fresh = requireNotNull(reopened.vaultOfflineGroups().captureOwner("a"))
                assertNotEquals(owner.incarnation, fresh.incarnation)
                assertNull(reopened.transfer("old-transfer"))
            } finally {
                database.close()
                context.deleteDatabase(name)
            }
        }

    private fun queueSequence(database: FileBrowserDatabase): Long =
        database.openHelper.readableDatabase
            .query("SELECT sequence FROM transfer_queue WHERE transferId='old-transfer'")
            .use { cursor ->
                check(cursor.moveToFirst())
                cursor.getLong(0)
            }

    private fun insertFixture(
        sql: SQLiteDatabase,
        schema: JSONObject,
        table: String,
        overrides: Map<String, Any>,
    ) {
        val entities = schema.getJSONArray("entities")
        val entity =
            (0 until entities.length())
                .map { entities.getJSONObject(it) }
                .single { it.getString("tableName") == table }
        val fields = entity.getJSONArray("fields")
        val names = (0 until fields.length()).map { fields.getJSONObject(it).getString("columnName") }
        val values =
            (0 until fields.length()).map { index ->
                val field = fields.getJSONObject(index)
                overrides[field.getString("columnName")] ?: if (field.optBoolean("notNull", false)) {
                    if (field.getString("affinity") == "TEXT") "" else 0
                } else {
                    null
                }
            }
        val placeholders = names.joinToString(",") { "?" }
        sql.execSQL("INSERT INTO $table (${names.joinToString(",")}) VALUES ($placeholders)", values.toTypedArray())
    }
}
