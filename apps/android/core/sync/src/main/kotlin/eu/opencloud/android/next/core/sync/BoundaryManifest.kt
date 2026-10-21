package eu.opencloud.android.next.core.sync

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteException
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.Closeable
import java.io.IOException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

@Serializable
internal data class BoundaryRecord(
    val sequence: Long,
    val parent: Long?,
    val source: BoundaryEntry,
    val destination: BoundaryEntry,
)

/** Private spill metadata is authenticated with a disposable in-memory key, including its traversal position. */
@Suppress("TooGenericExceptionCaught") // Constructor failure must close and remove the private spill file.
internal class BoundaryManifest(
    context: Context,
) : Closeable {
    private val key = ByteArray(32).also(SecureRandom()::nextBytes)
    private val identityKey = ByteArray(32).also(SecureRandom()::nextBytes)
    private val temporary =
        try {
            manifestStorage { BackupTraversalFile(context) }
        } catch (failure: Throwable) {
            key.fill(0)
            identityKey.fill(0)
            throw failure
        }
    private val database =
        try {
            manifestStorage {
                SQLiteDatabase.openOrCreateDatabase(temporary.file, null).also { db ->
                    try {
                        db.execSQL("PRAGMA synchronous = OFF")
                        db.execSQL(
                            "CREATE TABLE entry (sequence INTEGER PRIMARY KEY, parent INTEGER, identity TEXT UNIQUE, pending INTEGER NOT NULL, payload BLOB NOT NULL)",
                        )
                        db.execSQL("CREATE INDEX next_entry ON entry(pending, sequence)")
                        db.execSQL("CREATE INDEX entry_parent ON entry(parent)")
                    } catch (failure: Throwable) {
                        db.close()
                        throw failure
                    }
                }
            }
        } catch (failure: Throwable) {
            key.fill(0)
            identityKey.fill(0)
            temporary.close()
            throw failure
        }

    fun add(
        parent: Long?,
        source: BoundaryEntry,
        destination: BoundaryEntry,
    ) = manifestStorage {
        val token = identity(source.id)
        database.rawQuery("SELECT 1 FROM entry WHERE identity = ? LIMIT 1", arrayOf(token)).use {
            if (it.moveToFirst()) throw OpenCloudException(OpenCloudError.InvalidResponse)
        }
        val sequence =
            database.compileStatement("SELECT COALESCE(MAX(sequence), 0) + 1 FROM entry").use {
                it.simpleQueryForLong()
            }
        val payload = Json.encodeToString(BoundaryRecord(sequence, parent, source, destination)).toByteArray()
        val encrypted =
            try {
                encrypt(payload, associatedData(sequence, parent, token))
            } finally {
                payload.fill(0)
            }
        val values =
            ContentValues().apply {
                put("sequence", sequence)
                if (parent == null) putNull("parent") else put("parent", parent)
                put("identity", token)
                put("pending", if (source.directory) 1 else 0)
                put("payload", encrypted)
            }
        database.insertOrThrow("entry", null, values)
    }

    fun nextDirectory(): BoundaryRecord? =
        manifestStorage {
            next("pending = 1", "sequence ASC")?.also {
                database.execSQL("UPDATE entry SET pending = 0 WHERE sequence = ?", arrayOf(it.sequence))
            }
        }

    suspend fun forEach(
        reverse: Boolean = false,
        block: suspend (BoundaryRecord) -> Unit,
    ) {
        var previous = if (reverse) Long.MAX_VALUE else 0L
        while (true) {
            val record =
                manifestStorage {
                    next(
                        "sequence ${if (reverse) "<" else ">"} $previous",
                        "sequence ${if (reverse) "DESC" else "ASC"}",
                    )
                } ?: break
            block(record)
            previous = record.sequence
        }
    }

    fun requireChildren(
        parent: Long,
        children: List<BoundaryEntry>,
        destination: Boolean = false,
    ) = manifestStorage {
        val actual = children.associateBy { it.id }
        if (actual.size != children.size) throw OpenCloudException(OpenCloudError.InvalidResponse)
        var count = 0
        database
            .rawQuery(
                "SELECT sequence, parent, identity, payload FROM entry WHERE parent = ?",
                arrayOf(parent.toString()),
            ).use { cursor ->
                while (cursor.moveToNext()) {
                    val record = decodeCursor(cursor)
                    val expected = if (destination) record.destination else record.source
                    val child = actual[expected.id]
                    if (child == null ||
                        !sameBoundaryEntry(expected, child)
                    ) {
                        throw OpenCloudException(OpenCloudError.PreconditionFailed)
                    }
                    count++
                }
            }
        if (count != children.size) throw OpenCloudException(OpenCloudError.PreconditionFailed)
    }

    private fun next(
        condition: String,
        ordering: String,
    ): BoundaryRecord? =
        database
            .rawQuery(
                "SELECT sequence, parent, identity, payload FROM entry WHERE $condition ORDER BY $ordering LIMIT 1",
                null,
            ).use {
                if (it.moveToFirst()) decodeCursor(it) else null
            }

    private fun decodeCursor(cursor: Cursor): BoundaryRecord {
        val sequence = cursor.getLong(0)
        val parent = if (cursor.isNull(1)) null else cursor.getLong(1)
        val encrypted = cursor.getBlob(3)
        if (encrypted.size < 28) throw OpenCloudException(OpenCloudError.InvalidResponse)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, encrypted.copyOfRange(0, 12)))
        cipher.updateAAD(associatedData(sequence, parent, cursor.getString(2)))
        val plain =
            try {
                cipher.doFinal(encrypted, 12, encrypted.size - 12)
            } catch (_: javax.crypto.AEADBadTagException) {
                throw OpenCloudException(OpenCloudError.InvalidResponse)
            }
        return try {
            Json.decodeFromString<BoundaryRecord>(plain.toString(Charsets.UTF_8))
        } finally {
            plain.fill(0)
        }
    }

    private fun associatedData(
        sequence: Long,
        parent: Long?,
        token: String,
    ): ByteArray = "$sequence/${parent ?: "root"}/$token".toByteArray()

    private fun identity(id: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(identityKey, "HmacSHA256"))
        return mac.doFinal(id.toByteArray()).joinToString("") { "%02x".format(it) }
    }

    private fun encrypt(
        plain: ByteArray,
        associatedData: ByteArray,
    ): ByteArray {
        val nonce = ByteArray(12).also(SecureRandom()::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(associatedData)
        return nonce + cipher.doFinal(plain)
    }

    override fun close() {
        key.fill(0)
        identityKey.fill(0)
        try {
            database.close()
        } finally {
            temporary.close()
        }
    }
}

internal fun sameBoundaryEntry(
    expected: BoundaryEntry,
    actual: BoundaryEntry,
): Boolean =
    if (expected.directory && actual.directory) {
        expected.id == actual.id && expected.path == actual.path && expected.name == actual.name
    } else {
        expected == actual
    }

private inline fun <T> manifestStorage(block: () -> T): T =
    try {
        block()
    } catch (_: SQLiteException) {
        throw OpenCloudException(OpenCloudError.LocalStorageWriteFailed)
    } catch (_: IOException) {
        throw OpenCloudException(OpenCloudError.LocalStorageWriteFailed)
    }
