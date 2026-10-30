package eu.opencloud.android.next.core.sync

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteConstraintException
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteException
import android.util.Base64
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** All methods are synchronous; no authorization callback can suspend while holding this store's lock or cursor. */
@Suppress("TooGenericExceptionCaught") // Partial construction must wipe disposable keys and remove its own spill.
internal class BoundaryDirectoryStore(
    context: Context,
    private val parent: String,
) : AutoCloseable {
    private val key = ByteArray(32).also(SecureRandom()::nextBytes)
    private val identityKey = ByteArray(32).also(SecureRandom()::nextBytes)
    private var closed = false
    private var finished = false
    private var count = 0L
    private val temporary =
        try {
            boundaryDirectoryStorage { BackupTraversalFile(context) }
        } catch (failure: Throwable) {
            wipeKeys()
            throw failure
        }
    private val database =
        try {
            boundaryDirectoryStorage {
                SQLiteDatabase.openOrCreateDatabase(temporary.file, null).also { database ->
                    try {
                        database.execSQL("PRAGMA synchronous = OFF")
                        database.execSQL(
                            "CREATE TABLE entry (sequence INTEGER PRIMARY KEY, identity TEXT NOT NULL UNIQUE, " +
                                "pathIdentity TEXT NOT NULL UNIQUE, payload BLOB NOT NULL)",
                        )
                    } catch (failure: Throwable) {
                        database.close()
                        throw failure
                    }
                }
            }
        } catch (failure: Throwable) {
            wipeKeys()
            closeBoundaryDirectoryStorage { temporary.close() }
            throw failure
        }

    @Synchronized
    fun requireOpen() {
        if (closed) throw OpenCloudException(OpenCloudError.PreconditionFailed)
    }

    @Synchronized
    fun add(entry: BoundaryEntry) =
        boundaryDirectoryStorage {
            requireOpen()
            check(!finished)
            requireBoundaryDirectoryChild(parent, entry)
            val plain = BoundaryDirectoryCodec.encode(entry)
            try {
                val sequence = Math.addExact(count, 1)
                val identity = identity("id", entry.id)
                val pathIdentity = identity("path", entry.path.trim('/'))
                val encrypted = encrypt(plain, associatedData(sequence, identity, pathIdentity))
                try {
                    insertEncrypted(sequence, identity, pathIdentity, encrypted)
                    count = sequence
                } finally {
                    encrypted.fill(0)
                }
            } finally {
                plain.fill(0)
            }
        }

    private fun insertEncrypted(
        sequence: Long,
        identity: String,
        pathIdentity: String,
        encrypted: ByteArray,
    ) {
        val values =
            ContentValues().apply {
                put("sequence", sequence)
                put("identity", identity)
                put("pathIdentity", pathIdentity)
                put("payload", encrypted)
            }
        try {
            database.insertOrThrow("entry", null, values)
        } catch (_: SQLiteConstraintException) {
            invalidBoundaryDirectory()
        }
    }

    @Synchronized
    fun finish(): Long {
        requireOpen()
        check(!finished)
        finished = true
        return count
    }

    @Synchronized
    fun page(
        afterSequence: Long,
        limit: Int,
    ): List<BoundaryEntry> =
        boundaryDirectoryStorage {
            requireReady()
            require(afterSequence in 0..count && limit in 1..BOUNDARY_DIRECTORY_PAGE)
            val expected = minOf(limit.toLong(), count - afterSequence).toInt()
            val entries = ArrayList<BoundaryEntry>(expected)
            var bytes = 0L
            database
                .rawQuery(
                    "SELECT sequence, identity, pathIdentity, payload FROM entry WHERE sequence > ? ORDER BY sequence LIMIT ?",
                    arrayOf(afterSequence.toString(), expected.toString()),
                ).use { cursor ->
                    while (entries.size < expected) {
                        if (!cursor.moveToNext() || cursor.getLong(0) != afterSequence + entries.size + 1) {
                            invalidBoundaryDirectory()
                        }
                        bytes = appendPageEntry(cursor, entries, bytes) ?: break
                    }
                }
            entries
        }

    @Synchronized
    fun findById(id: String): BoundaryEntry? =
        boundaryDirectoryStorage {
            requireReady()
            database
                .rawQuery(
                    "SELECT sequence, identity, pathIdentity, payload FROM entry WHERE identity = ? LIMIT 1",
                    arrayOf(identity("id", id)),
                ).use { cursor ->
                    if (!cursor.moveToFirst()) return@use null
                    val entry = decodeRecord(cursor)
                    if (entry.id != id) invalidBoundaryDirectory()
                    entry
                }
        }

    private fun appendPageEntry(
        cursor: Cursor,
        entries: MutableList<BoundaryEntry>,
        bytes: Long,
    ): Long? {
        val encoded = cursor.getBlob(3)
        try {
            requireRecordLength(encoded.size)
            val size = encoded.size - 28
            if (entries.isNotEmpty() && bytes + size > BOUNDARY_DIRECTORY_BYTES) return null
            entries += decode(cursor, encoded)
            return bytes + size
        } finally {
            encoded.fill(0)
        }
    }

    private fun decodeRecord(cursor: Cursor): BoundaryEntry {
        val encoded = cursor.getBlob(3)
        return try {
            requireRecordLength(encoded.size)
            decode(cursor, encoded)
        } finally {
            encoded.fill(0)
        }
    }

    private fun decode(
        cursor: Cursor,
        encoded: ByteArray,
    ): BoundaryEntry {
        val sequence = cursor.getLong(0)
        val idToken = cursor.getString(1)
        val pathToken = cursor.getString(2)
        if (sequence !in 1..count) invalidBoundaryDirectory()
        val plain =
            try {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(
                    Cipher.DECRYPT_MODE,
                    SecretKeySpec(key, "AES"),
                    GCMParameterSpec(128, encoded.copyOfRange(0, 12)),
                )
                cipher.updateAAD(associatedData(sequence, idToken, pathToken))
                cipher.doFinal(encoded, 12, encoded.size - 12)
            } catch (_: GeneralSecurityException) {
                invalidBoundaryDirectory()
            }
        return try {
            BoundaryDirectoryCodec.decode(plain).also {
                requireBoundaryDirectoryChild(parent, it)
                if (identity("id", it.id) != idToken || identity("path", it.path.trim('/')) != pathToken) {
                    invalidBoundaryDirectory()
                }
            }
        } finally {
            plain.fill(0)
        }
    }

    private fun encrypt(
        plain: ByteArray,
        aad: ByteArray,
    ): ByteArray {
        val nonce = ByteArray(12).also(SecureRandom()::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        return nonce + cipher.doFinal(plain)
    }

    private fun identity(
        domain: String,
        value: String,
    ): String {
        if (value.length > BOUNDARY_DIRECTORY_BYTES) invalidBoundaryDirectory()
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(identityKey, "HmacSHA256"))
        mac.update(domain.toByteArray(Charsets.UTF_8))
        val bytes = value.toByteArray(Charsets.UTF_8)
        return try {
            Base64.encodeToString(mac.doFinal(bytes), Base64.NO_WRAP)
        } finally {
            bytes.fill(0)
        }
    }

    private fun associatedData(
        sequence: Long,
        identity: String,
        pathIdentity: String,
    ): ByteArray = "$sequence:$identity:$pathIdentity".toByteArray(Charsets.UTF_8)

    private fun requireRecordLength(length: Int) {
        if (length !in 28..BOUNDARY_DIRECTORY_BYTES + 28) invalidBoundaryDirectory()
    }

    private fun requireReady() {
        requireOpen()
        check(finished)
    }

    private fun wipeKeys() {
        key.fill(0)
        identityKey.fill(0)
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        wipeKeys()
        try {
            closeBoundaryDirectoryStorage { database.close() }
        } finally {
            closeBoundaryDirectoryStorage { temporary.close() }
        }
    }
}

private inline fun <T> boundaryDirectoryStorage(block: () -> T): T =
    try {
        block()
    } catch (_: SQLiteException) {
        throw OpenCloudException(OpenCloudError.LocalStorageWriteFailed)
    } catch (_: IOException) {
        throw OpenCloudException(OpenCloudError.LocalStorageWriteFailed)
    }

private inline fun closeBoundaryDirectoryStorage(close: () -> Unit) {
    try {
        close()
    } catch (_: SQLiteException) {
        // Ephemeral metadata is already inaccessible because its in-memory keys were wiped.
    } catch (_: IOException) {
        // Cleanup attempts must preserve the original failure or coroutine cancellation.
    }
}
