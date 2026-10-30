package eu.opencloud.android.next.core.sync

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteException
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** HMAC-only membership: neither parent names, candidate names nor reversible descriptors enter the spill. */
@Suppress("TooGenericExceptionCaught") // Partial construction must wipe its key and close only its owned spill.
internal class BoundaryNameStore(
    context: Context,
) : AutoCloseable {
    private val key = ByteArray(32).also(SecureRandom()::nextBytes)
    private var closed = false
    private var finished = false
    private var count = 0L
    private val temporary =
        try {
            boundaryNameStorage { BackupTraversalFile(context) }
        } catch (failure: Throwable) {
            key.fill(0)
            throw failure
        }
    private val database =
        try {
            boundaryNameStorage {
                SQLiteDatabase.openOrCreateDatabase(temporary.file, null).also { database ->
                    try {
                        database.execSQL("PRAGMA synchronous = OFF")
                        database.execSQL(
                            "CREATE TABLE name (identity BLOB PRIMARY KEY NOT NULL " +
                                "CHECK(typeof(identity) = 'blob' AND length(identity) = 32))",
                        )
                    } catch (failure: Throwable) {
                        database.close()
                        throw failure
                    }
                }
            }
        } catch (failure: Throwable) {
            key.fill(0)
            closeBoundaryNameStorage { temporary.close() }
            throw failure
        }

    @Synchronized
    fun requireOpen() {
        if (closed) throw OpenCloudException(OpenCloudError.PreconditionFailed)
    }

    @Synchronized
    fun add(name: String) =
        boundaryNameStorage {
            requireOpen()
            check(!finished)
            insert(name)
            Unit
        }

    /** Metadata-only capture can reject duplicate opaque identities without retaining a transaction. */
    @Synchronized
    fun addUnique(value: String): Boolean =
        boundaryNameStorage {
            requireOpen()
            check(!finished)
            insert(value)
        }

    @Synchronized
    fun finish() =
        boundaryNameStorage {
            requireOpen()
            check(!finished)
            requireCount()
            finished = true
        }

    @Synchronized
    fun reserve(name: String): Boolean =
        boundaryNameStorage {
            requireOpen()
            check(finished)
            requireCount()
            insert(name)
        }

    private fun insert(name: String): Boolean {
        val token = identity(name)
        return try {
            val values = ContentValues().apply { put("identity", token) }
            val inserted = database.insertWithOnConflict("name", null, values, SQLiteDatabase.CONFLICT_IGNORE) != -1L
            if (inserted) count = Math.addExact(count, 1)
            inserted
        } finally {
            token.fill(0)
        }
    }

    private fun requireCount() {
        val actual = database.compileStatement("SELECT COUNT(*) FROM name").use { it.simpleQueryForLong() }
        if (actual != count) throw OpenCloudException(OpenCloudError.InvalidResponse)
    }

    /** Encode incrementally so hashing a candidate never allocates an array proportional to its length. */
    private fun identity(name: String): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        val encoder =
            Charsets.UTF_8
                .newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
        val input = CharBuffer.wrap(name)
        val bytes = ByteBuffer.allocate(8 * 1024)
        try {
            while (true) {
                val status = encoder.encode(input, bytes, true)
                bytes.flip()
                mac.update(bytes)
                bytes.clear()
                if (status.isError) status.throwException()
                if (status.isUnderflow) break
            }
            val final = encoder.flush(bytes)
            if (final.isError) final.throwException()
            check(final.isUnderflow)
            bytes.flip()
            mac.update(bytes)
            return mac.doFinal()
        } catch (_: CharacterCodingException) {
            throw OpenCloudException(OpenCloudError.InvalidResponse)
        } finally {
            bytes.array().fill(0)
        }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        key.fill(0)
        try {
            closeBoundaryNameStorage { database.close() }
        } finally {
            closeBoundaryNameStorage { temporary.close() }
        }
    }
}

private inline fun <T> boundaryNameStorage(block: () -> T): T =
    try {
        block()
    } catch (_: SQLiteException) {
        throw OpenCloudException(OpenCloudError.LocalStorageWriteFailed)
    } catch (_: IOException) {
        throw OpenCloudException(OpenCloudError.LocalStorageWriteFailed)
    }

private inline fun closeBoundaryNameStorage(close: () -> Unit) {
    try {
        close()
    } catch (_: SQLiteException) {
        // The disposable key has already been wiped; cleanup must not replace the original cancellation.
    } catch (_: IOException) {
        // Advisory owner cleanup remains best effort after key removal.
    }
}
