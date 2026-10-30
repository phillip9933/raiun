package eu.opencloud.android.next.core.sync

import android.content.ContentValues
import android.database.sqlite.SQLiteDatabase
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.VaultIdentity
import eu.opencloud.android.next.core.sync.VaultOfflineIndexCodec.aad
import eu.opencloud.android.next.core.sync.VaultOfflineIndexCodec.encodeEntry
import eu.opencloud.android.next.core.sync.VaultOfflineIndexCodec.encrypt
import eu.opencloud.android.next.core.sync.VaultOfflineIndexCodec.pathToken
import eu.opencloud.android.next.core.sync.VaultOfflineIndexCodec.updateHash
import java.security.MessageDigest

/** Bounded append state for one unpublished generation; its caller owns the transaction. */
@Suppress("LongParameterList") // Identity, generation, key and cancellation are record-AEAD bindings.
internal class VaultOfflineIndexWriter(
    private val database: SQLiteDatabase,
    private val identity: VaultIdentity,
    private val location: VaultLocation,
    private val generation: String,
    private val key: ByteArray,
    private val checkActive: () -> Unit,
) {
    var count = 0L
        private set
    private val hash = MessageDigest.getInstance("SHA-256")

    fun append(entry: OfflineEntry) {
        checkActive()
        val sequence = count
        val plain = encodeEntry(entry)
        val token = pathToken(key, entry.encryptedPath)
        val sealed =
            try {
                if (plain.size > MAX_RECORD_BYTES) throw OpenCloudException(OpenCloudError.EncryptedOfflineIndexFull)
                encrypt(key, aad(identity, location, generation, "record:$sequence", token), plain, sequence)
            } finally {
                plain.fill(0)
            }
        try {
            database.insertOrThrow(
                "entries",
                null,
                ContentValues().apply {
                    put("seq", sequence)
                    put("pathToken", token)
                    put("size", sealed.size)
                },
            )
            writeChunks(sequence, sealed)
            updateHash(hash, sequence, token, sealed)
            count = Math.addExact(count, 1)
            if (count % 128L == 0L) {
                database.setTransactionSuccessful()
                database.endTransaction()
                database.beginTransaction()
            }
        } finally {
            sealed.fill(0)
            token.fill(0)
        }
    }

    private fun writeChunks(
        sequence: Long,
        sealed: ByteArray,
    ) {
        var offset = 0
        var part = 0
        while (offset < sealed.size) {
            checkActive()
            val end = minOf(sealed.size, offset + CHUNK_BYTES)
            database.insertOrThrow(
                "chunks",
                null,
                ContentValues().apply {
                    put("seq", sequence)
                    put("part", part++)
                    put("payload", sealed.copyOfRange(offset, end))
                },
            )
            offset = end
        }
    }

    fun digest(): ByteArray = hash.digest()

    private companion object {
        const val MAX_RECORD_BYTES = 16 * 1024 * 1024
        const val CHUNK_BYTES = 64 * 1024
    }
}
