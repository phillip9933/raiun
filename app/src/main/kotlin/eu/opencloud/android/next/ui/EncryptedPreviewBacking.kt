package eu.opencloud.android.next.ui

import android.content.Context
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Seekable preview data held as independently authenticated ciphertext chunks in private cache. */
class EncryptedPreviewBacking private constructor(
    private val file: File,
    private val accessValid: () -> Boolean,
    private val key: ByteArray,
    private val noncePrefix: ByteArray,
) : AutoCloseable {
    private val storage = RandomAccessFile(file, "rw")
    private val pending = ByteArray(CHUNK_BYTES)
    private var pendingSize = 0
    private var plainLength = 0L
    private var sealed = false
    private var closed = false
    private var streamOpened = false

    val size: Long
        @Synchronized get() {
            requireReadable()
            return plainLength
        }

    /** The owner streams decrypted DAV bytes here, then calls seal before exposing a descriptor. */
    @Synchronized fun outputStream(): OutputStream {
        requireWritable()
        check(!streamOpened) { "Preview output stream was already opened." }
        streamOpened = true
        return object : OutputStream() {
            override fun write(value: Int) {
                synchronized(this@EncryptedPreviewBacking) {
                    requireWritable()
                    pending[pendingSize++] = value.toByte()
                    if (pendingSize == CHUNK_BYTES) flushChunk()
                }
            }

            override fun write(
                bytes: ByteArray,
                offset: Int,
                length: Int,
            ) {
                java.util.Objects.checkFromIndexSize(offset, length, bytes.size)
                synchronized(this@EncryptedPreviewBacking) {
                    requireWritable()
                    var cursor = offset
                    val end = offset + length
                    while (cursor < end) {
                        requireWritable()
                        val copied = minOf(end - cursor, CHUNK_BYTES - pendingSize)
                        bytes.copyInto(pending, pendingSize, cursor, cursor + copied)
                        pendingSize += copied
                        cursor += copied
                        if (pendingSize == CHUNK_BYTES) flushChunk()
                    }
                }
            }

            override fun close() {
                seal()
            }
        }
    }

    @Synchronized fun seal() {
        if (sealed) {
            requireReadable()
            return
        }
        requireWritable()
        if (pendingSize > 0) flushChunk()
        storage.fd.sync()
        sealed = true
    }

    /** Reads only authenticated chunks. A failed read clears bytes already copied in that call. */
    @Suppress("TooGenericExceptionCaught")
    @Synchronized
    fun read(
        offset: Long,
        size: Int,
        destination: ByteArray,
    ): Int {
        requireReadable()
        require(offset >= 0L && size >= 0)
        require(size <= destination.size)
        if (offset >= plainLength || size == 0) return 0
        val requested = minOf(size.toLong(), plainLength - offset).toInt()
        var copied = 0
        try {
            while (copied < requested) {
                requireReadable()
                val position = Math.addExact(offset, copied.toLong())
                val index = position / CHUNK_BYTES
                val within = (position % CHUNK_BYTES).toInt()
                val chunk = readChunk(index)
                try {
                    val count = minOf(requested - copied, chunk.size - within)
                    chunk.copyInto(destination, copied, within, within + count)
                    copied += count
                } finally {
                    chunk.fill(0)
                }
            }
            return copied
        } catch (failure: Exception) {
            destination.fill(0, 0, copied)
            throw failure
        }
    }

    fun inputStream(): InputStream {
        size // Validate sealing and access before returning a lazy reader.
        return object : InputStream() {
            private var position = 0L
            private var ended = false
            private val buffer = ByteArray(CHUNK_BYTES)
            private var bufferStart = 0L
            private var bufferSize = 0

            override fun read(): Int {
                val one = ByteArray(1)
                return try {
                    if (read(one, 0, 1) < 0) -1 else one[0].toInt() and 0xff
                } finally {
                    one.fill(0)
                }
            }

            @Suppress("TooGenericExceptionCaught") // Wipe the buffered page on any access or storage failure.
            override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
                java.util.Objects.checkFromIndexSize(offset, length, bytes.size)
                if (ended) throw IOException("Preview reader is closed.")
                return if (length == 0) {
                    0
                } else {
                    // Recheck access even when the requested bytes are already in the memory buffer.
                    try {
                        this@EncryptedPreviewBacking.size
                    } catch (failure: Exception) {
                        buffer.fill(0)
                        bufferSize = 0
                        throw failure
                    }
                    if (position !in bufferStart until bufferStart + bufferSize) {
                        buffer.fill(0)
                        bufferStart = position
                        bufferSize = this@EncryptedPreviewBacking.read(position, buffer.size, buffer)
                    }
                    if (bufferSize == 0) {
                        -1
                    } else {
                        val within = (position - bufferStart).toInt()
                        val count = minOf(length, bufferSize - within)
                        buffer.copyInto(bytes, offset, within, within + count)
                        position = Math.addExact(position, count.toLong())
                        count
                    }
                }
            }

            override fun close() {
                ended = true
                buffer.fill(0)
            }
        }
    }

    @Synchronized override fun close() {
        if (closed) return
        closed = true
        pending.fill(0)
        key.fill(0)
        noncePrefix.fill(0)
        try {
            storage.close()
        } finally {
            synchronized(activeFiles) { activeFiles.remove(file.absolutePath) }
            // The key is already cleared. A failed unlink leaves only unusable ciphertext;
            // the next preview initialization retries orphan cleanup.
            file.delete()
        }
    }

    private fun flushChunk() {
        requireWritable()
        val index = plainLength / CHUNK_BYTES
        val length = pendingSize
        val encrypted = crypt(Cipher.ENCRYPT_MODE, index, length, pending, length)
        try {
            storage.seek(recordOffset(index))
            storage.write(encrypted)
            plainLength = Math.addExact(plainLength, length.toLong())
            pending.fill(0, 0, length)
            pendingSize = 0
        } finally {
            encrypted.fill(0)
        }
    }

    @Suppress("TooGenericExceptionCaught") // Authentication and short reads both invalidate the ciphertext chunk.
    private fun readChunk(index: Long): ByteArray {
        val remaining = plainLength - Math.multiplyExact(index, CHUNK_BYTES.toLong())
        val length = minOf(CHUNK_BYTES.toLong(), remaining).toInt()
        if (length <= 0) throw IOException("Preview chunk is outside the sealed length.")
        val encrypted = ByteArray(length + TAG_BYTES)
        try {
            storage.seek(recordOffset(index))
            storage.readFully(encrypted)
            return crypt(Cipher.DECRYPT_MODE, index, length, encrypted, encrypted.size)
        } catch (failure: Exception) {
            throw IOException("Encrypted preview chunk could not be authenticated.", failure)
        } finally {
            encrypted.fill(0)
        }
    }

    private fun crypt(
        mode: Int,
        index: Long,
        length: Int,
        bytes: ByteArray,
        count: Int,
    ): ByteArray {
        val nonce =
            ByteBuffer
                .allocate(12)
                .put(noncePrefix)
                .putLong(index)
                .array()
        val aad =
            ByteBuffer
                .allocate(16)
                .putInt(1)
                .putLong(index)
                .putInt(length)
                .array()
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BYTES * 8, nonce))
            cipher.updateAAD(aad)
            return cipher.doFinal(bytes, 0, count)
        } finally {
            nonce.fill(0)
            aad.fill(0)
        }
    }

    @Suppress("ComplexCondition") // Every lock, lifecycle and interrupt guard must fail closed before a write.
    private fun requireWritable() {
        if (closed || sealed || !accessValid() || Thread.currentThread().isInterrupted) {
            throw IOException("Encrypted preview is no longer writable.")
        }
    }

    @Suppress("ComplexCondition") // Every lock, lifecycle and interrupt guard must fail closed before a read.
    private fun requireReadable() {
        if (closed || !sealed || !accessValid() || Thread.currentThread().isInterrupted) {
            throw IOException("Encrypted preview is unavailable.")
        }
        val expected =
            if (plainLength == 0L) {
                0L
            } else {
                val last = (plainLength - 1L) / CHUNK_BYTES
                Math.addExact(recordOffset(last), ((plainLength - 1L) % CHUNK_BYTES) + 1L + TAG_BYTES)
            }
        if (storage.length() != expected) throw IOException("Encrypted preview cache length changed.")
    }

    private fun recordOffset(index: Long) = Math.multiplyExact(index, (CHUNK_BYTES + TAG_BYTES).toLong())

    companion object {
        private const val CHUNK_BYTES = 64 * 1024
        private const val TAG_BYTES = 16
        private const val DIRECTORY = "encrypted-previews"
        private val activeFiles = mutableSetOf<String>()

        @Suppress("TooGenericExceptionCaught", "ThrowsCount") // Roll back key and file for every construction failure.
        fun create(
            context: Context,
            accessValid: () -> Boolean,
        ): EncryptedPreviewBacking {
            if (!accessValid()) throw IOException("Encrypted preview access is unavailable.")
            val directory = File(context.cacheDir, DIRECTORY)
            if (!directory.isDirectory && !directory.mkdirs()) throw IOException("Preview cache is unavailable.")
            synchronized(activeFiles) {
                directory
                    .listFiles()
                    .orEmpty()
                    .filter { it.isFile && it.name.startsWith("preview-") && it.name.endsWith(".ciphertext") }
                    .filterNot { it.absolutePath in activeFiles }
                    .forEach(File::delete)
            }
            val key = ByteArray(32).also(SecureRandom()::nextBytes)
            val prefix = ByteArray(4).also(SecureRandom()::nextBytes)
            val file =
                synchronized(activeFiles) {
                    File.createTempFile("preview-", ".ciphertext", directory).also { activeFiles.add(it.absolutePath) }
                }
            return try {
                EncryptedPreviewBacking(file, accessValid, key, prefix)
            } catch (failure: Exception) {
                synchronized(activeFiles) { activeFiles.remove(file.absolutePath) }
                key.fill(0)
                prefix.fill(0)
                file.delete()
                throw failure
            }
        }
    }
}
