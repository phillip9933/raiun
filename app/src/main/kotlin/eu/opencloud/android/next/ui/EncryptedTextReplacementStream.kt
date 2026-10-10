package eu.opencloud.android.next.ui

import java.io.IOException
import java.io.InputStream

/** Replaces a bounded text range without buffering or persisting the remaining plaintext. */
internal class EncryptedTextReplacementStream(
    private val source: InputStream,
    private var prefixRemaining: Long,
    private val removedLength: Long,
    private val replacement: ByteArray,
) : InputStream() {
    private var replacementPosition = 0
    private var removed = false
    private var closed = false

    init {
        require(prefixRemaining >= 0 && removedLength >= 0)
    }

    override fun read(): Int {
        val one = ByteArray(1)
        return try {
            if (read(one, 0, 1) < 0) -1 else one[0].toInt() and 0xff
        } finally {
            one.fill(0)
        }
    }

    @Suppress("ReturnCount") // Return each streaming phase separately without concatenating plaintext buffers.
    override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
        java.util.Objects.checkFromIndexSize(offset, length, bytes.size)
        if (closed) throw IOException("Text replacement reader is closed.")
        if (length == 0) return 0
        if (prefixRemaining > 0) {
            val count = source.read(bytes, offset, minOf(length.toLong(), prefixRemaining).toInt())
            if (count <= 0) throw IOException("Text replacement prefix ended early.")
            prefixRemaining -= count
            return count
        }
        if (!removed) discardOriginalRange()
        if (replacementPosition < replacement.size) {
            val count = minOf(length, replacement.size - replacementPosition)
            replacement.copyInto(bytes, offset, replacementPosition, replacementPosition + count)
            replacementPosition += count
            return count
        }
        return source.read(bytes, offset, length)
    }

    private fun discardOriginalRange() {
        val scratch = ByteArray(64 * 1024)
        try {
            var remaining = removedLength
            while (remaining > 0) {
                val count = source.read(scratch, 0, minOf(scratch.size.toLong(), remaining).toInt())
                if (count <= 0) throw IOException("Text replacement range ended early.")
                remaining -= count
                scratch.fill(0)
            }
            removed = true
        } finally {
            scratch.fill(0)
        }
    }

    override fun close() {
        if (closed) return
        closed = true
        source.close()
    }
}
