package eu.opencloud.android.next.ui

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream

class EncryptedTextReplacementStreamTest {
    @Test fun shorterAndLongerUtf8ReplacementsKeepExactPrefixAndSuffix() {
        val original = "before-🗝️-after".toByteArray(Charsets.UTF_8)
        val prefix = "before-".toByteArray(Charsets.UTF_8).size.toLong()
        val removed = "🗝️".toByteArray(Charsets.UTF_8).size.toLong()
        listOf("x", "🔐 a longer replacement").forEach { replacement ->
            val reader =
                EncryptedTextReplacementStream(
                    ByteArrayInputStream(original),
                    prefix,
                    removed,
                    replacement.toByteArray(Charsets.UTF_8),
                )
            val actual = reader.use { it.readBytes() }
            assertArrayEquals("before-$replacement-after".toByteArray(Charsets.UTF_8), actual)
        }
    }

    @Test fun largePrefixAndRemovalCrossInternalChunkBoundaries() {
        val prefix = ByteArray(80 * 1024) { (it % 251).toByte() }
        val removed = ByteArray(130 * 1024) { 47 }
        val suffix = ByteArray(90 * 1024) { (it % 239).toByte() }
        val replacement = "fresh 🗝️".toByteArray(Charsets.UTF_8)
        val original = prefix + removed + suffix
        val source =
            object : ByteArrayInputStream(original) {
                override fun read(
                    bytes: ByteArray,
                    offset: Int,
                    length: Int,
                ): Int = super.read(bytes, offset, minOf(length, 3071))
            }
        val actual =
            EncryptedTextReplacementStream(
                source,
                prefix.size.toLong(),
                removed.size.toLong(),
                replacement,
            ).use { it.readBytes() }
        assertArrayEquals(prefix + replacement + suffix, actual)
    }

    @Test fun prematurePrefixOrRemovalEofFailsAndCloseReleasesSource() {
        listOf(10L to 0L, 2L to 10L).forEach { (prefix, removed) ->
            var closed = false
            val source =
                object : InputStream() {
                    private val delegate = ByteArrayInputStream(byteArrayOf(1, 2, 3))

                    override fun read(): Int = delegate.read()

                    override fun read(
                        bytes: ByteArray,
                        offset: Int,
                        length: Int,
                    ): Int = delegate.read(bytes, offset, length)

                    override fun close() {
                        closed = true
                        delegate.close()
                    }
                }
            val reader = EncryptedTextReplacementStream(source, prefix, removed, byteArrayOf(9))
            assertThrows(IOException::class.java) { reader.readBytes() }
            reader.close()
            assertTrue(closed)
            assertThrows(IOException::class.java) { reader.read() }
        }
    }

    @Test fun zeroLengthReplacementAtBeginningAndEndIsExact() {
        val start = EncryptedTextReplacementStream(ByteArrayInputStream(byteArrayOf(1, 2)), 0, 0, byteArrayOf(9))
        assertArrayEquals(byteArrayOf(9, 1, 2), start.use { it.readBytes() })
        val end = EncryptedTextReplacementStream(ByteArrayInputStream(byteArrayOf(1, 2)), 2, 0, byteArrayOf(9))
        assertArrayEquals(byteArrayOf(1, 2, 9), end.use { it.readBytes() })
        assertEquals(
            0,
            EncryptedTextReplacementStream(ByteArrayInputStream(byteArrayOf()), 0, 0, byteArrayOf())
                .use { it.readBytes().size },
        )
    }
}
