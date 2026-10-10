package eu.opencloud.android.next.ui

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.util.concurrent.atomic.AtomicBoolean

@RunWith(RobolectricTestRunner::class)
class EncryptedPreviewBackingTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test fun largePreviewSupportsRandomCrossChunkReadsAndCleansUp() {
        val access = AtomicBoolean(true)
        val backing = EncryptedPreviewBacking.create(context) { access.get() }
        val pattern = ByteArray(8192) { (it * 31).toByte() }
        val total = 9L * 1024 * 1024 + 17L
        val path = backingFile()
        try {
            val output = backing.outputStream()
            var written = 0L
            while (written < total) {
                val count = minOf(pattern.size.toLong(), total - written).toInt()
                output.write(pattern, 0, count)
                written += count
            }
            output.close()
            backing.seal()
            assertEquals(total, backing.size)
            assertEquals(total / (64 * 1024) * (64 * 1024 + 16) + 17 + 16, path.length())
            val offset = 64L * 1024 - 37L
            val actual = ByteArray(100)
            assertEquals(100, backing.read(offset, actual.size, actual))
            val expected = ByteArray(100) { pattern[((offset + it) % pattern.size).toInt()] }
            assertArrayEquals(expected, actual)
            assertEquals(17, backing.read(total - 17, actual.size, actual))
            assertArrayEquals(pattern.copyOfRange(0, 17), actual.copyOfRange(0, 17))
            backing.inputStream().use { reader ->
                val prefix = ByteArray(100)
                assertEquals(100, reader.read(prefix))
                assertArrayEquals(pattern.copyOfRange(0, 100), prefix)
            }
            RandomAccessFile(path, "r").use { file ->
                val firstCiphertextBytes = ByteArray(pattern.size)
                file.readFully(firstCiphertextBytes)
                assertFalse(firstCiphertextBytes.contentEquals(pattern))
            }
        } finally {
            backing.close()
        }
        assertFalse(path.exists())
        assertThrows(IOException::class.java) { backing.read(0, 1, ByteArray(1)) }
    }

    @Test fun tamperAndRevocationFailClosed() {
        val access = AtomicBoolean(true)
        val backing = EncryptedPreviewBacking.create(context) { access.get() }
        val path = backingFile()
        try {
            backing.outputStream().use { it.write(ByteArray(70 * 1024) { 42 }) }
            val data = ByteArray(80 * 1024) { 7 }
            RandomAccessFile(path, "rw").use { file ->
                file.seek(64L * 1024 + 20L)
                val original = file.readByte()
                file.seek(64L * 1024 + 20L)
                file.writeByte(original.toInt() xor 1)
            }
            assertThrows(IOException::class.java) { backing.read(0, data.size, data) }
            assertTrue(data.copyOfRange(0, 64 * 1024).all { it == 0.toByte() })
            access.set(false)
            assertThrows(IOException::class.java) { backing.read(0, 1, data) }
            assertThrows(IOException::class.java) { backing.inputStream() }
        } finally {
            backing.close()
        }
        assertFalse(path.exists())
    }

    @Test fun staleCiphertextIsRemovedOnNextCreation() {
        val directory = File(context.cacheDir, "encrypted-previews").apply { mkdirs() }
        val stale = File(directory, "preview-orphan.ciphertext").apply { writeBytes(byteArrayOf(1, 2, 3)) }
        val backing = EncryptedPreviewBacking.create(context) { true }
        try {
            assertFalse(stale.exists())
        } finally {
            backing.close()
        }
    }

    private fun backingFile(): File =
        File(context.cacheDir, "encrypted-previews").listFiles().orEmpty().single { it.name.startsWith("preview-") }
}
