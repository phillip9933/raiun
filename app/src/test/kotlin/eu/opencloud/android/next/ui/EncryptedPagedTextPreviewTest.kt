package eu.opencloud.android.next.ui

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.IOException

@RunWith(RobolectricTestRunner::class)
class EncryptedPagedTextPreviewTest {
    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test fun pagesEndAtCompleteUtf8CodePointsAndKeepExactByteRanges() {
        val backing = EncryptedPreviewBacking.create(context) { true }
        try {
            backing.outputStream().use { output ->
                output.write(ByteArray(64 * 1024 - 1) { 'a'.code.toByte() })
                output.write("🗝️last".toByteArray(Charsets.UTF_8))
            }
            val first = readEncryptedTextPage(backing, 0)
            assertEquals(64 * 1024 - 1, first.length)
            assertTrue(first.text.all { it == 'a' })
            assertTrue(first.hasNext)
            val second = readEncryptedTextPage(backing, first.offset + first.length)
            assertEquals("🗝️last", second.text)
            assertFalse(second.hasNext)
            assertEquals(backing.size, first.length.toLong() + second.length)
            assertEquals("🗝️new", String(requireNotNull(encodeEncryptedTextPage("🗝️new")), Charsets.UTF_8))
        } finally {
            backing.close()
        }
    }

    @Test fun malformedUtf8AndRevokedAccessFailClosed() {
        var allowed = true
        val backing = EncryptedPreviewBacking.create(context) { allowed }
        try {
            backing.outputStream().use { it.write(byteArrayOf(0x61, 0xc3.toByte(), 0x28)) }
            assertThrows(IOException::class.java) { readEncryptedTextPage(backing, 0) }
            allowed = false
            assertThrows(IOException::class.java) { readEncryptedTextPage(backing, 0) }
        } finally {
            backing.close()
        }
    }
}
