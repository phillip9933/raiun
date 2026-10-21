package eu.opencloud.android.next.core.documentsprovider

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class PagedDocumentCursorTest {
    @Test fun `large directory loads only requested pages and supports backwards seeks`() {
        val requests = mutableListOf<Int>()
        PagedDocumentCursor(arrayOf("name", "size"), 10_000) { offset ->
            requests.add(offset)
            (offset until minOf(offset + 128, 10_000)).map { arrayOf<Any?>("file-$it", it.toLong()) }
        }.use { cursor ->
            assertEquals(10_000, cursor.count)
            assertTrue(requests.isEmpty())
            assertTrue(cursor.moveToPosition(9_999))
            assertEquals("file-9999", cursor.getString(0))
            assertEquals(9_999L, cursor.getLong(1))
            assertTrue(cursor.moveToPosition(9_998))
            assertEquals(listOf(9_984), requests)
            assertTrue(cursor.moveToFirst())
            assertEquals("file-0", cursor.getString(0))
            assertEquals(listOf(9_984, 0), requests)
            assertFalse(cursor.moveToPosition(10_000))
        }
    }
}
