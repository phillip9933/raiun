package eu.opencloud.android.next.core.documentsprovider

import android.provider.DocumentsContract
import android.provider.DocumentsContract.Document
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.FileNotFoundException

@RunWith(RobolectricTestRunner::class)
class SharedRootRowsTest {
    private val row = SharedRootRow(SharedDocumentId("a", "share", "scope", "root"), "Shared photos")
    private val columns =
        arrayOf(Document.COLUMN_DOCUMENT_ID, Document.COLUMN_MIME_TYPE, Document.COLUMN_FLAGS, "other")

    @Test fun emitsOnlyUsableReadOnlyRowsWithProjectionAndUnavailableNotice() =
        runBlocking {
            val rows = SharedRootRows({ SharedRootListing(listOf(row), 1) { true } }, { { true } })
            rows.query("a", columns).use { cursor ->
                assertEquals(1, cursor.count)
                cursor.moveToFirst()
                assertEquals(row.id.encode(), cursor.getString(0))
                assertEquals(Document.MIME_TYPE_DIR, cursor.getString(1))
                assertEquals(0, cursor.getInt(2))
                assertEquals(null, cursor.getString(3))
                assertNotNull(cursor.extras.getString(DocumentsContract.EXTRA_ERROR))
            }
        }

    @Test fun rejectsStaleEmptyCatalogAndLateLock() =
        runBlocking<Unit> {
            val empty = SharedRootRows({ SharedRootListing(emptyList(), 0) { false } }, { { true } })
            assertThrows(FileNotFoundException::class.java) { runBlocking { empty.query("a", columns) } }
            var allowed = true
            val locked =
                SharedRootRows({
                    SharedRootListing(listOf(row), 0) {
                        allowed = false
                        true
                    }
                }, { { allowed } })
            assertThrows(FileNotFoundException::class.java) { runBlocking { locked.query("a", columns) } }
        }

    @Test fun rejectsForeignAndDuplicateRows() =
        runBlocking {
            val foreign = row.copy(id = row.id.copy(account = "b"))
            for (items in listOf(listOf(row, row), listOf(foreign))) {
                val rows = SharedRootRows({ SharedRootListing(items, 0) { true } }, { { true } })
                assertThrows(FileNotFoundException::class.java) { runBlocking { rows.query("a", columns) } }
            }
        }

    @Test fun failedOrCancelledDiscoveryNeverBecomesEmptySuccess() =
        runBlocking<Unit> {
            val cancelled = SharedRootRows({ throw CancellationException() }, { { true } })
            assertThrows(CancellationException::class.java) { runBlocking { cancelled.query("a", columns) } }
            val failed = SharedRootRows({ throw FileNotFoundException() }, { { true } })
            assertThrows(FileNotFoundException::class.java) { runBlocking { failed.query("a", columns) } }
        }
}
