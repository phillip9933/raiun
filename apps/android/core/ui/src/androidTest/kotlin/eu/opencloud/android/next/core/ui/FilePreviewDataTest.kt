package eu.opencloud.android.next.core.ui

import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.pdf.PdfDocument
import androidx.test.ext.junit.runners.AndroidJUnit4
import eu.opencloud.android.next.core.datastore.PreviewKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import java.nio.charset.CharacterCodingException

@RunWith(AndroidJUnit4::class)
class FilePreviewDataTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun textReadsCurrentSnapshotAndRejectsInvalidEncoding() {
        val file = temporary.newFile()
        copyPreview("Restored version ✓".byteInputStream(), file)
        assertEquals("Restored version ✓", readPreview(file, PreviewKind.TEXT, 0).text)
        file.writeBytes(byteArrayOf(0xc3.toByte(), 0x28))
        assertThrows(CharacterCodingException::class.java) { readPreview(file, PreviewKind.TEXT, 0) }
        file.writeBytes(ByteArray(1024 * 1024 + 1))
        assertThrows(IllegalArgumentException::class.java) { readPreview(file, PreviewKind.TEXT, 0) }
    }

    @Test fun pdfRendersRequestedPageAndReportsPageCount() {
        val file = temporary.newFile()
        val document = PdfDocument()
        try {
            repeat(2) { index ->
                val page = document.startPage(PdfDocument.PageInfo.Builder(200, 300, index).create())
                page.canvas.drawColor(if (index == 0) Color.RED else Color.BLUE)
                document.finishPage(page)
            }
            file.outputStream().use { document.writeTo(it) }
        } finally {
            document.close()
        }
        val first = readPreview(file, PreviewKind.PDF, 0)
        val second = readPreview(file, PreviewKind.PDF, 1)
        assertEquals(2, second.pages)
        assertEquals(1, second.page)
        assertEquals(Color.RED, requireNotNull(first.bitmap).getPixel(100, 100))
        assertEquals(Color.BLUE, requireNotNull(second.bitmap).getPixel(100, 100))
    }

    @Test fun imagePreviewBoundsDecodedMemory() {
        val file = temporary.newFile()
        val original = Bitmap.createBitmap(4096, 64, Bitmap.Config.ARGB_8888)
        file.outputStream().use { original.compress(Bitmap.CompressFormat.PNG, 100, it) }
        original.recycle()
        val result = readPreview(file, PreviewKind.IMAGE, 0)
        assertNotNull(result.bitmap)
        assertEquals(2048, requireNotNull(result.bitmap).width)
    }
}
