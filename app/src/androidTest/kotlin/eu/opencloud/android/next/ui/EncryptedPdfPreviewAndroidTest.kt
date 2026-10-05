package eu.opencloud.android.next.ui

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class EncryptedPdfPreviewAndroidTest {
    @Test
    fun rendersPageFromSeekableMemoryOnlyDescriptor() =
        runBlocking {
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            val pdf = singlePagePdf()
            val document = EncryptedPdfDocument.open(context, pdf)
            try {
                val page = document.render(0)
                try {
                    assertEquals(0, page.page)
                    assertEquals(1, page.pages)
                    assertTrue(page.bitmap.width <= 2048)
                    assertTrue(page.bitmap.height <= 2048)
                    assertTrue(page.bitmap.width.toLong() * page.bitmap.height <= 4_000_000L)
                } finally {
                    page.bitmap.recycle()
                }
            } finally {
                document.close()
                assertTrue(document.isBackingCleared())
                pdf.fill(0)
            }
        }

    private fun singlePagePdf(): ByteArray {
        val content = StringBuilder("%PDF-1.4\n")
        val offsets = mutableListOf<Int>()
        listOf(
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
            "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 240 360] /Resources << >> /Contents 4 0 R >>\nendobj\n",
            "4 0 obj\n<< /Length 0 >>\nstream\n\nendstream\nendobj\n",
        ).forEach { objectText ->
            offsets += content.toString().encodeToByteArray().size
            content.append(objectText)
        }
        val xrefOffset = content.toString().encodeToByteArray().size
        content.append("xref\n0 5\n0000000000 65535 f \n")
        offsets.forEach { offset -> content.append(offset.toString().padStart(10, '0')).append(" 00000 n \n") }
        content
            .append("trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n")
            .append(xrefOffset)
            .append("\n%%EOF\n")
        return content.toString().encodeToByteArray()
    }
}
