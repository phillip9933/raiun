package eu.opencloud.android.next

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.pdf.PdfRenderer
import android.os.ParcelFileDescriptor
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.offlinescan.core.Cancellation
import dev.offlinescan.core.Edits
import dev.offlinescan.core.ExportFormat
import dev.offlinescan.core.Preset
import dev.offlinescan.core.ScanConfig
import dev.offlinescan.core.ScanSession
import dev.offlinescan.export.AndroidExporter
import dev.offlinescan.processing.OpenCvProcessor
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.concurrent.CancellationException

/** Exercises the native scanner artifacts as packaged in the host APK, without camera or network. */
@RunWith(AndroidJUnit4::class)
class ScannerSdkIntegrationAndroidTest {
    @Test
    fun exportedDetailAndMultiPagePdfKeepSourceResolutionWithoutDiagnostics() {
        val root = testRoot()
        try {
            val source = File(root, "printed-page.png")
            writePrintedPage(source)
            val originalBytes = source.readBytes()
            val config = ScanConfig()
            val processor = OpenCvProcessor()
            val outputDirectory = File(root, "output")
            ScanSession(config, File(root, "session"), processor).use { session ->
                val first = session.`import`(source)
                val second = session.`import`(source)
                session.update(first.id, Edits(preset = Preset.ORIGINAL))
                session.update(second.id, Edits(preset = Preset.ORIGINAL))

                val jpeg =
                    AndroidExporter(
                        processor,
                    ).export(session.pages.take(1), outputDirectory, ExportFormat.JPEG, config)
                assertEquals("image/jpeg", jpeg.mimeType)
                assertEquals(1, jpeg.files.size)
                assertEquals(2300, jpeg.pages.single().width)
                assertEquals(3100, jpeg.pages.single().height)
                assertTrue(jpeg.warnings.isEmpty())
                assertNull(jpeg.diagnostics)
                assertEquals(
                    listOf("page-1.jpg"),
                    jpeg.files
                        .single()
                        .parentFile!!
                        .listFiles()!!
                        .map(File::getName),
                )
                val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                BitmapFactory.decodeFile(jpeg.files.single().path, bounds)
                assertEquals(2300, bounds.outWidth)
                assertEquals(3100, bounds.outHeight)
                val rendered = BitmapFactory.decodeFile(jpeg.files.single().path)
                try {
                    assertTrue(Color.red(rendered.getPixel(70, 70)) > 240)
                    assertTrue(Color.red(rendered.getPixel(150, 500)) < 100)
                } finally {
                    rendered.recycle()
                }

                val pdf = AndroidExporter(processor).export(session.pages, outputDirectory, ExportFormat.PDF, config)
                assertEquals("application/pdf", pdf.mimeType)
                assertEquals(2, pdf.pageCount)
                assertTrue(pdf.pages.all { it.width == 2300 && it.height == 3100 })
                assertNull(pdf.diagnostics)
                assertEquals(
                    listOf("scan.pdf"),
                    pdf.files
                        .single()
                        .parentFile!!
                        .listFiles()!!
                        .map(File::getName),
                )
                val pdfText =
                    pdf.files
                        .single()
                        .readBytes()
                        .toString(Charsets.ISO_8859_1)
                assertEquals(2, Regex("/Subtype /Image /Width 2300 /Height 3100\\b").findAll(pdfText).count())
                ParcelFileDescriptor.open(pdf.files.single(), ParcelFileDescriptor.MODE_READ_ONLY).use { descriptor ->
                    PdfRenderer(descriptor).use { renderer ->
                        assertEquals(2, renderer.pageCount)
                        repeat(renderer.pageCount) { index ->
                            renderer.openPage(index).use { page ->
                                assertEquals(552, page.width) // 2300 pixels at 300 DPI, in PDF points.
                                assertEquals(744, page.height)
                            }
                        }
                    }
                }
                assertArrayEquals(originalBytes, first.original.readBytes())
                assertArrayEquals(originalBytes, second.original.readBytes())
            }
            assertArrayEquals(originalBytes, source.readBytes())
            assertFalse(File(root, "session").listFiles().orEmpty().any())
            assertEquals(2, outputDirectory.listFiles().orEmpty().size)
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun cancelledExportClearsStagingAndPreservesOriginal() {
        val root = testRoot()
        try {
            val source = File(root, "printed-page.png")
            writePrintedPage(source)
            val originalBytes = source.readBytes()
            val config = ScanConfig()
            val processor = OpenCvProcessor()
            val outputDirectory = File(root, "output")
            ScanSession(config, File(root, "session"), processor).use { session ->
                session.`import`(source)
                try {
                    AndroidExporter(processor).export(
                        pages = session.pages,
                        destination = outputDirectory,
                        format = ExportFormat.JPEG,
                        config = config,
                        cancellation = Cancellation { throw CancellationException("synthetic cancellation") },
                    )
                    fail("Export should have been cancelled")
                } catch (_: CancellationException) {
                    // The exporter must remove its staging directory on cancellation.
                }
                assertTrue(outputDirectory.listFiles().orEmpty().isEmpty())
                assertArrayEquals(
                    originalBytes,
                    session.pages
                        .single()
                        .original
                        .readBytes(),
                )
            }
            assertArrayEquals(originalBytes, source.readBytes())
        } finally {
            root.deleteRecursively()
        }
    }

    private fun testRoot(): File =
        File(
            InstrumentationRegistry.getInstrumentation().targetContext.cacheDir,
            "scanner-sdk-integration-${System.nanoTime()}",
        ).apply { check(mkdirs()) }

    private fun writePrintedPage(file: File) {
        val bitmap = Bitmap.createBitmap(2300, 3100, Bitmap.Config.ARGB_8888)
        try {
            val canvas = Canvas(bitmap)
            canvas.drawColor(Color.WHITE)
            val ink =
                Paint(Paint.ANTI_ALIAS_FLAG).apply {
                    color = Color.BLACK
                    textSize = 32f
                }
            repeat(24) { row ->
                canvas.drawText(
                    "SCAN DETAIL 0123456789  abcdefghijklmnopqrstuvwxyz",
                    90f,
                    200f + row * 105f,
                    ink,
                )
            }
            canvas.drawRect(100f, 450f, 200f, 550f, ink)
            file.outputStream().use { check(bitmap.compress(Bitmap.CompressFormat.PNG, 100, it)) }
        } finally {
            bitmap.recycle()
        }
    }
}
