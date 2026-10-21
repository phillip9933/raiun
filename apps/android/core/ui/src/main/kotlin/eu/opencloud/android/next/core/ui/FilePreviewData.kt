package eu.opencloud.android.next.core.ui

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.ImageDecoder
import android.graphics.pdf.PdfRenderer
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.compose.ui.graphics.toArgb
import eu.opencloud.android.next.core.datastore.PreviewKind
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudColor
import java.io.File
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction

/** Private, bounded snapshot for a viewer session; never uses an editor draft. */
fun copyPreview(
    input: InputStream,
    destination: File,
) {
    input.use { source ->
        destination.outputStream().use { output ->
            val buffer = ByteArray(8192)
            var total = 0L
            var count = source.read(buffer)
            while (count >= 0) {
                total += count
                require(total <= 100L * 1024 * 1024)
                output.write(buffer, 0, count)
                count = source.read(buffer)
            }
        }
    }
}

data class FilePreviewState(
    val loading: Boolean = true,
    val text: String? = null,
    val bitmap: Bitmap? = null,
    val page: Int = 0,
    val pages: Int = 0,
    val failed: Boolean = false,
)

internal fun readPreview(
    file: File,
    kind: PreviewKind,
    page: Int,
): FilePreviewState =
    when (kind) {
        PreviewKind.TEXT -> {
            require(file.length() <= 1024 * 1024)
            val text =
                Charsets.UTF_8
                    .newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(file.readBytes()))
                    .toString()
            FilePreviewState(loading = false, text = text)
        }
        PreviewKind.IMAGE -> {
            val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            BitmapFactory.decodeFile(file.path, bounds)
            require(bounds.outWidth > 0 && bounds.outHeight > 0)
            var sample = 1
            while (bounds.outWidth / sample > 2048 || bounds.outHeight / sample > 2048) sample *= 2
            val bitmap =
                requireNotNull(
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        ImageDecoder.decodeBitmap(ImageDecoder.createSource(file)) { decoder, _, _ ->
                            decoder.setTargetSampleSize(sample)
                            decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
                        }
                    } else {
                        BitmapFactory.decodeFile(
                            file.path,
                            BitmapFactory.Options().apply {
                                inSampleSize =
                                    sample
                            },
                        )
                    },
                )
            FilePreviewState(loading = false, bitmap = bitmap)
        }
        PreviewKind.PDF -> readPdf(file, page)
    }

private fun readPdf(
    file: File,
    page: Int,
): FilePreviewState =
    ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY).use { descriptor ->
        PdfRenderer(descriptor).use { renderer ->
            renderer.openPage(page).use { pdfPage ->
                val scale = minOf(1600f / pdfPage.width, 2000f / pdfPage.height)
                val bitmap =
                    Bitmap.createBitmap(
                        (pdfPage.width * scale).toInt().coerceAtLeast(1),
                        (pdfPage.height * scale).toInt().coerceAtLeast(1),
                        Bitmap.Config.ARGB_8888,
                    )
                bitmap.eraseColor(OpenCloudColor.DocumentPaper.toArgb())
                pdfPage.render(bitmap, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                FilePreviewState(loading = false, bitmap = bitmap, page = page, pages = renderer.pageCount)
            }
        }
    }
