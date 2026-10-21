package eu.opencloud.android.next.core.sync

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Matrix
import android.media.ExifInterface
import eu.opencloud.android.next.core.network.AccountProfileClient
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import android.graphics.Color as BitmapColor

/** Accept the web UI's JPG/PNG inputs; upload a bounded, metadata-free JPEG as the Graph API specifies. */
internal fun profilePhotoJpeg(bytes: ByteArray): ByteArray {
    require(bytes.size in 1..AccountProfileClient.MAX_PHOTO)
    val options = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    BitmapFactory.decodeByteArray(bytes, 0, bytes.size, options)
    require(options.outMimeType in setOf("image/jpeg", "image/png") && options.outWidth > 0 && options.outHeight > 0)
    options.inSampleSize = 1
    while (maxOf(options.outWidth, options.outHeight) / options.inSampleSize > 1024) options.inSampleSize *= 2
    options.inJustDecodeBounds = false
    val source = requireNotNull(BitmapFactory.decodeByteArray(bytes, 0, bytes.size, options))
    val oriented =
        Bitmap.createBitmap(
            source,
            0,
            0,
            source.width,
            source.height,
            photoOrientation(bytes, options.outMimeType),
            true,
        )
    val side = minOf(oriented.width, oriented.height)
    val square = Bitmap.createBitmap(oriented, (oriented.width - side) / 2, (oriented.height - side) / 2, side, side)
    val scaled = Bitmap.createScaledBitmap(square, 256, 256, true)
    val output = Bitmap.createBitmap(256, 256, Bitmap.Config.ARGB_8888)
    Canvas(output).apply {
        drawColor(BitmapColor.WHITE)
        drawBitmap(scaled, 0f, 0f, null)
    }
    return try {
        ByteArrayOutputStream().use { buffer ->
            check(output.compress(Bitmap.CompressFormat.JPEG, 90, buffer))
            buffer.toByteArray()
        }
    } finally {
        // Bitmap helpers can return their input when no transform is necessary.
        listOf(source, oriented, square, scaled, output).distinct().forEach(Bitmap::recycle)
    }
}

private fun photoOrientation(
    bytes: ByteArray,
    mime: String?,
): Matrix {
    val orientation =
        if (mime == "image/jpeg") {
            try {
                ExifInterface(
                    ByteArrayInputStream(bytes),
                ).getAttributeInt(ExifInterface.TAG_ORIENTATION, ExifInterface.ORIENTATION_NORMAL)
            } catch (_: IOException) {
                ExifInterface.ORIENTATION_NORMAL
            }
        } else {
            ExifInterface.ORIENTATION_NORMAL
        }
    return Matrix().apply {
        when (orientation) {
            ExifInterface.ORIENTATION_FLIP_HORIZONTAL -> setScale(-1f, 1f)
            ExifInterface.ORIENTATION_ROTATE_180 -> setRotate(180f)
            ExifInterface.ORIENTATION_FLIP_VERTICAL -> setScale(1f, -1f)
            ExifInterface.ORIENTATION_TRANSPOSE -> {
                setRotate(90f)
                postScale(-1f, 1f)
            }
            ExifInterface.ORIENTATION_ROTATE_90 -> setRotate(90f)
            ExifInterface.ORIENTATION_TRANSVERSE -> {
                setRotate(-90f)
                postScale(-1f, 1f)
            }
            ExifInterface.ORIENTATION_ROTATE_270 -> setRotate(-90f)
        }
    }
}
