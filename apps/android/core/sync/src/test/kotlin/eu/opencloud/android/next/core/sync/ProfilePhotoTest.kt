package eu.opencloud.android.next.core.sync

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.io.ByteArrayOutputStream

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35])
class ProfilePhotoTest {
    @Test fun pngBecomesASquareJpegWithBoundedDimensions() {
        val image = Bitmap.createBitmap(800, 600, Bitmap.Config.ARGB_8888).apply { eraseColor(Color.RED) }
        val input = ByteArrayOutputStream().apply { image.compress(Bitmap.CompressFormat.PNG, 100, this) }.toByteArray()
        image.recycle()
        val result = profilePhotoJpeg(input)
        val options = BitmapFactory.Options()
        val bitmap = BitmapFactory.decodeByteArray(result, 0, result.size, options)!!
        try {
            assertEquals("image/jpeg", options.outMimeType)
            assertEquals(256, bitmap.width)
            assertEquals(256, bitmap.height)
            assertTrue(Color.red(bitmap.getPixel(128, 128)) > 240)
        } finally {
            bitmap.recycle()
        }
    }

    @Test fun cameraOrientationIsAppliedBeforeRemovingMetadata() {
        val image = Bitmap.createBitmap(256, 256, Bitmap.Config.ARGB_8888)
        for (y in 0 until 256) for (x in 0 until 256) image.setPixel(x, y, if (y < 128) Color.RED else Color.BLUE)
        val file =
            java.io.File.createTempFile(
                "profile-photo",
                ".jpg",
                org.robolectric.RuntimeEnvironment
                    .getApplication()
                    .cacheDir,
            )
        try {
            file.outputStream().use { image.compress(Bitmap.CompressFormat.JPEG, 95, it) }
            image.recycle()
            android.media.ExifInterface(file.path).apply {
                setAttribute(
                    android.media.ExifInterface.TAG_ORIENTATION,
                    android.media.ExifInterface.ORIENTATION_ROTATE_90
                        .toString(),
                )
                saveAttributes()
            }
            val bytes = profilePhotoJpeg(file.readBytes())
            val result = BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
            assertTrue(Color.blue(result.getPixel(32, 128)) > 240)
            assertTrue(Color.red(result.getPixel(224, 128)) > 240)
            result.recycle()
        } finally {
            file.delete()
        }
    }

    @Test fun invalidPictureIsRejectedBeforeUpload() {
        assertThrows(IllegalArgumentException::class.java) { profilePhotoJpeg("not a photo".toByteArray()) }
    }
}
