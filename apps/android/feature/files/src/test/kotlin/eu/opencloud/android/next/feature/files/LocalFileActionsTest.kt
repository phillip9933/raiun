package eu.opencloud.android.next.feature.files

import android.content.Intent
import android.graphics.Bitmap
import android.media.ExifInterface
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.io.File

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class LocalFileActionsTest {
    @Test fun sendGrantsReadAccessToExactlyTheSharedDocument() {
        val resource =
            ResourceEntity(
                "a",
                "s",
                "id",
                null,
                "/photo.jpg",
                "photo.jpg",
                ResourceKind.FILE,
                "image/jpeg",
                4,
                null,
                0,
                0,
            )
        val intent = externalSendIntent(RuntimeEnvironment.getApplication(), resource)
        assertEquals(Intent.ACTION_SEND, intent.action)
        assertEquals("image/jpeg", intent.type)
        assertEquals(
            intent.clipData!!.getItemAt(0).uri,
            intent.getParcelableExtra<android.net.Uri>(Intent.EXTRA_STREAM),
        )
        assertTrue(intent.flags and Intent.FLAG_GRANT_READ_URI_PERMISSION != 0)
        assertEquals(0, intent.flags and Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
    }

    @Test fun photoDetailsReadEmbeddedExif() {
        val file = File(RuntimeEnvironment.getApplication().cacheDir, "details.jpg")
        val bitmap = Bitmap.createBitmap(8, 8, Bitmap.Config.ARGB_8888)
        file.outputStream().use { bitmap.compress(Bitmap.CompressFormat.JPEG, 90, it) }
        bitmap.recycle()
        ExifInterface(file).apply {
            setAttribute(ExifInterface.TAG_MAKE, "Test camera")
            setAttribute(ExifInterface.TAG_DATETIME_ORIGINAL, "2026:09:29 12:34:56")
            saveAttributes()
        }
        assertTrue(readPhotoMetadata(file).contains("Camera make: Test camera"))
        assertTrue(readPhotoMetadata(file).contains("Taken: 2026:09:29 12:34:56"))
    }

    @Test fun cleanupDetailsDistinguishPinnedNeverAndExpired() {
        val file =
            File(RuntimeEnvironment.getApplication().cacheDir, "temporary").apply {
                writeText("data")
                setLastModified(1000)
            }
        assertTrue(localCopyDescription(file, true, 1).contains("Kept offline"))
        assertTrue(localCopyDescription(file, false, 0).contains("Never"))
        assertTrue(localCopyDescription(file, false, 1, now = 4_000_000).contains("cleanup now"))
        assertEquals("Cloud only", localCopyDescription(null, false, 1))
    }
}
