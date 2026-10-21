package eu.opencloud.android.next.core.sync

import android.net.Uri
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class PhotoMetadataSourceTest {
    @Test fun `document and picker photos qualify for a warning without requiring URI conversion`() {
        assertTrue(
            isPhotoMetadataSource(Uri.parse("content://com.android.providers.media.documents/document/image:7"), null),
        )
        assertTrue(isPhotoMetadataSource(Uri.parse("content://documents.example/document/123"), "image/jpeg"))
        assertTrue(isPhotoMetadataSource(Uri.parse("content://media/picker/0/media/123"), "image/png"))
        assertTrue(isPhotoMetadataSource(Uri.parse("content://media/external/images/media/7"), null))
    }

    @Test fun `nonphotos and unknown files do not request photo location permission`() {
        val uri = Uri.parse("content://documents.example/document/photo.jpg")
        assertFalse(isPhotoMetadataSource(uri, "application/pdf"))
        assertFalse(isPhotoMetadataSource(uri, "video/mp4"))
        assertFalse(isPhotoMetadataSource(uri, null))
        assertFalse(
            isPhotoMetadataSource(Uri.parse("content://com.android.providers.media.documents/document/video:7"), null),
        )
    }
}
