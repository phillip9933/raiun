package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VideoPreviewDetectionTest {
    @Test
    fun `recognizes video mime types and common filename extensions`() {
        assertTrue(resource("recording", "video/mp4").isVideoPreview())
        assertTrue(resource("recording", "video/webm; codecs=vp9").isVideoPreview())
        assertTrue(resource("recording.MKV", null).isVideoPreview())
        assertTrue(resource("recording.mov", "application/octet-stream").isVideoPreview())
    }

    @Test
    fun `does not classify unrelated files as video previews`() {
        assertFalse(resource("notes.txt", "text/plain").isVideoPreview())
        assertFalse(resource("photo.jpg", "image/jpeg").isVideoPreview())
    }

    private fun resource(
        name: String,
        mimeType: String?,
    ) = ResourceEntity(
        accountId = "account",
        spaceId = "space",
        remoteId = name,
        parentId = null,
        path = name,
        name = name,
        kind = ResourceKind.FILE,
        mimeType = mimeType,
        sizeBytes = 1,
        eTag = null,
        modifiedAtEpochMillis = 0,
        createdAtEpochMillis = 0,
    )
}
