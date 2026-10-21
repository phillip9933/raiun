package eu.opencloud.android.next.core.sync

import org.junit.Assert.assertEquals
import org.junit.Test

class UploadDestinationTest {
    @Test
    fun `destination collection paths are built from shallowest to deepest`() {
        assertEquals(
            listOf("/Camera Uploads", "/Camera Uploads/2026", "/Camera Uploads/2026/September"),
            destinationCollectionPaths("/Camera Uploads/2026/September/photo.jpg"),
        )
    }

    @Test
    fun `root upload has no destination collections`() {
        assertEquals(emptyList<String>(), destinationCollectionPaths("/photo.jpg"))
    }
}
