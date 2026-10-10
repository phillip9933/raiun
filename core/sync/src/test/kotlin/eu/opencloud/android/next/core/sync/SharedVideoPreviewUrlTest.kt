package eu.opencloud.android.next.core.sync

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SharedVideoPreviewUrlTest {
    @Test
    fun `preview query keeps the share scoped resource path and validator`() {
        val result =
            sharedVideoPreviewUrl(
                "https://cloud.example/remote.php/dav/shares/scope/Video%20One.mp4",
                "\"v1\"",
            )

        assertEquals("/remote.php/dav/shares/scope/Video%20One.mp4", result.encodedPath)
        assertEquals("1", result.queryParameter("preview"))
        assertEquals("128", result.queryParameter("x"))
        assertEquals("128", result.queryParameter("y"))
        assertEquals("v1", result.queryParameter("c"))
    }

    @Test
    fun `preview query omits an absent validator`() {
        val result = sharedVideoPreviewUrl("https://cloud.example/scoped/file.webm", null)

        assertNull(result.queryParameter("c"))
        assertTrue(result.queryParameterNames.containsAll(setOf("preview", "x", "y")))
    }
}
