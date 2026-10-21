package eu.opencloud.android.next.feature.spaces

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class SpaceActionsTest {
    @Test fun quotaMustBePositiveAndExactlyRepresentable() {
        assertEquals(1_073_741_824L, quotaBytes("1"))
        assertEquals(536_870_912L, quotaBytes("0.5"))
        listOf("", "abc", "0", "-1", "9223372036854775807", "0.00000000000001").forEach {
            assertNull(quotaBytes(it))
        }
    }

    @Test fun webHandoffStaysOnTheTrustedOrigin() {
        assertEquals(
            "https://cloud.example/f/space",
            trustedSpaceWebUrl("https://cloud.example", "https://cloud.example/f/space"),
        )
        listOf(
            null,
            "https://other.example/f/space",
            "http://cloud.example/f/space",
            "https://user:secret@cloud.example/f/space",
            "https://cloud.example:8443/f/space",
            "javascript:alert(1)",
            "/f/space",
            "https://cloud.example/f/space#token",
            "not a url",
        ).forEach {
            assertNull(trustedSpaceWebUrl("https://cloud.example", it))
        }
    }
}
