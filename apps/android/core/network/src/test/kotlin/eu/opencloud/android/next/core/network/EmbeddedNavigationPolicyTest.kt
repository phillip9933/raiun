package eu.opencloud.android.next.core.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class EmbeddedNavigationPolicyTest {
    private val policy =
        EmbeddedNavigationPolicy("https://cloud.example/", "https://office.example/editor?token=secret")

    @Test fun `navigation stays on exact delegated editor origin`() {
        assertTrue(policy.allowsNavigation("https://office.example/document?id=1#page2"))
        assertTrue(policy.allowsNavigation("https://office.example:443/"))
        for (url in listOf(
            "https://cloud.example/",
            "https://office.example:444/",
            "https://office.example.evil/",
            "https://evil.example/",
            "//office.example/",
            "http://office.example/",
        )) {
            assertFalse(url, policy.allowsNavigation(url))
        }
    }

    @Test fun `resource scope includes server and editor but not other origins`() {
        assertTrue(policy.allowsResource("https://cloud.example/wopi/files/one"))
        assertTrue(policy.allowsResource("https://office.example/assets/editor.js"))
        assertTrue(policy.allowsResource("blob:https://office.example/opaque-id"))
        assertFalse(policy.allowsNavigation("blob:https://office.example/opaque-id"))
        assertFalse(policy.allowsResource("blob:https://cloud.example/opaque-id"))
        assertFalse(policy.allowsResource("blob:https://evil.example/opaque-id"))
        assertFalse(policy.allowsResource("https://cdn.example/editor.js"))
    }

    @Test fun `local content intents credentials and malformed input are rejected`() {
        for (url in listOf(
            "file:///private",
            "content://private/document",
            "intent://launch",
            "javascript:alert(1)",
            "data:text/html,<script></script>",
            "https://user:secret@office.example/",
            "https://office.example/\nsecret",
            "https://office.example/" + "x".repeat(16_384),
        )) {
            assertFalse(policy.allowsNavigation(url))
            assertFalse(policy.allowsResource(url))
        }
        assertEquals("EmbeddedNavigationPolicy(redacted)", policy.toString())
        assertThrows(OpenCloudException::class.java) {
            EmbeddedNavigationPolicy("http://cloud.example/", "https://office.example/")
        }
        assertThrows(
            OpenCloudException::class.java,
        ) { EmbeddedNavigationPolicy("https://cloud.example/", "file:///private") }
    }
}
