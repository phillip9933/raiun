package eu.opencloud.android.next.core.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class CapabilitiesParserTest {
    private val parser = CapabilitiesParser()

    @Test
    fun `unrelated strings and explicit false cannot enable features`() {
        val result =
            parse(
                """{"files":{"description":"tus spaces"},"spaces":{"enabled":false},
                "files_sharing":{"api_enabled":false,"api":{"enabled":true}},
                "dav":{"trashbin":{"enabled":false,"version":"1.0"}}}""",
            )
        assertFalse(result.spacesEnabled)
        assertFalse(result.tusSupported)
        assertFalse(result.sharingEnabled)
        assertFalse(result.trashSupported)
    }

    @Test
    fun `documented tus versions are required`() {
        assertTrue(parse("""{"files":{"tus_support":{"version":"1.0.0","resumable":"1.0.0"}}}""").tusSupported)
        assertFalse(parse("""{"files":{"tus_support":{"version":"2.0.0","resumable":"2.0.0"}}}""").tusSupported)
        assertFalse(parse("""{"files":{"tus_support":{}}}""").tusSupported)
    }

    @Test
    fun `absent fields disable features but invalid envelopes fail safely`() {
        assertFalse(parse("{}").sharingEnabled)
        for (body in listOf("not-json", "{}", """{"ocs":{"meta":{"statuscode":403},"data":{"capabilities":{}}}}""")) {
            val failure = assertThrows(OpenCloudException::class.java) { parser.parse(body, "https://cloud.example") }
            assertFalse(failure.toString().contains(body))
        }
    }

    private fun parse(capabilities: String) =
        parser.parse("""{"ocs":{"data":{"capabilities":$capabilities}}}""", "https://cloud.example")

    @Test
    fun `only enabled advertised app registries are exposed`() {
        val result =
            parse(
                """{"files":{"app_providers":[
            {"enabled":true,"apps_url":"/app/list","open_web_url":"/app/open-web","open_url":"/app/open"},
            {"enabled":false,"apps_url":"/disabled"}, {"enabled":true}, {"apps_url":"/implicit"}
        ]}}""",
            )
        assertEquals(1, result.appProviders.size)
        assertEquals("/app/list", result.appProviders.single().appsUrl)
        assertEquals("/app/open-web", result.appProviders.single().openWebUrl)
        assertEquals("/app/open", result.appProviders.single().openUrl)
        assertTrue(parse("{}").appProviders.isEmpty())
        assertTrue(parse("""{"files":{"app_providers":null}}""").appProviders.isEmpty())
    }
}
