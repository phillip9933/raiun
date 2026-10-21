package eu.opencloud.android.next.feature.files

import android.net.Uri
import android.webkit.PermissionRequest
import android.webkit.WebResourceRequest
import eu.opencloud.android.next.core.network.EmbeddedNavigationPolicy
import eu.opencloud.android.next.core.network.OpenCloudError
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class EditorWebClientsTest {
    private val failures = mutableListOf<OpenCloudError>()
    private val client =
        EditorWebClient(
            EmbeddedNavigationPolicy("https://cloud.example", "https://office.example/editor"),
            failures::add,
        )

    @Test fun navigationAndResourcesUseDifferentScopes() {
        val server = Request("https://cloud.example/resource", true)
        assertTrue(client.shouldOverrideUrlLoading(null, server))
        assertEquals(403, client.shouldInterceptRequest(null, server)!!.statusCode)
        assertNull(client.shouldInterceptRequest(null, Request("https://cloud.example/resource", false)))
        assertFalse(client.shouldOverrideUrlLoading(null, Request("https://office.example/document", true)))
        for (url in listOf("intent://open", "file:///private", "content://document", "https://foreign.example")) {
            assertTrue(client.shouldOverrideUrlLoading(null, Request(url, true)))
            val blocked = client.shouldInterceptRequest(null, Request(url, false))!!
            assertEquals(403, blocked.statusCode)
            assertEquals(-1, blocked.data.read())
        }
    }

    @Test fun unexpectedPagePermanentlyClosesClientWithOneSanitizedFailure() {
        client.onPageStarted(null, "https://foreign.example/?token=secret", null)
        client.onPageStarted(null, "https://another.example", null)
        assertEquals(listOf(OpenCloudError.Trust), failures)
        assertTrue(client.shouldOverrideUrlLoading(null, Request("https://office.example", true)))
        assertEquals(403, client.shouldInterceptRequest(null, Request("https://office.example", false))!!.statusCode)
    }

    @Test fun rendererTerminationIsHandledAndReportedOnce() {
        assertTrue(client.onRenderProcessGone(null, null))
        assertTrue(client.onRenderProcessGone(null, null))
        assertEquals(listOf(OpenCloudError.Unknown), failures)
    }

    @Test fun explicitCloseBlocksRequestsWithoutReportingFailure() {
        client.close()
        client.onPageStarted(null, "https://office.example", null)
        assertTrue(failures.isEmpty())
        assertTrue(client.shouldOverrideUrlLoading(null, Request("https://office.example", true)))
    }

    @Test fun chromeDeniesNativeCapabilitiesAndConsumesConsoleOutput() {
        val chrome = EditorChromeClient()
        var denied = false
        chrome.onPermissionRequest(
            object : PermissionRequest() {
                override fun getOrigin(): Uri = Uri.parse("https://office.example")

                override fun getResources(): Array<String> = arrayOf(RESOURCE_VIDEO_CAPTURE, "future-resource")

                override fun grant(resources: Array<out String>?) {
                    error("must not grant")
                }

                override fun deny() {
                    denied = true
                }
            },
        )
        assertTrue(denied)
        var locationDenied = false
        chrome.onGeolocationPermissionsShowPrompt("https://office.example") { _, allow, retain ->
            locationDenied = !allow && !retain
        }
        assertTrue(locationDenied)
        assertFalse(chrome.onShowFileChooser(null, null, null))
        assertFalse(chrome.onCreateWindow(null, false, true, null))
        assertTrue(chrome.onConsoleMessage(null))
    }

    private class Request(
        private val address: String,
        private val main: Boolean,
    ) : WebResourceRequest {
        override fun getUrl(): Uri = Uri.parse(address)

        override fun isForMainFrame(): Boolean = main

        override fun isRedirect(): Boolean = false

        override fun hasGesture(): Boolean = true

        override fun getMethod(): String = "GET"

        override fun getRequestHeaders(): MutableMap<String, String> = mutableMapOf()
    }
}
