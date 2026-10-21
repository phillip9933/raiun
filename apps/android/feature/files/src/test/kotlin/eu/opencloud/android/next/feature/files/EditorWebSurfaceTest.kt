package eu.opencloud.android.next.feature.files

import android.content.Context
import android.webkit.WebSettings
import android.webkit.WebView
import eu.opencloud.android.next.core.network.EmbeddedWebAppSession
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class EditorWebSurfaceTest {
    private val context: Context = RuntimeEnvironment.getApplication()
    private val events = mutableListOf<String>()
    private val view = RecordingView(context)

    private fun surface(attachFails: Boolean = false) =
        EditorWebSurface(
            context,
            "https://cloud.example",
            { events.add("failed") },
            { view },
            {
                events.add("attach")
                check(!attachFails)
                val release: () -> Unit = {
                    events.add("release")
                }
                release
            },
        )

    @Test fun isolatesBeforeLoadingAndDestroysBeforeReleasing() {
        val surface = surface()
        surface.show(session("POST"))
        assertEquals(listOf("attach", "post:access_token=a%26b"), events)
        assertEquals(1, surface.container.childCount)
        assertFalse(view.settings.allowFileAccess)
        assertFalse(view.settings.allowContentAccess)
        assertEquals(WebSettings.MIXED_CONTENT_NEVER_ALLOW, view.settings.mixedContentMode)
        assertEquals(WebSettings.LOAD_NO_CACHE, view.settings.cacheMode)
        assertTrue(view.settings.javaScriptEnabled)
        assertFalse(view.isSaveEnabled)
        surface.close()
        surface.close()
        assertEquals(0, surface.container.childCount)
        assertEquals(listOf("attach", "post:access_token=a%26b", "destroy", "release"), events)
        assertThrows(IllegalStateException::class.java) { surface.show(session("GET")) }
    }

    @Test fun getIsLoadedOnceWithoutInventingPostData() {
        val surface = surface()
        surface.show(session("GET"))
        assertEquals(listOf("attach", "get"), events)
        assertThrows(IllegalStateException::class.java) { surface.show(session("GET")) }
        surface.close()
    }

    @Test fun failedIsolationDestroysViewWithoutLoading() {
        val surface = surface(attachFails = true)
        assertThrows(IllegalStateException::class.java) { surface.show(session("GET")) }
        assertEquals(listOf("attach", "destroy"), events)
        assertEquals(0, surface.container.childCount)
    }

    @Test fun failedLoadReleasesProfileAndCannotBeResumed() {
        view.failLoad = true
        val surface = surface()
        assertThrows(IllegalStateException::class.java) { surface.show(session("GET")) }
        assertEquals(listOf("attach", "get", "destroy", "release"), events)
        assertThrows(IllegalStateException::class.java) { surface.show(session("GET")) }
    }

    // Construct a protocol fixture without widening the production model's internal constructor.
    private fun session(method: String): EmbeddedWebAppSession =
        EmbeddedWebAppSession::class.java
            .getDeclaredConstructor(
                String::class.java,
                String::class.java,
                Map::class.java,
            ).newInstance("https://office.example/editor", method, mapOf("access_token" to "a&b"))

    private inner class RecordingView(
        context: Context,
    ) : WebView(context) {
        var failLoad = false

        override fun loadUrl(url: String) {
            events.add("get")
            check(!failLoad)
        }

        override fun postUrl(
            url: String,
            postData: ByteArray,
        ) {
            events.add("post:${postData.toString(Charsets.UTF_8)}")
            check(!failLoad)
        }

        override fun destroy() {
            events.add("destroy")
            super.destroy()
        }
    }
}
