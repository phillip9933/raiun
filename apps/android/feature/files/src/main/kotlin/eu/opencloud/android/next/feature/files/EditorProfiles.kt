package eu.opencloud.android.next.feature.files

import android.annotation.SuppressLint
import android.webkit.WebView
import androidx.webkit.ProfileStore
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import java.util.UUID

internal interface EditorProfileStorage {
    fun names(): Set<String>

    fun delete(name: String)
}

/** UI-thread-only registry. Fresh names isolate each session; loaded profiles may await process restart for deletion. */
internal class EditorProfileRegistry(
    private val storage: EditorProfileStorage,
) {
    private val active = mutableSetOf<String>()

    fun acquire(): EditorProfileLease {
        storage.names().filter { owned(it) && it !in active }.forEach(::deleteIfUnloaded)
        val retained = storage.names().filter(::owned).toSet() + active
        if (retained.size >= MAX_PROFILES) throw OpenCloudException(OpenCloudError.Unsupported)
        val name = PREFIX + UUID.randomUUID()
        check(name !in retained)
        active.add(name)
        return EditorProfileLease(name) {
            active.remove(name)
            deleteIfUnloaded(name)
        }
    }

    private fun deleteIfUnloaded(name: String) {
        try {
            storage.delete(name)
        } catch (_: IllegalStateException) {
            // WebKit cannot delete a profile loaded in this process; a later process retries before loading it.
        }
    }

    private fun owned(name: String): Boolean =
        name.startsWith(PREFIX) && UUID_PATTERN.matches(name.removePrefix(PREFIX))

    companion object {
        private const val PREFIX = "opencloud-editor-"
        private const val MAX_PROFILES = 32
        private val UUID_PATTERN = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
    }
}

internal class EditorProfileLease(
    val name: String,
    private val release: () -> Unit,
) {
    private var closed = false

    /** Destroy the associated WebView before closing this lease. */
    fun close() {
        if (!closed) {
            closed = true
            release()
        }
    }

    override fun toString(): String = "EditorProfileLease(redacted)"
}

internal object AndroidEditorProfiles {
    fun supported(): Boolean = WebViewFeature.isFeatureSupported(WebViewFeature.MULTI_PROFILE)

    // Private storage is only used by attach after the explicit runtime feature check.
    @SuppressLint("RequiresFeature")
    private val registry =
        EditorProfileRegistry(
            object : EditorProfileStorage {
                override fun names(): Set<String> = ProfileStore.getInstance().allProfileNames.toSet()

                override fun delete(name: String) {
                    ProfileStore.getInstance().deleteProfile(name)
                }
            },
        )

    /** Must precede every other WebView API, except attachment to its view hierarchy. */
    fun attach(view: WebView): EditorProfileLease {
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.MULTI_PROFILE)) {
            throw OpenCloudException(OpenCloudError.Unsupported)
        }
        val lease = registry.acquire()
        var attached = false
        try {
            WebViewCompat.setProfile(view, lease.name)
            // A session must not keep a background network worker after its WebView is destroyed.
            WebViewCompat.getProfile(view).serviceWorkerController.serviceWorkerWebSettings.apply {
                blockNetworkLoads = true
                allowFileAccess = false
                allowContentAccess = false
                cacheMode = android.webkit.WebSettings.LOAD_NO_CACHE
            }
            attached = true
        } finally {
            if (!attached) lease.close()
        }
        return lease
    }
}
