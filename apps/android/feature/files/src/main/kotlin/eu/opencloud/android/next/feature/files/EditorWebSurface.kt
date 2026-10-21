package eu.opencloud.android.next.feature.files

import android.annotation.SuppressLint
import android.content.Context
import android.view.View
import android.webkit.WebSettings
import android.webkit.WebView
import android.widget.FrameLayout
import eu.opencloud.android.next.core.network.EmbeddedNavigationPolicy
import eu.opencloud.android.next.core.network.EmbeddedWebAppSession
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.sync.EmbeddedSessionSurface

/** Single-use, UI-thread-owned surface. Its owner must close on background, lock and account invalidation. */
internal class EditorWebSurface(
    context: Context,
    private val serverUrl: String,
    private val onFailure: (OpenCloudError) -> Unit,
    private val createView: () -> WebView = { WebView(context) },
    private val attachProfile: (WebView) -> (() -> Unit) = { view -> AndroidEditorProfiles.attach(view)::close },
) : EmbeddedSessionSurface<EmbeddedWebAppSession> {
    val container = FrameLayout(context)
    private var webView: WebView? = null
    private var client: EditorWebClient? = null
    private var releaseProfile: (() -> Unit)? = null
    private var started = false
    private var closed = false

    override fun show(session: EmbeddedWebAppSession) {
        check(!started && !closed)
        started = true
        var loaded = false
        try {
            val policy = EmbeddedNavigationPolicy(serverUrl, session.url)
            val view = createView()
            webView = view
            // Profile assignment must be the first API call on the new WebView.
            releaseProfile = attachProfile(view)
            configure(view, policy)
            container.addView(view, FrameLayout.LayoutParams(-1, -1))
            val body = session.postBody()
            if (body == null) view.loadUrl(session.url) else view.postUrl(session.url, body)
            loaded = true
        } finally {
            if (!loaded) close()
        }
    }

    @SuppressLint("SetJavaScriptEnabled") // Office providers require JS; no native bridge is installed.
    private fun configure(view: WebView, policy: EmbeddedNavigationPolicy) {
        view.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            allowFileAccess = false
            allowContentAccess = false
            mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
            cacheMode = WebSettings.LOAD_NO_CACHE
            javaScriptCanOpenWindowsAutomatically = false
            setSupportMultipleWindows(true)
            setGeolocationEnabled(false)
            mediaPlaybackRequiresUserGesture = true
            safeBrowsingEnabled = true
        }
        view.isSaveEnabled = false
        view.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        client = EditorWebClient(policy, ::fail).also { view.webViewClient = it }
        view.webChromeClient = EditorChromeClient()
        view.setDownloadListener { _, _, _, _, _ -> fail(OpenCloudError.Unsupported) }
    }

    private fun fail(error: OpenCloudError) {
        if (!closed) {
            close()
            onFailure(error)
        }
    }

    override fun close() {
        if (closed) return
        closed = true
        client?.close()
        client = null
        val view = webView
        webView = null
        val release = releaseProfile
        releaseProfile = null
        container.removeAllViews()
        try {
            try {
                view?.stopLoading()
                view?.onPause()
                view?.clearHistory()
            } finally {
                view?.destroy()
            }
        } finally {
            release?.invoke()
        }
    }
}
