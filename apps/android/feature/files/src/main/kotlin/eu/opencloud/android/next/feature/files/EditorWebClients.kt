package eu.opencloud.android.next.feature.files

import android.graphics.Bitmap
import android.net.Uri
import android.net.http.SslError
import android.os.Message
import android.webkit.ClientCertRequest
import android.webkit.ConsoleMessage
import android.webkit.GeolocationPermissions
import android.webkit.HttpAuthHandler
import android.webkit.PermissionRequest
import android.webkit.RenderProcessGoneDetail
import android.webkit.SslErrorHandler
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import eu.opencloud.android.next.core.network.EmbeddedNavigationPolicy
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.httpError
import java.io.ByteArrayInputStream
import java.util.concurrent.atomic.AtomicBoolean

/** Callback filtering is defense in depth, not a network firewall: WebView omits some redirect/resource callbacks. */
internal class EditorWebClient(
    private val policy: EmbeddedNavigationPolicy,
    private val onFailure: (OpenCloudError) -> Unit,
) : WebViewClient() {
    private val closed = AtomicBoolean(false)

    fun close() {
        closed.set(true)
    }

    override fun shouldOverrideUrlLoading(
        view: WebView?,
        request: WebResourceRequest,
    ): Boolean = closed.get() || !allows(request)

    override fun shouldInterceptRequest(
        view: WebView?,
        request: WebResourceRequest,
    ): WebResourceResponse? =
        if (closed.get() || !allows(request)) {
            WebResourceResponse("text/plain", "UTF-8", 403, "Blocked", emptyMap(), ByteArrayInputStream(byteArrayOf()))
        } else {
            null
        }

    override fun onPageStarted(
        view: WebView?,
        url: String?,
        favicon: Bitmap?,
    ) {
        if (closed.get() || url == null || !policy.allowsNavigation(url)) {
            view?.stopLoading()
            fail(OpenCloudError.Trust)
        }
    }

    override fun onReceivedSslError(
        view: WebView?,
        handler: SslErrorHandler,
        error: SslError?,
    ) {
        handler.cancel()
        fail(OpenCloudError.Trust)
    }

    override fun onReceivedHttpAuthRequest(
        view: WebView?,
        handler: HttpAuthHandler,
        host: String?,
        realm: String?,
    ) {
        handler.cancel()
        fail(OpenCloudError.Unsupported)
    }

    override fun onReceivedClientCertRequest(
        view: WebView?,
        request: ClientCertRequest,
    ) {
        request.cancel()
        fail(OpenCloudError.Unsupported)
    }

    override fun onRenderProcessGone(
        view: WebView?,
        detail: RenderProcessGoneDetail?,
    ): Boolean {
        fail(OpenCloudError.Unknown)
        return true
    }

    override fun onReceivedError(
        view: WebView?,
        request: WebResourceRequest,
        error: WebResourceError,
    ) {
        if (request.isForMainFrame) {
            fail(if (error.errorCode == ERROR_TIMEOUT) OpenCloudError.Timeout else OpenCloudError.Connectivity)
        }
    }

    override fun onReceivedHttpError(
        view: WebView?,
        request: WebResourceRequest,
        response: WebResourceResponse,
    ) {
        if (request.isForMainFrame) fail(httpError(response.statusCode))
    }

    private fun allows(request: WebResourceRequest): Boolean =
        if (request.isForMainFrame) {
            policy.allowsNavigation(request.url.toString())
        } else {
            policy.allowsResource(request.url.toString())
        }

    private fun fail(error: OpenCloudError) {
        if (closed.compareAndSet(false, true)) onFailure(error)
    }
}

/** No native file grants, credential dialogs, new windows, device permissions or console/token logging. */
internal class EditorChromeClient : WebChromeClient() {
    override fun onPermissionRequest(request: PermissionRequest) = request.deny()

    override fun onGeolocationPermissionsShowPrompt(
        origin: String?,
        callback: GeolocationPermissions.Callback,
    ) {
        callback.invoke(origin, false, false)
    }

    override fun onShowFileChooser(
        webView: WebView?,
        filePathCallback: ValueCallback<Array<Uri>>?,
        fileChooserParams: FileChooserParams?,
    ): Boolean = false

    override fun onCreateWindow(
        view: WebView?,
        isDialog: Boolean,
        isUserGesture: Boolean,
        resultMsg: Message?,
    ): Boolean = false

    override fun onConsoleMessage(consoleMessage: ConsoleMessage?): Boolean = true
}
