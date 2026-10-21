package eu.opencloud.android.next.core.network

import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

/** Production requires HTTPS; loopback HTTP is an explicit protocol-test seam. */
class EndpointPolicy(
    private val allowLoopbackHttp: Boolean = false,
) {
    fun endpoint(
        value: String,
        allowQuery: Boolean = true,
    ): HttpUrl {
        val url = value.toHttpUrlOrNull() ?: reject()
        val localTest = allowLoopbackHttp && url.host in setOf("localhost", "127.0.0.1", "::1")
        if (!url.isHttps && !localTest) reject()
        if (url.username.isNotEmpty() || url.password.isNotEmpty()) reject()
        if (url.fragment != null || (!allowQuery && url.query != null)) reject()
        return url
    }

    fun issuer(value: String): String = endpoint(value, allowQuery = false).toString()

    private fun reject(): Nothing = throw OpenCloudException(OpenCloudError.Trust)
}
