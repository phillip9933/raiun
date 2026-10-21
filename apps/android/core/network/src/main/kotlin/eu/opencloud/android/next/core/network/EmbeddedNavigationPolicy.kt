package eu.opencloud.android.next.core.network

import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

/** Policy for the future embedded host. No implicit intent launches or arbitrary top-level redirects. */
class EmbeddedNavigationPolicy(
    serverUrl: String,
    editorUrl: String,
) {
    private val server = trusted(serverUrl)
    private val editor = trusted(editorUrl)

    fun allowsNavigation(value: String): Boolean = parse(value)?.let { sameOrigin(editor, it) } == true

    fun allowsResource(value: String): Boolean {
        // Blob resources belong to the editor origin; never allow them as top-level navigation.
        val blob = value.startsWith("blob:")
        val url = parse(if (blob) value.removePrefix("blob:") else value) ?: return false
        return sameOrigin(editor, url) || (!blob && sameOrigin(server, url))
    }

    private fun trusted(value: String): HttpUrl = parse(value) ?: throw OpenCloudException(OpenCloudError.Trust)

    private fun parse(value: String): HttpUrl? {
        if (value.length > 16_384 || value.any { it.isISOControl() }) return null
        return value.toHttpUrlOrNull()?.takeIf { it.isHttps && it.username.isEmpty() && it.password.isEmpty() }
    }

    private fun sameOrigin(
        first: HttpUrl,
        second: HttpUrl,
    ): Boolean = first.scheme == second.scheme && first.host == second.host && first.port == second.port

    override fun toString(): String = "EmbeddedNavigationPolicy(redacted)"
}
