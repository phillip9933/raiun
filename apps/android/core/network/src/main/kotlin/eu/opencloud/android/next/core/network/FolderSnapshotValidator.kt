package eu.opencloud.android.next.core.network

import okhttp3.HttpUrl.Companion.toHttpUrl
import org.w3c.dom.Element

/** A failed resource response is not evidence that the resource was deleted. */
internal class FolderSnapshotValidator(
    requestUrl: String,
    private val registerPath: ((String) -> Boolean)? = null,
) {
    private val requested = requestUrl.toHttpUrl()
    private val parentSegments = requested.pathSegments.dropLastWhile { it.isEmpty() }
    private val seen = mutableSetOf<String>()
    private var foundCollection = false

    fun accept(response: Element): Boolean {
        val href = response.getElementsByTagNameNS(DAV, "href").item(0)?.textContent ?: invalidSnapshot()
        val url = requested.resolve(href) ?: invalidSnapshot()
        requireSameOrigin(url, requested)
        val segments = url.pathSegments.dropLastWhile { it.isEmpty() }
        if (segments != parentSegments && segments.dropLast(1) != parentSegments) invalidSnapshot()
        val canonicalPath = segments.joinToString("/")
        if (registerPath?.invoke(canonicalPath) == false ||
            (registerPath == null && !seen.add(canonicalPath))
        ) {
            invalidSnapshot()
        }
        keepSuccessfulProperties(response)
        val collection = segments == parentSegments
        if (collection) {
            if (response.getElementsByTagNameNS(DAV, "collection").length == 0) invalidSnapshot()
            foundCollection = true
        }
        return collection
    }

    fun finish() {
        if (!foundCollection) invalidSnapshot()
    }
}

private fun requireSameOrigin(
    url: okhttp3.HttpUrl,
    requested: okhttp3.HttpUrl,
) {
    if (url.scheme != requested.scheme || url.host != requested.host || url.port != requested.port) invalidSnapshot()
}

private fun keepSuccessfulProperties(response: Element) {
    val propstats = response.getElementsByTagNameNS(DAV, "propstat")
    var successful = false
    for (index in propstats.length - 1 downTo 0) {
        val propstat = propstats.item(index) as Element
        val status = propstat.getElementsByTagNameNS(DAV, "status").item(0)?.textContent
        val code =
            status
                ?.trim()
                ?.split(Regex("\\s+"))
                ?.getOrNull(1)
                ?.toIntOrNull()
        if (code == 200) {
            successful = true
        } else {
            propstat.parentNode.removeChild(propstat)
        }
    }
    if (!successful) invalidSnapshot()
}

private fun invalidSnapshot(): Nothing = throw OpenCloudException(OpenCloudError.InvalidResponse)

private const val DAV = "DAV:"
