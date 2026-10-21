package eu.opencloud.android.next.core.network

import okhttp3.HttpUrl.Companion.toHttpUrl
import org.w3c.dom.Element

internal fun parseDavObject(
    xml: String,
    url: String,
    strictChecksumStatus: Boolean = false,
): DavObject {
    val document = parseSafeXml(xml)
    val root = document.documentElement
    if (root.namespaceURI != DAV || root.localName != "multistatus") invalidProperties()
    val entries = root.getElementsByTagNameNS(DAV, "response")
    if (entries.length != 1) invalidProperties()
    val entry = entries.item(0) as Element
    validateHref(entry, url)
    if (strictChecksumStatus) rejectChecksumPropertyErrors(entry)
    val prop = resourceProperties(entry)
    val folder = prop.getElementsByTagNameNS(DAV, "collection").length > 0
    val length = if (folder) 0 else prop.text("getcontentlength")?.toLongOrNull() ?: invalidProperties()
    if (length < 0) invalidProperties()
    return DavObject(folder, length, prop.text("getetag"), parseDavChecksums(prop))
}

/** A denied or failed checksum property is an error, not evidence that checksums are absent. */
private fun rejectChecksumPropertyErrors(entry: Element) {
    val stats = entry.getElementsByTagNameNS(DAV, "propstat")
    for (index in 0 until stats.length) {
        val stat = stats.item(index) as Element
        val prop = stat.getElementsByTagNameNS(DAV, "prop").item(0) as? Element ?: invalidProperties()
        if (prop.getElementsByTagNameNS(OC, "checksums").length == 0) continue
        val status =
            stat
                .text("status")
                ?.trim()
                ?.split(Regex("\\s+"))
                ?.getOrNull(1)
                ?.toIntOrNull()
                ?: invalidProperties()
        if (status !in setOf(200, 404, 405, 501)) throw TransferHttpException(status)
    }
}

private fun parseDavChecksums(prop: Element): Map<String, String> {
    val values = prop.getElementsByTagNameNS("http://owncloud.org/ns", "checksum")
    val result = mutableMapOf<String, String>()
    for (index in 0 until values.length) {
        values.item(index).textContent.trim().split(Regex("\\s+")).forEach { token ->
            val name = token.substringBefore(':').uppercase()
            val algorithm =
                when (name) {
                    "SHA256", "SHA-256" -> "SHA-256"
                    "SHA1", "SHA-1" -> "SHA-1"
                    "MD5" -> "MD5"
                    else -> return@forEach
                }
            val length =
                when (algorithm) {
                    "SHA-256" -> 64
                    "SHA-1" -> 40
                    else -> 32
                }
            val value = token.substringAfter(':', "").lowercase()
            if (value.length != length || value.any { it !in "0123456789abcdef" }) invalidProperties()
            val previous = result.put(algorithm, value)
            if (previous != null && previous != value) invalidProperties()
        }
    }
    return result
}

private fun validateHref(
    entry: Element,
    url: String,
) {
    val requested = url.toHttpUrl()
    val actual = requested.resolve(entry.text("href") ?: invalidProperties()) ?: invalidProperties()
    val originMatches =
        requested.scheme == actual.scheme && requested.host == actual.host && requested.port == actual.port
    // Compare decoded segments, preserving encoded slashes as part of their segment.
    val pathMatches =
        requested.pathSegments.dropLastWhile(String::isEmpty) == actual.pathSegments.dropLastWhile(String::isEmpty)
    val hasSuffix = actual.query != null || actual.fragment != null
    if (!originMatches || !pathMatches || hasSuffix) {
        invalidProperties()
    }
}

private fun resourceProperties(entry: Element): Element {
    val merged = entry.ownerDocument.createElementNS(DAV, "prop")
    val seen = mutableSetOf<Pair<String?, String?>>()
    val stats = entry.getElementsByTagNameNS(DAV, "propstat")
    for (index in 0 until stats.length) {
        val stat = stats.item(index) as Element
        if (stat
                .text("status")
                ?.trim()
                ?.split(Regex("\\s+"))
                ?.getOrNull(1) != "200"
        ) {
            continue
        }
        val prop = stat.getElementsByTagNameNS(DAV, "prop").item(0) as? Element ?: invalidProperties()
        for (childIndex in 0 until prop.childNodes.length) {
            val child = prop.childNodes.item(childIndex) as? Element ?: continue
            if (!seen.add(child.namespaceURI to child.localName)) invalidProperties()
            merged.appendChild(child.cloneNode(true))
        }
    }
    if (merged.getElementsByTagNameNS(DAV, "resourcetype").length != 1) invalidProperties()
    return merged
}

private fun Element.text(name: String): String? = getElementsByTagNameNS(DAV, name).item(0)?.textContent

private fun invalidProperties(): Nothing = throw OpenCloudException(OpenCloudError.InvalidResponse)

private const val DAV = "DAV:"
private const val OC = "http://owncloud.org/ns"
