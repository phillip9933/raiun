package eu.opencloud.android.next.core.network

import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.w3c.dom.Element
import java.util.concurrent.CancellationException

/** A favorite absence is authoritative only after a complete, validated search response. */
class FavoriteSnapshotClient(
    client: OkHttpClient,
) {
    private val client =
        client
            .newBuilder()
            .followRedirects(false)
            .followSslRedirects(false)
            .build()

    fun snapshot(
        endpoint: String,
        authorization: String,
        roots: Map<String, String>,
    ): Map<String, Set<String>> = locations(endpoint, authorization, roots).mapValues { it.value.keys.toSet() }

    // Preserve typed failures while redacting raw parser/transport details.
    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    fun locations(
        endpoint: String,
        authorization: String,
        roots: Map<String, String>,
    ): Map<String, Map<String, String>> =
        try {
            readSnapshot(endpoint, authorization, roots)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: OpenCloudException) {
            throw failure
        } catch (failure: java.io.IOException) {
            throw OpenCloudException(failure.toOpenCloudError())
        } catch (_: Exception) {
            throw OpenCloudException(OpenCloudError.InvalidResponse)
        }

    private fun readSnapshot(
        endpoint: String,
        authorization: String,
        roots: Map<String, String>,
    ): Map<String, Map<String, String>> {
        val url = endpoint.toHttpUrl()
        val request =
            Request
                .Builder()
                .url(url)
                .header("Authorization", authorization)
                .method("REPORT", BODY)
                .build()
        return client.newCall(request).execute().use { response ->
            if (response.code != 207) throw TransferHttpException(response.code)
            val total =
                response
                    .header(
                        "Content-Range",
                    )?.let {
                        RANGE
                            .matchEntire(it)
                            ?.groupValues
                            ?.get(1)
                            ?.toIntOrNull()
                    }
            val source = requireNotNull(response.body?.source())
            require(!source.request(MAX_BYTES + 1))
            val bytes = source.readByteArray()
            val document = parseSafeXml(bytes.toString(Charsets.UTF_8))
            val envelope = document.documentElement
            require(envelope.namespaceURI == DAV && envelope.localName == "multistatus")
            val responses = envelope.getElementsByTagNameNS(DAV, "response")
            // OpenCloud omits Content-Range for an empty search, but supplies it for nonempty results.
            validateResultCount(response.header("Content-Range"), total, responses.length)
            val result = roots.mapValues { mutableMapOf<String, String>() }
            val seen = mutableSetOf<String>()
            repeat(responses.length) { index ->
                val item = responses.item(index) as Element
                val href = requireNotNull(url.resolve(requireNotNull(item.value(DAV, "href"))))
                require(href.query == null && href.fragment == null && seen.add(href.toString()))
                val owner =
                    roots.entries
                        .single { (_, root) ->
                            val base = root.toHttpUrl()
                            val prefix = favoriteDavSegments(base)
                            href.scheme == base.scheme &&
                                href.host == base.host &&
                                href.port == base.port &&
                                favoriteDavSegments(href).take(prefix.size) == prefix
                        }.key
                val properties = item.getElementsByTagNameNS(DAV, "propstat")
                val ids = mutableSetOf<String>()
                repeat(properties.length) { propertyIndex ->
                    val propstat = properties.item(propertyIndex) as Element
                    val status =
                        propstat
                            .value(DAV, "status")
                            ?.trim()
                            ?.split(Regex("\\s+"))
                            ?.getOrNull(1)
                    if (status == "200") propstat.value(OC, "fileid")?.takeIf(String::isNotBlank)?.let(ids::add)
                }
                val path = relativeFavoritePath(requireNotNull(roots[owner]), href)
                require(ids.size == 1 && requireNotNull(result[owner]).put(ids.single(), path) == null)
            }
            result
        }
    }

    private fun validateResultCount(
        header: String?,
        total: Int?,
        count: Int,
    ) {
        val emptyResponse = header == null && count == 0
        require(emptyResponse || (total != null && total in 0..MAX_ITEMS && count == total))
    }

    private companion object {
        const val DAV = "DAV:"
        const val OC = "http://owncloud.org/ns"
        const val MAX_ITEMS = 100_000
        const val MAX_BYTES = 32L * 1024 * 1024
        val RANGE = Regex("(?:[A-Za-z]+ )?(?:[0-9]+-[0-9]+|\\*)/([0-9]+)")
        val BODY =
            """<oc:search-files xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><oc:fileid/></d:prop><oc:search><oc:pattern>is:favorite</oc:pattern><oc:limit>100001</oc:limit></oc:search></oc:search-files>"""
                .toRequestBody("application/xml".toMediaType())
    }
}

private fun relativeFavoritePath(
    root: String,
    href: okhttp3.HttpUrl,
): String {
    val prefix = favoriteDavSegments(root.toHttpUrl())
    val segments = favoriteDavSegments(href).drop(prefix.size)
    require(
        segments.all {
            it.isNotEmpty() &&
                it !in setOf(".", "..") &&
                it.none { char -> char == '/' || char == '\\' || char.isISOControl() }
        },
    )
    return "/${segments.joinToString("/")}"
}

/** OpenCloud search mirrors the request's /remote.php prefix; Graph roots can use /dav directly. */
private fun favoriteDavSegments(url: okhttp3.HttpUrl): List<String> {
    val segments = url.pathSegments.dropLastWhile(String::isEmpty)
    return if (segments.take(3) == listOf("remote.php", "dav", "spaces")) segments.drop(1) else segments
}

private fun Element.value(
    namespace: String,
    name: String,
): String? = getElementsByTagNameNS(namespace, name).item(0)?.textContent
