package eu.opencloud.android.next.core.network

import okhttp3.HttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.w3c.dom.Element
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import javax.xml.parsers.DocumentBuilderFactory

data class RemoteFileVersion(
    val id: String,
    val modifiedAt: Long?,
    val sizeBytes: Long?,
)

/** Server-retained revisions. Never follow metadata links or redirects with account credentials. */
class FileVersionsClient(
    client: OkHttpClient,
    private val policy: EndpointPolicy = EndpointPolicy(),
) {
    private val http =
        client
            .newBuilder()
            .followRedirects(false)
            .followSslRedirects(false)
            .retryOnConnectionFailure(false)
            .build()

    fun list(
        root: String,
        fileId: String,
        authorization: String,
    ): List<RemoteFileVersion> {
        val url = collection(root, fileId)
        val request =
            Request
                .Builder()
                .url(url)
                .header("Authorization", authorization)
                .header("Depth", "1")
                .method("PROPFIND", PROPERTIES.toRequestBody("application/xml".toMediaType()))
                .build()
        return http.newCall(request).execute().use { response ->
            if (response.code != 207) throw TransferHttpException(response.code)
            val source = requireNotNull(response.body).source()
            require(!source.request(2_000_001)) { "Version listing is too large." }
            parseVersions(source.readUtf8(), url)
        }
    }

    @Suppress("LongParameterList") // Explicit source revision, destination precondition, and authorization.
    fun restore(
        root: String,
        fileId: String,
        versionId: String,
        destination: String,
        eTag: String,
        authorization: String,
    ) {
        val source = collection(root, fileId).newBuilder().addPathSegment(validSegment(versionId)).build()
        val target = policy.endpoint(destination, allowQuery = false)
        require(source.scheme == target.scheme && source.host == target.host && source.port == target.port)
        val version = requireNotNull(DownloadExpectation(0, eTag).strongETag)
        require(version.none { it == '[' || it == ']' || it == '\r' || it == '\n' })
        val request =
            Request
                .Builder()
                .url(source)
                .header("Authorization", authorization)
                .header("Destination", target.toString())
                .header("Overwrite", "T")
                // COPY's If-Match applies to the source. The tagged DAV condition protects the destination.
                .header("If", "<$target> ([$version])")
                .method("COPY", byteArrayOf().toRequestBody())
                .build()
        http.newCall(request).execute().use { response ->
            if (response.code !in setOf(201, 204)) throw TransferHttpException(response.code)
        }
    }

    private fun collection(
        root: String,
        fileId: String,
    ): HttpUrl {
        val url = policy.endpoint(root, allowQuery = false)
        val segments = url.pathSegments.filter(String::isNotBlank)
        val index = segments.indexOfLast { it == "spaces" }
        require(index > 0 && index + 1 < segments.size) { "Version history is unavailable for this location." }
        return url
            .newBuilder()
            .encodedPath("/")
            .apply {
                segments.take(index).forEach(::addPathSegment)
                addPathSegment("meta")
                addPathSegment(validSegment(fileId))
                addPathSegment("v")
                addPathSegment("")
            }.build()
    }

    private companion object {
        const val PROPERTIES = """<d:propfind xmlns:d="DAV:"><d:prop>
            <d:getlastmodified/><d:getcontentlength/><d:resourcetype/>
            </d:prop></d:propfind>"""
    }
}

private fun validSegment(value: String): String {
    require(
        value.isNotBlank() && value !in setOf(".", "..") && value.none { it == '/' || it == '\\' || it.isISOControl() },
    )
    return value
}

private fun parseVersions(
    xml: String,
    collection: HttpUrl,
): List<RemoteFileVersion> {
    require(!xml.contains("<!DOCTYPE", true) && !xml.contains("<!ENTITY", true))
    val factory =
        DocumentBuilderFactory.newInstance().apply {
            isNamespaceAware = true
            isExpandEntityReferences = false
        }
    val document = factory.newDocumentBuilder().parse(xml.byteInputStream())
    val responses = document.getElementsByTagNameNS("DAV:", "response")
    require(responses.length <= 10_001)
    return (0 until responses.length)
        .mapNotNull { index ->
            val response = responses.item(index) as Element
            val href = requireNotNull(response.davText("href"))
            val url = requireNotNull(collection.resolve(href))
            requireVersionOrigin(url, collection)
            val base = collection.pathSegments.filter(String::isNotBlank)
            val path = url.pathSegments.filter(String::isNotBlank)
            if (path == base) return@mapNotNull null

            val good = response.successfulVersionProperties()
            val isCollection = good.any { it.getElementsByTagNameNS("DAV:", "collection").length > 0 }
            // OpenCloud returns the metadata parent as its synthetic version-directory entry.
            if (isCollection && path == base.dropLast(1)) return@mapNotNull null
            require(path.size == base.size + 1 && path.take(base.size) == base)
            if (good.isEmpty() || isCollection) {
                return@mapNotNull null
            }
            val date = good.firstNotNullOfOrNull { it.davText("getlastmodified") }
            val size = good.firstNotNullOfOrNull { it.davText("getcontentlength") }?.toLongOrNull()?.takeIf { it >= 0 }
            RemoteFileVersion(
                validSegment(path.last()),
                runCatching {
                    ZonedDateTime.parse(date, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant().toEpochMilli()
                }.getOrNull(),
                size,
            )
        }.also { versions -> require(versions.map { it.id }.distinct().size == versions.size) }
        .sortedByDescending { it.modifiedAt ?: 0 }
}

private fun Element.davText(name: String): String? = getElementsByTagNameNS("DAV:", name).item(0)?.textContent

private fun Element.successfulVersionProperties(): List<Element> {
    val propstats = getElementsByTagNameNS("DAV:", "propstat")
    return (0 until propstats.length)
        .map { propstats.item(it) as Element }
        .filter {
            it
                .davText("status")
                ?.trim()
                ?.split(Regex("\\s+"))
                ?.getOrNull(1) == "200"
        }
}

private fun requireVersionOrigin(
    url: HttpUrl,
    collection: HttpUrl,
) {
    require(url.scheme == collection.scheme && url.host == collection.host && url.port == collection.port)
    require(url.query == null && url.fragment == null && url.username.isEmpty() && url.password.isEmpty())
}
