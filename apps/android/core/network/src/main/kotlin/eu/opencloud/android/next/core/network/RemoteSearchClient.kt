package eu.opencloud.android.next.core.network

import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.w3c.dom.Element
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

class RemoteSearchClient(
    client: OkHttpClient,
) {
    private val client =
        client
            .newBuilder()
            .followRedirects(false)
            .followSslRedirects(false)
            .build()

    fun search(
        endpointUrl: String,
        query: String,
        authorization: String,
        limit: Int = 50,
    ): List<RemoteSearchResource> {
        require(query.isNotBlank()) { "A search query is required." }
        require(limit in 1..500)
        val request =
            Request
                .Builder()
                .url(endpointUrl)
                .header("Authorization", authorization)
                .method("REPORT", searchBody(query, limit))
                .build()
        val body = execute(request)
        val document = parseSafeXml(body)
        if (document.documentElement.localName != "multistatus" ||
            document.documentElement.namespaceURI != DAV_NAMESPACE
        ) {
            throw OpenCloudException(OpenCloudError.InvalidResponse)
        }
        val responses = document.getElementsByTagNameNS(DAV_NAMESPACE, "response")
        return (0 until responses.length)
            .mapNotNull { index ->
                val response = responses.item(index) as Element
                val href = response.searchText(DAV_NAMESPACE, "href") ?: return@mapNotNull null
                val decodedPath = searchPath(endpointUrl, href)
                val name =
                    response.searchText(OC_NAMESPACE, "name")?.takeIf(String::isNotBlank)
                        ?: decodedPath.substringAfterLast('/')
                val id =
                    response.searchText(OC_NAMESPACE, "fileid")
                        ?: response.searchText(OC_NAMESPACE, "id") ?: return@mapNotNull null
                val spaceAndPath = decodedPath.substringAfter("/spaces/", "")
                val spaceId = spaceAndPath.substringBefore('/').takeIf(String::isNotBlank) ?: return@mapNotNull null
                val path = "/${spaceAndPath.substringAfter('/', "").trimStart('/')}"
                if (response.isEncryptedVault() || isVaultPath(path)) return@mapNotNull null
                RemoteSearchResource(
                    id = id,
                    spaceId = spaceId,
                    path = path,
                    name = name,
                    folder = response.getElementsByTagNameNS(DAV_NAMESPACE, "collection").length > 0,
                    mimeType = response.searchText(DAV_NAMESPACE, "getcontenttype"),
                    size =
                        response.searchText(DAV_NAMESPACE, "getcontentlength")?.toLongOrNull()
                            ?: response.searchText(OC_NAMESPACE, "size")?.toLongOrNull()
                            ?: 0,
                    eTag = response.searchText(DAV_NAMESPACE, "getetag"),
                    modifiedAtEpochMillis = response.searchText(DAV_NAMESPACE, "getlastmodified").searchEpochMillis(),
                )
            }.distinctBy { it.spaceId to it.id }
    }

    private fun execute(request: Request): String =
        client.newCall(request).execute().use { response ->
            if (response.code != 207) {
                throw TransferHttpException(response.code)
            }
            val source = response.body?.source() ?: throw OpenCloudException(OpenCloudError.InvalidResponse)
            if (source.request(32L * 1024 * 1024 + 1)) throw OpenCloudException(OpenCloudError.InvalidResponse)
            source.readUtf8()
        }

    private fun searchBody(
        query: String,
        limit: Int,
    ) =
        """<?xml version="1.0"?><oc:search-files xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:ocrclone="ocrclone"><d:prop><ocrclone:integrity-id/><oc:id/><oc:fileid/><oc:name/><oc:size/><d:getetag/><d:getcontentlength/><d:getcontenttype/><d:getlastmodified/><d:resourcetype/></d:prop><oc:search><oc:pattern>${query.xmlEscape()}</oc:pattern><oc:limit>$limit</oc:limit></oc:search></oc:search-files>"""
            .toRequestBody("application/xml".toMediaType())

    private companion object {
        const val DAV_NAMESPACE = "DAV:"
        const val OC_NAMESPACE = "http://owncloud.org/ns"
    }
}

data class RemoteSearchResource(
    val id: String,
    val spaceId: String,
    val path: String,
    val name: String,
    val folder: Boolean,
    val mimeType: String?,
    val size: Long,
    val eTag: String?,
    val modifiedAtEpochMillis: Long,
)

private fun Element.searchText(
    namespace: String,
    localName: String,
): String? = getElementsByTagNameNS(namespace, localName).item(0)?.textContent

private fun String?.searchEpochMillis(): Long = parseRemoteTimestamp(this)

private fun searchPath(
    endpoint: String,
    href: String,
): String {
    val base = endpoint.toHttpUrl()
    val target = base.resolve(href) ?: throw OpenCloudException(OpenCloudError.InvalidResponse)
    val sameOrigin = base.scheme == target.scheme && base.host == target.host && base.port == target.port
    val credentials = target.username.isNotEmpty() || target.password.isNotEmpty()
    if (!sameOrigin || credentials || target.fragment != null) {
        throw OpenCloudException(OpenCloudError.Trust)
    }
    return URLDecoder.decode(target.encodedPath.replace("+", "%2B"), StandardCharsets.UTF_8.name()).trimEnd('/')
}

private fun String.xmlEscape(): String =
    replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&apos;")
