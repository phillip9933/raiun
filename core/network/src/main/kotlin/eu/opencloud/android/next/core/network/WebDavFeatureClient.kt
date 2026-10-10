package eu.opencloud.android.next.core.network

import android.util.Log
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.w3c.dom.Element
import java.io.ByteArrayInputStream
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.time.ZonedDateTime
import java.util.UUID
import javax.xml.parsers.DocumentBuilderFactory

data class RemoteTrashResource(
    val id: String,
    val spaceId: String,
    val name: String,
    val originalPath: String,
    val folder: Boolean,
    val deletedAtEpochMillis: Long,
    val sizeBytes: Long? = null,
)

class WebDavFeatureClient(
    client: OkHttpClient,
    private val initiatorId: String = CLIENT_INITIATOR_ID,
) {
    private val client =
        client
            .newBuilder()
            .followRedirects(false)
            .followSslRedirects(false)
            .retryOnConnectionFailure(false)
            .build()
            .withMetadataDeadline()

    fun renameFile(
        resourceUrl: String,
        name: String,
        eTag: String?,
        authorization: String,
    ) {
        require(
            name.isNotBlank() &&
                name !in
                setOf(
                    ".",
                    "..",
                ) &&
                name.none { it == '/' || it == '\\' || it.isISOControl() },
        )
        val source = resourceUrl.toHttpUrl()
        val destination = source.newBuilder().setPathSegment(source.pathSegments.lastIndex, name).build()
        execute(
            Request
                .Builder()
                .url(source)
                .openCloudDavHeaders(authorization)
                .header("If-Match", requireVersion(eTag))
                .header("Overwrite", "F")
                .header("Destination", destination.toString())
                .method("MOVE", EMPTY_BODY)
                .build(),
            setOf(201, 204),
        )
    }

    private fun requireVersion(eTag: String?): String =
        DownloadExpectation(0, eTag).strongETag
            ?: throw OpenCloudException(OpenCloudError.PreconditionFailed)

    fun delete(
        resourceUrl: String,
        authorization: String,
        eTag: String? = null,
    ) {
        execute(
            Request
                .Builder()
                .url(resourceUrl)
                .openCloudDavHeaders(authorization)
                .header("If-Match", requireVersion(eTag))
                .delete()
                .build(),
            setOf(200, 204),
        )
    }

    fun trash(
        rootWebDavUrl: String,
        spaceId: String,
        authorization: String,
    ): List<RemoteTrashResource> {
        val url = trashUrl(rootWebDavUrl)
        val xml =
            execute(
                Request
                    .Builder()
                    .url(url)
                    .openCloudDavHeaders(authorization)
                    .header("Depth", "1")
                    .method("PROPFIND", TRASH_PROPFIND_BODY)
                    .build(),
                setOf(207),
            )
        return parseTrash(xml, url, spaceId)
    }

    private fun parseTrash(
        xml: String,
        requestUrl: String,
        spaceId: String,
    ): List<RemoteTrashResource> {
        val document =
            secureDocumentBuilderFactory().newDocumentBuilder().parse(
                ByteArrayInputStream(xml.toByteArray()),
            )
        val responses = document.getElementsByTagNameNS(DAV_NAMESPACE, "response")
        return (0 until responses.length).mapNotNull { index ->
            val response = responses.item(index) as Element
            val href = response.text(DAV_NAMESPACE, "href") ?: return@mapNotNull null
            if (sameCollection(requestUrl, href)) return@mapNotNull null
            val id =
                URLDecoder
                    .decode(
                        href.substringBefore('?').replace("+", "%2B"),
                        StandardCharsets.UTF_8.name(),
                    ).trimEnd('/')
                    .substringAfterLast('/')
            val originalName =
                response.text(TRASH_NAMESPACE, "trashbin-original-filename")?.takeIf(String::isNotBlank)
                    ?: id
            val originalLocation = response.text(TRASH_NAMESPACE, "trashbin-original-location").orEmpty().trim('/')
            RemoteTrashResource(
                id = id,
                spaceId = spaceId,
                name = originalName.substringAfterLast('/'),
                originalPath = "/$originalLocation",
                folder = response.getElementsByTagNameNS(DAV_NAMESPACE, "collection").length > 0,
                deletedAtEpochMillis = response.text(TRASH_NAMESPACE, "trashbin-delete-datetime").toEpochMillis(),
                sizeBytes = response.trashSize(),
            )
        }
    }

    fun restore(
        rootWebDavUrl: String,
        trashId: String,
        destinationUrl: String,
        authorization: String,
    ) {
        execute(
            Request
                .Builder()
                .url(trashItemUrl(rootWebDavUrl, trashId))
                .openCloudDavHeaders(authorization)
                .header("Destination", destinationUrl)
                .header("Overwrite", "F")
                .method("MOVE", EMPTY_BODY)
                .build(),
            setOf(201, 204),
        )
    }

    fun permanentlyDelete(
        rootWebDavUrl: String,
        trashId: String,
        authorization: String,
    ) {
        execute(
            Request
                .Builder()
                .url(trashItemUrl(rootWebDavUrl, trashId))
                .openCloudDavHeaders(authorization)
                .delete()
                .build(),
            setOf(200, 204),
        )
    }

    private fun Request.Builder.openCloudDavHeaders(authorization: String) =
        header("Authorization", authorization)
            .header("Content-Type", DAV_CONTENT_TYPE)
            .header("Initiator-ID", initiatorId)
            .header("X-Requested-With", "XMLHttpRequest")
            .header("X-Request-ID", UUID.randomUUID().toString())

    private fun execute(
        request: Request,
        expected: Set<Int>,
    ): String =
        client.newCall(request).execute().use { response ->
            if (response.code !in expected) {
                runCatching {
                    Log.e("OpenCloudSync", "${request.method} failed with HTTP ${response.code}")
                }
                throw TransferHttpException(response.code)
            }
            response.readBoundedMetadata(LISTING_METADATA_LIMIT_BYTES)
        }

    private companion object {
        const val DAV_NAMESPACE = "DAV:"
        const val TRASH_NAMESPACE = "http://owncloud.org/ns"
        const val DAV_CONTENT_TYPE = "application/xml; charset=utf-8"
        val CLIENT_INITIATOR_ID = UUID.randomUUID().toString()
        val EMPTY_BODY = ByteArray(0).toRequestBody(null)
        val TRASH_PROPFIND_BODY =
            """<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><oc:trashbin-original-filename/><oc:trashbin-original-location/><oc:trashbin-delete-datetime/><d:resourcetype/><d:getcontentlength/><oc:size/></d:prop></d:propfind>"""
                .toRequestBody("application/xml".toMediaType())
    }
}

private fun trashUrl(rootWebDavUrl: String): String {
    val root = rootWebDavUrl.toHttpUrl()
    val segments = root.pathSegments.filter(String::isNotBlank)
    val spacesIndex = segments.indexOfLast { it == "spaces" }
    require(spacesIndex >= 0 && spacesIndex + 1 < segments.size) { "Unsupported space WebDAV URL: $rootWebDavUrl" }
    return root
        .newBuilder()
        .encodedPath("/")
        .apply {
            segments.take(spacesIndex + 1).forEach(::addPathSegment)
            addPathSegment("trash-bin")
            addPathSegment(segments[spacesIndex + 1])
        }.build()
        .toString()
}

private fun trashItemUrl(
    rootWebDavUrl: String,
    trashId: String,
): String =
    trashUrl(rootWebDavUrl)
        .toHttpUrl()
        .newBuilder()
        .addPathSegment(trashId)
        .build()
        .toString()

private fun sameCollection(
    requestUrl: String,
    href: String,
): Boolean {
    val responsePath = runCatching { href.toHttpUrl().encodedPath }.getOrElse { href.substringBefore('?') }
    return requestUrl.toHttpUrl().encodedPath.trimEnd('/') == responsePath.trimEnd('/')
}

private fun Element.text(
    namespace: String,
    localName: String,
): String? = getElementsByTagNameNS(namespace, localName).item(0)?.textContent

private fun Element.trashSize(): Long? {
    val propstats = getElementsByTagNameNS("DAV:", "propstat")
    val properties =
        (0 until propstats.length).map { propstats.item(it) as Element }.filter {
            it
                .text("DAV:", "status")
                ?.trim()
                ?.split(Regex("\\s+"))
                ?.getOrNull(1) == "200"
        }
    val folder = properties.any { it.getElementsByTagNameNS("DAV:", "collection").length > 0 }

    fun size(
        namespace: String,
        property: String,
    ): Long? =
        properties.firstNotNullOfOrNull {
            it
                .text(namespace, property)
                ?.trim()
                ?.toLongOrNull()
                ?.takeIf { bytes -> bytes >= 0 }
        }
    return if (folder) {
        size("http://owncloud.org/ns", "size")
    } else {
        size("DAV:", "getcontentlength") ?: size("http://owncloud.org/ns", "size")
    }
}

private fun String?.toEpochMillis(): Long =
    runCatching { this?.let(ZonedDateTime::parse)?.toInstant()?.toEpochMilli() }.getOrNull() ?: 0

private fun secureDocumentBuilderFactory() =
    DocumentBuilderFactory.newInstance().apply {
        isNamespaceAware = true
        isExpandEntityReferences = false
        runCatching { setAttribute("http://javax.xml.XMLConstants/property/accessExternalDTD", "") }
        runCatching { setAttribute("http://javax.xml.XMLConstants/property/accessExternalSchema", "") }
    }
