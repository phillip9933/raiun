package eu.opencloud.android.next.core.network

import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.w3c.dom.Element
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

class RemoteDiscoveryClient(
    client: OkHttpClient,
    private val maxResponseBytes: Long = 32L * 1024 * 1024,
) {
    init {
        require(maxResponseBytes in 1..32L * 1024 * 1024)
    }

    private val client =
        client
            .withMetadataDeadline()
            .newBuilder()
            .followRedirects(false)
            .followSslRedirects(false)
            .build()

    fun folder(
        rootWebDavUrl: String,
        path: String,
        authorization: String,
    ): List<RemoteResource> = folderSnapshot(rootWebDavUrl, path, authorization).resources

    fun folderSnapshot(
        rootWebDavUrl: String,
        path: String,
        authorization: String,
    ): RemoteFolderSnapshot = readFolder(rootWebDavUrl, path, authorization, "1")

    /** Shared listings must publish encrypted requested-collection evidence for atomic cache revocation. */
    fun sharedFolderSnapshot(
        rootWebDavUrl: String,
        path: String,
        authorization: String,
    ): RemoteFolderSnapshot =
        try {
            readFolder(rootWebDavUrl, path, authorization, "1", reportEncryptedCollection = true)
        } catch (failure: OpenCloudException) {
            if (failure.error != OpenCloudError.InvalidResponse) throw failure
            throw SharedMetadataException(SharedMetadataStage.DAV_LISTING)
        }

    internal fun requireCollection(
        url: String,
        authorization: String,
    ) {
        if (readFolder(url, "", authorization, "0").resources.isNotEmpty()) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
    }

    /** A discovery address may be stale after a rename or replacement; verify its current identity. */
    internal fun requireCollectionIdentity(
        url: String,
        authorization: String,
        expectedId: String,
    ) {
        readFolder(url, "", authorization, "0", expectedCollectionId = expectedId)
    }

    // Explicit read constraints; fail closed and preserve cancellation.
    @Suppress("TooGenericExceptionCaught", "ThrowsCount", "LongParameterList")
    private fun readFolder(
        rootWebDavUrl: String,
        path: String,
        authorization: String,
        depth: String,
        reportEncryptedCollection: Boolean = false,
        expectedCollectionId: String? = null,
    ): RemoteFolderSnapshot {
        val url = rootWebDavUrl.childUrl(path)
        if (isVaultPath(url.toHttpUrl().pathSegments.joinToString("/"))) {
            throw OpenCloudException(OpenCloudError.Unsupported)
        }
        val request =
            Request
                .Builder()
                .url(
                    url,
                ).header("Authorization", authorization)
                .header("Depth", depth)
                .method("PROPFIND", PROPFIND_BODY)
                .build()
        val validator = FolderSnapshotValidator(url)
        val excluded = mutableSetOf<String>()
        val identities = mutableSetOf<Pair<String, String>>()
        val resources = mutableListOf<RemoteResource>()
        var encryptedCollection = false
        var plainCollectionConfirmed = false
        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) throw TransferHttpException(response.code)
            val body = response.body ?: throw OpenCloudException(OpenCloudError.InvalidResponse)
            try {
                readDavResponses(body.byteStream(), maxResponseBytes) { element ->
                    if (validator.accept(element)) {
                        element.requireIdentity(expectedCollectionId)
                        encryptedCollection = element.isEncryptedVault()
                        plainCollectionConfirmed = reportEncryptedCollection && element.confirmsPlainCollection()
                    } else {
                        val href =
                            element.text(DAV_NAMESPACE, "href")
                                ?: throw OpenCloudException(OpenCloudError.InvalidResponse)
                        element.resource(path, href, excluded, identities)?.let(resources::add)
                    }
                }
            } catch (cancelled: java.util.concurrent.CancellationException) {
                throw cancelled
            } catch (failure: OpenCloudException) {
                throw failure
            } catch (failure: java.io.IOException) {
                throw failure
            } catch (_: Exception) {
                throw OpenCloudException(OpenCloudError.InvalidResponse)
            }
        }
        validator.finish()
        if (encryptedCollection) {
            if (!reportEncryptedCollection) throw OpenCloudException(OpenCloudError.Unsupported)
            return RemoteFolderSnapshot(emptyList(), setOf(path))
        }
        return RemoteFolderSnapshot(resources, excluded.toSet(), plainCollectionConfirmed)
    }

    private fun Element.requireIdentity(expectedId: String?) {
        if (expectedId == null) return
        val actualId = text(OC_NAMESPACE, "fileid") ?: text(OC_NAMESPACE, "id")
        if (actualId != expectedId) throw SharedMetadataException(SharedMetadataStage.ITEM_IDENTITY)
    }

    private fun Element.resource(
        path: String,
        href: String,
        excluded: MutableSet<String>,
        identities: MutableSet<Pair<String, String>>,
    ): RemoteResource? {
        val response = this
        val decodedPath =
            URLDecoder
                .decode(href.substringBefore('?').replace("+", "%2B"), StandardCharsets.UTF_8.name())
                .trimEnd('/')
        val name =
            response.text(OC_NAMESPACE, "name")?.takeIf(String::isNotBlank) ?: decodedPath.substringAfterLast('/')
        requireRemoteName(name)
        val relativePath = "${path.trimEnd('/')}/$name".let { if (it.startsWith('/')) it else "/$it" }
        val id = response.text(OC_NAMESPACE, "fileid") ?: response.text(OC_NAMESPACE, "id") ?: href
        if (id.isBlank() || !identities.add("path" to relativePath) || !identities.add("id" to id)) {
            throw OpenCloudException(OpenCloudError.InvalidResponse)
        }
        if (response.excludesVaultPath(relativePath)) {
            excluded.add(relativePath)
            return null
        }
        return RemoteResource(
            id = id,
            path = relativePath,
            name = name,
            folder = response.getElementsByTagNameNS(DAV_NAMESPACE, "collection").length > 0,
            mimeType = response.text(DAV_NAMESPACE, "getcontenttype"),
            size = response.resourceSize(),
            eTag = response.text(DAV_NAMESPACE, "getetag"),
            modifiedAtEpochMillis = response.text(DAV_NAMESPACE, "getlastmodified").toEpochMillis(),
            createdAtEpochMillis = response.text(DAV_NAMESPACE, "creationdate").toEpochMillis(),
            favorite =
                response.text(OC_NAMESPACE, "favorite") == "1" || response.text(OC_NAMESPACE, "favorite") == "true",
        )
    }

    private fun Element.resourceSize(): Long =
        text(DAV_NAMESPACE, "getcontentlength")?.toLongOrNull()
            ?: text(OC_NAMESPACE, "size")?.toLongOrNull()
            ?: 0

    private companion object {
        const val DAV_NAMESPACE = "DAV:"
        const val OC_NAMESPACE = "http://owncloud.org/ns"
        val PROPFIND_BODY =
            """<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:ocrclone="ocrclone"><d:prop><ocrclone:integrity-id/><oc:fileid/><oc:id/><oc:name/><oc:size/><oc:favorite/><d:getetag/><d:getcontentlength/><d:getcontenttype/><d:getlastmodified/><d:creationdate/><d:resourcetype/></d:prop></d:propfind>"""
                .toRequestBody(
                    "application/xml".toMediaType(),
                )
    }
}

private fun requireSnapshotName(name: String) {
    require(name !in setOf(".", "..") && name.none { it == '/' || it == '\\' || it.isISOControl() })
}

/** Published only after the complete validated response; exclusions are not ordinary missing entries. */
data class RemoteFolderSnapshot(
    val resources: List<RemoteResource>,
    val excludedVaultPaths: Set<String>,
    val plainCollectionConfirmed: Boolean = false,
)

data class RemoteResource(
    val id: String,
    val path: String,
    val name: String,
    val folder: Boolean,
    val mimeType: String?,
    val size: Long,
    val eTag: String?,
    val modifiedAtEpochMillis: Long,
    val createdAtEpochMillis: Long,
    val favorite: Boolean = false,
)

private fun Element.text(
    namespace: String,
    localName: String,
): String? = getElementsByTagNameNS(namespace, localName).item(0)?.textContent

private fun String?.toEpochMillis(): Long = parseRemoteTimestamp(this)

private fun String.childUrl(path: String): String =
    toHttpUrl()
        .newBuilder()
        .apply {
            path
                .trim('/')
                .split('/')
                .filter(String::isNotBlank)
                .forEach(::addPathSegment)
        }.build()
        .toString()

private fun requireRemoteName(name: String) {
    try {
        requireSnapshotName(name)
    } catch (_: IllegalArgumentException) {
        throw OpenCloudException(OpenCloudError.InvalidResponse)
    }
}
