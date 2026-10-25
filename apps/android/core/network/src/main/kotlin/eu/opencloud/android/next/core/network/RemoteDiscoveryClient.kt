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

    private val metadataClient =
        client
            .withMetadataDeadline()
            .newBuilder()
            .followRedirects(false)
            .followSslRedirects(false)
            .build()
    private val streamingClient =
        client
            .newBuilder()
            .callTimeout(
                minOf(client.callTimeoutMillis.takeIf { it > 0 } ?: 300_000, 300_000).toLong(),
                java.util.concurrent.TimeUnit.MILLISECONDS,
            ).followRedirects(false)
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
    ): RemoteFolderSnapshot = readFolder(rootWebDavUrl, path, authorization)

    /** Sink callbacks are provisional until this method returns after complete root and XML validation. */
    fun streamFolder(
        rootWebDavUrl: String,
        path: String,
        authorization: String,
        sink: RemoteFolderSink,
    ) {
        readFolder(rootWebDavUrl, path, authorization, FolderReadOptions(sink = sink))
    }

    /** Shared listings must publish encrypted requested-collection evidence for atomic cache revocation. */
    fun sharedFolderSnapshot(
        rootWebDavUrl: String,
        path: String,
        authorization: String,
    ): RemoteFolderSnapshot =
        try {
            readFolder(rootWebDavUrl, path, authorization, FolderReadOptions(reportEncryptedCollection = true))
        } catch (failure: OpenCloudException) {
            if (failure.error != OpenCloudError.InvalidResponse) throw failure
            throw SharedMetadataException(SharedMetadataStage.DAV_LISTING)
        }

    internal fun requireCollection(
        url: String,
        authorization: String,
    ) {
        if (readFolder(url, "", authorization, FolderReadOptions(depth = "0")).resources.isNotEmpty()) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
    }

    /** A discovery address may be stale after a rename or replacement; verify its current identity. */
    internal fun requireCollectionIdentity(
        url: String,
        authorization: String,
        expectedId: String,
    ) {
        readFolder(url, "", authorization, FolderReadOptions(depth = "0", expectedCollectionId = expectedId))
    }

    // Explicit read constraints; fail closed and preserve cancellation.
    @Suppress("TooGenericExceptionCaught", "ThrowsCount")
    private fun readFolder(
        rootWebDavUrl: String,
        path: String,
        authorization: String,
        options: FolderReadOptions = FolderReadOptions(),
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
                .header("Depth", options.depth)
                .method("PROPFIND", PROPFIND_BODY)
                .build()
        val state = FolderReadState(url, path, options)
        (if (options.sink == null) metadataClient else streamingClient).newCall(request).execute().use { response ->
            if (!response.isSuccessful) throw TransferHttpException(response.code)
            val body = response.body ?: throw OpenCloudException(OpenCloudError.InvalidResponse)
            try {
                readDavResponses(
                    body.byteStream(),
                    if (options.sink == null) maxResponseBytes else STREAMING_RESPONSE_LIMIT_BYTES,
                    state::consume,
                )
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
        state.finish()
        if (state.encryptedCollection) {
            if (!options.reportEncryptedCollection) throw OpenCloudException(OpenCloudError.Unsupported)
            return RemoteFolderSnapshot(emptyList(), setOf(path))
        }
        return RemoteFolderSnapshot(state.resources, state.excluded.toSet(), state.plainCollectionConfirmed)
    }

    private data class FolderReadOptions(
        val depth: String = "1",
        val reportEncryptedCollection: Boolean = false,
        val expectedCollectionId: String? = null,
        val sink: RemoteFolderSink? = null,
    )

    private inner class FolderReadState(
        url: String,
        private val path: String,
        private val options: FolderReadOptions,
    ) {
        private val validator = FolderSnapshotValidator(url, options.sink?.registerCanonicalPath)
        private val identities = if (options.sink == null) mutableSetOf<Pair<String, String>>() else null
        val excluded = mutableSetOf<String>()
        val resources = mutableListOf<RemoteResource>()
        var encryptedCollection = false
            private set
        var plainCollectionConfirmed = false
            private set

        fun consume(element: Element) {
            if (validator.accept(element)) {
                element.requireIdentity(options.expectedCollectionId)
                (element.text(OC_NAMESPACE, "fileid") ?: element.text(OC_NAMESPACE, "id"))?.let(::registerCollectionId)
                encryptedCollection = element.isEncryptedVault()
                plainCollectionConfirmed = options.reportEncryptedCollection && element.confirmsPlainCollection()
                return
            }
            val href = element.text(DAV_NAMESPACE, "href") ?: throw OpenCloudException(OpenCloudError.InvalidResponse)
            element.resource(path, href, excluded, identities, options.sink?.onEntry)?.let(resources::add)
        }

        fun finish() = validator.finish()

        private fun registerCollectionId(id: String) {
            val accepted =
                id.isNotBlank() &&
                    (identities?.add("id" to id) ?: true) &&
                    (options.sink?.registerCollectionId?.invoke(id) ?: true)
            if (!accepted) throw OpenCloudException(OpenCloudError.InvalidResponse)
        }
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
        identities: MutableSet<Pair<String, String>>?,
        onEntry: ((RemoteFolderEntry) -> Unit)?,
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
        requireResourceIdentity(id, relativePath, identities)
        if (response.excludesVaultPath(relativePath)) {
            if (onEntry == null) excluded.add(relativePath)
            onEntry?.invoke(RemoteFolderEntry(id, relativePath, null))
            return null
        }
        val resource =
            RemoteResource(
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
        onEntry?.invoke(RemoteFolderEntry(id, relativePath, resource))
        return if (onEntry == null) resource else null
    }

    private fun Element.resourceSize(): Long =
        text(DAV_NAMESPACE, "getcontentlength")?.toLongOrNull()
            ?: text(OC_NAMESPACE, "size")?.toLongOrNull()
            ?: 0

    private fun requireResourceIdentity(
        id: String,
        path: String,
        identities: MutableSet<Pair<String, String>>?,
    ) {
        val valid =
            id.isNotBlank() &&
                (identities?.add("path" to path) ?: true) &&
                (identities?.add("id" to id) ?: true)
        if (!valid) throw OpenCloudException(OpenCloudError.InvalidResponse)
    }

    private companion object {
        const val STREAMING_RESPONSE_LIMIT_BYTES = 256L * 1024 * 1024
        const val DAV_NAMESPACE = "DAV:"
        const val OC_NAMESPACE = "http://owncloud.org/ns"
        val PROPFIND_BODY =
            """<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:ocrclone="ocrclone"><d:prop><ocrclone:integrity-id/><oc:fileid/><oc:id/><oc:name/><oc:size/><oc:favorite/><d:getetag/><d:getcontentlength/><d:getcontenttype/><d:getlastmodified/><d:creationdate/><d:resourcetype/></d:prop></d:propfind>"""
                .toRequestBody(
                    "application/xml".toMediaType(),
                )
    }
}

/** A null resource marks a vault path that must be excluded from the ordinary cache. */
data class RemoteFolderEntry(
    val id: String,
    val path: String,
    val resource: RemoteResource?,
)

/** Callbacks are provisional until [RemoteDiscoveryClient.streamFolder] returns successfully. */
data class RemoteFolderSink(
    val registerCanonicalPath: (String) -> Boolean,
    val registerCollectionId: (String) -> Boolean,
    val onEntry: (RemoteFolderEntry) -> Unit,
)

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
