package eu.opencloud.android.next.core.network

import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okio.BufferedSink
import org.w3c.dom.Element
import java.io.ByteArrayOutputStream
import java.io.FilterInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

/** Scoped DAV transport; every read/write shares root, href and conditional-request validation. */
@Suppress("LargeClass")
class VaultDavClient(
    client: OkHttpClient,
    private val maxXmlBytes: Long = DEFAULT_MAX_XML_BYTES,
    private val maxCiphertextBytes: Int = DEFAULT_MAX_CIPHERTEXT_BYTES,
    private val endpoints: EndpointPolicy = EndpointPolicy(),
) {
    private val client =
        client
            .newBuilder()
            .followRedirects(false)
            .followSslRedirects(false)
            .retryOnConnectionFailure(false)
            .build()

    init {
        require(maxXmlBytes in 1..DEFAULT_MAX_XML_BYTES)
        require(maxCiphertextBytes in 1..DEFAULT_MAX_CIPHERTEXT_BYTES)
    }

    /**
     * Lists a vault root or encrypted relative directory. [recognizedVaultRoot] is only for a
     * root already identified by authenticated Graph metadata. The caller must bind the supplied
     * root origin to its account; this client constrains descendants to that supplied scope.
     */
    fun list(
        rootWebDavUrl: String,
        path: String = "",
        authorization: String,
        recognizedVaultRoot: Boolean = false,
    ): VaultDavListing =
        listInternal(
            rootWebDavUrl,
            path,
            authorization,
            allowOrdinaryDirectory = false,
            recognizedVaultRoot = recognizedVaultRoot,
        )

    /** Lists a plain parent only to discover immediate `.vault` folders; ordinary children are omitted. */
    fun discoverFolderVaults(
        parentWebDavUrl: String,
        path: String = "",
        authorization: String,
    ): List<VaultDavEntry> =
        listInternal(parentWebDavUrl, path, authorization, allowOrdinaryDirectory = true, recognizedVaultRoot = false)
            .children
            .filter(::isFolderVaultEntry)

    /** Lists only immediate directories under an ordinary collection for explicit vault discovery. */
    fun discoverDirectories(
        parentWebDavUrl: String,
        path: String = "",
        authorization: String,
    ): List<VaultDavEntry> =
        listInternal(parentWebDavUrl, path, authorization, allowOrdinaryDirectory = true, recognizedVaultRoot = false)
            .children
            .filter(VaultDavEntry::isFolder)

    /** Inspects one ordinary directory without treating it as a vault root. */
    fun inspectOrdinaryDirectory(
        parentWebDavUrl: String,
        path: String = "",
        authorization: String,
    ): VaultDavListing =
        listInternal(parentWebDavUrl, path, authorization, allowOrdinaryDirectory = true, recognizedVaultRoot = false)

    /** Creates a collection at a validated path below the advertised WebDAV root. */
    fun createCollection(
        rootWebDavUrl: String,
        path: String,
        authorization: String,
    ) {
        val request = mutationRequest(rootWebDavUrl, path, authorization).method("MKCOL", null).build()
        executeMutation(request, setOf(200, 201, 204))
    }

    /** Deletes one already-identified resource; a strong ETag is mandatory. */
    fun deleteResource(
        rootWebDavUrl: String,
        path: String,
        authorization: String,
        strongETag: String,
    ) {
        val etag = requireStrongETag(strongETag)
        val request = mutationRequest(rootWebDavUrl, path, authorization).header("If-Match", etag).delete().build()
        executeMutation(request, setOf(200, 202, 204))
    }

    /**
     * Moves/copies only between paths inside this same advertised DAV root.
     * Explicit wire arguments keep origin, paths, identity, and authorization visible at callsites.
     */
    @Suppress("LongParameterList")
    fun moveOrCopy(
        rootWebDavUrl: String,
        sourcePath: String,
        destinationPath: String,
        authorization: String,
        strongETag: String,
        copy: Boolean,
    ) {
        val etag = requireStrongETag(strongETag)
        val root = validateRootUrl(rootWebDavUrl)
        val source = requireMutationTarget(root, sourcePath)
        val destination = requireMutationTarget(root, destinationPath)
        requireAuthorization(authorization)
        if (source.samePath(destination)) throw OpenCloudException(OpenCloudError.PreconditionFailed)
        val method = if (copy) "COPY" else "MOVE"
        val request =
            Request
                .Builder()
                .url(source)
                .header("Authorization", authorization)
                .header("If-Match", etag)
                .header("Destination", destination.toString())
                .header("Overwrite", "F")
                .method(method, null)
                .build()
        executeMutation(request, setOf(201, 204))
    }

    /**
     * Streams ciphertext to a scoped path using explicit create-only or ETag replacement guards.
     * Length, precondition, media type, and writer form one transport operation.
     */
    @Suppress("LongParameterList")
    fun putCiphertext(
        rootWebDavUrl: String,
        path: String,
        authorization: String,
        contentLength: Long,
        expectedETag: String? = null,
        contentType: String = "application/octet-stream",
        writeBody: (OutputStream) -> Unit,
    ): String? {
        require(contentLength >= 0)
        val etag = expectedETag?.let(::requireStrongETag)
        val url = scopedTarget(rootWebDavUrl, path)
        requireAuthorization(authorization)
        val body =
            object : RequestBody() {
                override fun contentType() = contentType.toMediaType()

                override fun isOneShot() = true

                override fun contentLength() = contentLength

                override fun writeTo(sink: BufferedSink) {
                    val output = sink.outputStream()
                    writeBody(output)
                    output.flush()
                }
            }
        val request =
            Request
                .Builder()
                .url(url)
                .header("Authorization", authorization)
                .apply {
                    if (etag == null) header("If-None-Match", "*") else header("If-Match", etag)
                }.put(body)
                .build()
        return executeMutation(request, setOf(200, 201, 204))
    }

    /** Writes the Web profile's proof property without inventing server-side metadata. */
    fun writeIntegrityToken(
        rootWebDavUrl: String,
        path: String,
        authorization: String,
        token: String,
    ) {
        if (token.isBlank() || token.any(Char::isISOControl)) throw OpenCloudException(OpenCloudError.Unsupported)
        val root = validateRootUrl(rootWebDavUrl)
        val url = if (path.isEmpty()) root else requireMutationTarget(root, path)
        requireAuthorization(authorization)
        val xml =
            """<?xml version="1.0" encoding="utf-8"?><d:propertyupdate xmlns:d="DAV:" xmlns:ocrclone="ocrclone"><d:set><d:prop><ocrclone:integrity-id>$token</ocrclone:integrity-id></d:prop></d:set></d:propertyupdate>"""
        val request =
            Request
                .Builder()
                .url(url)
                .header("Authorization", authorization)
                .method("PROPPATCH", xml.toRequestBody("application/xml".toMediaType()))
                .build()
        executeMutation(request, setOf(207), requireIntegrityPropertySuccess = true)
    }

    private fun listInternal(
        rootWebDavUrl: String,
        path: String,
        authorization: String,
        allowOrdinaryDirectory: Boolean,
        recognizedVaultRoot: Boolean,
    ): VaultDavListing {
        requireAuthorization(authorization)
        val root = validateRootUrl(rootWebDavUrl)
        requireNestedRootAllowed(root, path, allowOrdinaryDirectory, recognizedVaultRoot)
        val requested = appendRelativePath(root, path)
        val request =
            Request
                .Builder()
                .url(requested)
                .header("Authorization", authorization)
                .header("Depth", "1")
                .method("PROPFIND", PROPFIND_BODY)
                .build()
        val xml = executeBounded(request, maxXmlBytes)
        return parseListing(xml, root, requested, allowOrdinaryDirectory, recognizedVaultRoot)
    }

    // Keep duplicate-resource and root/child validation together in one bounded pass.
    @Suppress("CyclomaticComplexMethod")
    private fun parseListing(
        xml: String,
        root: HttpUrl,
        requested: HttpUrl,
        allowOrdinaryDirectory: Boolean,
        recognizedVaultRoot: Boolean,
    ): VaultDavListing {
        if (xml.contains("<!DOCTYPE", ignoreCase = true) || xml.contains("<!ENTITY", ignoreCase = true)) {
            invalidVaultResponse()
        }
        val document =
            try {
                parseSafeXml(xml)
            } catch (failure: OpenCloudException) {
                throw failure
            } catch (_: Exception) {
                invalidVaultResponse()
            }
        val rootElement = document.documentElement
        if (rootElement.namespaceURI != DAV || rootElement.localName != "multistatus") invalidVaultResponse()
        val responses = rootElement.getElementsByTagNameNS(DAV, "response")
        if (responses.length == 0) invalidVaultResponse()

        val entries = mutableListOf<VaultDavEntry>()
        val identities = MutableVaultDavIdentities()
        val scope =
            VaultDavResponseScope(
                root = root,
                requested = requested,
                rootSegments = root.encodedPathSegments.dropLastWhile(String::isEmpty),
                requestedSegments = requested.encodedPathSegments.dropLastWhile(String::isEmpty),
                rootName =
                    root.encodedPathSegments
                        .dropLastWhile(
                            String::isEmpty,
                        ).lastOrNull()
                        ?.let(::decodePathSegment) ?: "",
            )
        var requestedEntry: VaultDavEntry? = null
        var requestedIntegrity: String? = null
        var requestedVaultContentType = false
        for (index in 0 until responses.length) {
            val response = responses.item(index) as? Element ?: invalidVaultResponse()
            val parsed = parseResponseResource(response, scope, identities)
            if (parsed.isRequested) {
                if (requestedEntry != null) invalidVaultResponse()
                requestedEntry = parsed.entry
                requestedIntegrity = parsed.integrityToken
                requestedVaultContentType = parsed.isVaultContentType
            } else {
                entries += parsed.entry
            }
        }
        val self = requestedEntry ?: invalidVaultResponse()
        if (!self.isFolder) invalidVaultResponse()
        val isVaultRoot =
            root.samePath(requested) &&
                (
                    self.rawName.endsWith(".vault", ignoreCase = false) ||
                        !requestedIntegrity.isNullOrEmpty() ||
                        requestedVaultContentType ||
                        recognizedVaultRoot
                )
        if (root.samePath(requested) && !isVaultRoot && !allowOrdinaryDirectory) {
            throw OpenCloudException(OpenCloudError.Unsupported)
        }
        return VaultDavListing(
            root = self,
            children = entries,
            integrityToken = requestedIntegrity,
            vaultEvidence = isVaultRoot,
            requestedIsVaultMarker =
                self.isFolder &&
                    (self.rawName.endsWith(".vault", ignoreCase = false) || self.isVaultMarker),
        )
    }

    /** Reads a bounded ciphertext preview from an entry already obtained from [list]. */
    fun readCiphertext(
        rootWebDavUrl: String,
        entry: VaultDavEntry,
        authorization: String,
        maxBytes: Int = maxCiphertextBytes,
    ): ByteArray {
        require(maxBytes in 1..maxCiphertextBytes)
        return readBoundedEntry(rootWebDavUrl, entry, authorization, maxBytes, range = null)
    }

    /** Streams one listed ciphertext file without buffering it. The callback must consume the full body. */
    fun <T> withCiphertextStream(
        rootWebDavUrl: String,
        entry: VaultDavEntry,
        authorization: String,
        readBody: (InputStream) -> T,
    ): T {
        requireAuthorization(authorization)
        val root = validateRootUrl(rootWebDavUrl)
        validateRawName(entry.rawName)
        if (entry.isFolder || entry.size < 32L) throw OpenCloudException(OpenCloudError.Unsupported)
        val url = appendRelativePath(root, entry.relativePath)
        val advertisedHref = validateEntryHref(root, entry.href)
        if (!url.samePath(advertisedHref)) invalidVaultResponse()
        val request =
            Request
                .Builder()
                .url(advertisedHref)
                .header("Authorization", authorization)
                .header("Accept-Encoding", "identity")
                .apply { entry.strongETag?.let { header("If-Match", it) } }
                .get()
                .build()
        return client.newCall(request).execute().use { response ->
            requireReadStatus(response.code, range = null)
            val body = response.body ?: invalidVaultResponse()
            if (body.contentLength() >= 0 && body.contentLength() != entry.size) invalidVaultResponse()
            val input = ExactLengthInputStream(body.byteStream(), entry.size)
            val result = readBody(input)
            if (input.bytesRead != entry.size) invalidVaultResponse()
            result
        }
    }

    /** Reads at most the rclone header and first encrypted block, even when Range is ignored. */
    fun readProofPrefix(
        rootWebDavUrl: String,
        entry: VaultDavEntry,
        authorization: String,
    ): ByteArray =
        readBoundedEntry(rootWebDavUrl, entry, authorization, PROOF_PREFIX_BYTES, "bytes=0-${PROOF_PREFIX_BYTES - 1}")

    private fun readBoundedEntry(
        rootWebDavUrl: String,
        entry: VaultDavEntry,
        authorization: String,
        maxBytes: Int,
        range: String?,
    ): ByteArray {
        requireAuthorization(authorization)
        val root = validateRootUrl(rootWebDavUrl)
        validateRawName(entry.rawName)
        if (entry.isFolder) throw OpenCloudException(OpenCloudError.Unsupported)
        val url = appendRelativePath(root, entry.relativePath)
        val advertisedHref = validateEntryHref(root, entry.href)
        if (!url.samePath(advertisedHref)) invalidVaultResponse()
        val request =
            Request
                .Builder()
                .url(advertisedHref)
                .header("Authorization", authorization)
                .header("Accept-Encoding", "identity")
                .apply {
                    if (range != null) header("Range", range)
                    entry.strongETag?.let { header("If-Match", it) }
                }.get()
                .build()
        val response = client.newCall(request).execute()
        return readCiphertextResponse(response, maxBytes, range, entry.size)
    }

    private fun readCiphertextResponse(
        response: okhttp3.Response,
        maxBytes: Int,
        range: String?,
        expectedSize: Long,
    ): ByteArray {
        response.use {
            requireReadStatus(it.code, range)
            val body = it.body ?: invalidVaultResponse()
            if (body.contentLength() > maxBytes) invalidVaultResponse()
            val bytes = readAtMost(body.byteStream(), maxBytes)
            if (it.code == 200 && bytes.size.toLong() != expectedSize) invalidVaultResponse()
            if (range != null && it.code == 206) {
                validateContentRange(it.header("Content-Range"), bytes.size, expectedSize, maxBytes)
            }
            if (body.contentLength() >= 0 && body.contentLength() != bytes.size.toLong()) invalidVaultResponse()
            return bytes
        }
    }

    private fun requireReadStatus(
        statusCode: Int,
        range: String?,
    ) {
        if (range == null && statusCode == 200) return
        if (range != null && statusCode in setOf(200, 206)) return
        throw TransferHttpException(statusCode)
    }

    private fun executeBounded(
        request: Request,
        maxBytes: Long,
    ): String {
        val response = client.newCall(request).execute()
        response.use {
            if (it.code != 207) throw TransferHttpException(it.code)
            val body = it.body ?: invalidVaultResponse()
            if (body.contentLength() > maxBytes) invalidVaultResponse()
            val bytes = readAtMost(body.byteStream(), maxBytes.toInt())
            return bytes.toString(Charsets.UTF_8)
        }
    }

    private fun mutationRequest(
        rootWebDavUrl: String,
        path: String,
        authorization: String,
    ): Request.Builder {
        val url = scopedTarget(rootWebDavUrl, path)
        requireAuthorization(authorization)
        return Request.Builder().url(url).header("Authorization", authorization)
    }

    private fun scopedTarget(
        rootWebDavUrl: String,
        path: String,
    ): HttpUrl = requireMutationTarget(validateRootUrl(rootWebDavUrl), path)

    private fun requireMutationTarget(
        root: HttpUrl,
        path: String,
    ): HttpUrl {
        if (path.isEmpty()) throw OpenCloudException(OpenCloudError.Unsupported)
        val target = appendRelativePath(root, path)
        requireScopedUrl(target, root)
        return target
    }

    private fun requireStrongETag(value: String): String =
        value.takeIf(::isStrongETag) ?: throw OpenCloudException(OpenCloudError.PreconditionFailed)

    // Translate transport details into the app's stable public error categories.
    @Suppress("SwallowedException")
    private fun executeMutation(
        request: Request,
        expectedCodes: Set<Int>,
        requireIntegrityPropertySuccess: Boolean = false,
    ): String? =
        try {
            client.newCall(request).execute().use { response ->
                if (response.code == 412) throw TransferConflictException()
                if (response.code !in expectedCodes) throw TransferHttpException(response.code)
                if (requireIntegrityPropertySuccess) validateIntegrityPropertyResponse(response)
                response.header("ETag")
            }
        } catch (failure: IOException) {
            throw OpenCloudException(failure.toOpenCloudError())
        }

    private fun validateIntegrityPropertyResponse(response: okhttp3.Response) {
        val body = response.body ?: invalidVaultResponse()
        if (body.contentLength() > maxXmlBytes) invalidVaultResponse()
        val xml = readAtMost(body.byteStream(), maxXmlBytes.toInt()).toString(Charsets.UTF_8)
        val document = parseSafeXml(xml)
        val propstats = document.getElementsByTagNameNS(DAV, "propstat")
        var propertySucceeded = false
        for (index in 0 until propstats.length) {
            val propstat = propstats.item(index) as? Element ?: invalidVaultResponse()
            val status =
                propstat
                    .directText(DAV, "status")
                    ?.trim()
                    ?.split(Regex("\\s+"))
                    ?.getOrNull(1)
            if (status != "200") continue
            val prop = propstat.getElementsByTagNameNS(DAV, "prop").item(0) as? Element ?: invalidVaultResponse()
            if (prop.getElementsByTagNameNS(OCRCLONE, "integrity-id").length == 1) {
                propertySucceeded = true
            }
        }
        if (!propertySucceeded) invalidVaultResponse()
    }

    private fun successfulProperties(response: Element): Element {
        val merged = response.ownerDocument.createElementNS(DAV, "prop")
        val seen = mutableSetOf<Pair<String?, String?>>()
        val propstats = response.getElementsByTagNameNS(DAV, "propstat")
        for (index in 0 until propstats.length) {
            val stat = propstats.item(index) as? Element ?: invalidVaultResponse()
            val status =
                stat
                    .directText(DAV, "status")
                    ?.trim()
                    ?.split(Regex("\\s+"))
                    ?.getOrNull(1)
            if (status != "200") continue
            val prop = stat.getElementsByTagNameNS(DAV, "prop").item(0) as? Element ?: invalidVaultResponse()
            for (childIndex in 0 until prop.childNodes.length) {
                val child = prop.childNodes.item(childIndex) as? Element ?: continue
                if (!seen.add(child.namespaceURI to child.localName)) invalidVaultResponse()
                merged.appendChild(child.cloneNode(true))
            }
        }
        if (merged.getElementsByTagNameNS(DAV, "resourcetype").length != 1) invalidVaultResponse()
        return merged
    }

    private fun parseResponseResource(
        response: Element,
        scope: VaultDavResponseScope,
        identities: MutableVaultDavIdentities,
    ): ParsedVaultDavResponse {
        val hrefText = response.directChildText(DAV, "href") ?: invalidVaultResponse()
        val hrefUrl = resolveScopedHref(scope.root, scope.requested, hrefText)
        val prop = successfulProperties(response)
        val segments = hrefUrl.encodedPathSegments.dropLastWhile(String::isEmpty)
        val isRequested = hrefUrl.samePath(scope.requested)
        if (!isRequested) requireDirectChild(segments, scope.requestedSegments)
        val relativeSegments = segments.drop(scope.rootSegments.size)
        val decodedSegments = relativeSegments.map(::decodePathSegment)
        decodedSegments.forEach(::validateRawName)
        val relativePath = decodedSegments.joinToString("/")
        val hrefName = decodedSegments.lastOrNull() ?: scope.rootName
        val rawName = prop.directText(OC, "name") ?: hrefName
        validateRawName(rawName)
        if (decodedSegments.isNotEmpty() && rawName != hrefName) invalidVaultResponse()
        val entry = parseEntry(prop, hrefUrl, relativePath, rawName, identities)
        return ParsedVaultDavResponse(
            entry = entry,
            isRequested = isRequested,
            integrityToken = prop.directText(OCRCLONE, "integrity-id")?.trim()?.takeIf(String::isNotEmpty),
            isVaultContentType = prop.directText(DAV, "getcontenttype")?.trim() == VAULT_CONTENT_TYPE,
        )
    }

    private fun parseEntry(
        prop: Element,
        hrefUrl: HttpUrl,
        relativePath: String,
        rawName: String,
        identities: MutableVaultDavIdentities,
    ): VaultDavEntry {
        val id = (prop.directText(OC, "fileid") ?: prop.directText(OC, "id"))?.trim() ?: invalidVaultResponse()
        identities.requireUnique(id, relativePath)
        val resourceType = prop.directChild(DAV, "resourcetype") ?: invalidVaultResponse()
        val collectionCount = resourceType.getElementsByTagNameNS(DAV, "collection").length
        if (collectionCount > 1) invalidVaultResponse()
        val folder = collectionCount == 1
        val sizeText = prop.directText(DAV, "getcontentlength") ?: prop.directText(OC, "size")
        val size = sizeText?.toLongOrNull() ?: if (folder) 0L else invalidVaultResponse()
        if (size < 0) invalidVaultResponse()
        val etag = prop.directText(DAV, "getetag")?.trim()?.takeIf(::isStrongETag)
        val vaultMarker =
            prop.directText(DAV, "getcontenttype")?.trim() == VAULT_CONTENT_TYPE ||
                !prop.directText(OCRCLONE, "integrity-id")?.trim().isNullOrEmpty()
        return VaultDavEntry(id, relativePath, rawName, folder, size, etag, hrefUrl.toString(), vaultMarker)
    }

    private fun requireDirectChild(
        actualSegments: List<String>,
        requestedSegments: List<String>,
    ) {
        if (actualSegments.size != requestedSegments.size + 1) invalidVaultResponse()
        if (actualSegments.take(requestedSegments.size) != requestedSegments) invalidVaultResponse()
    }

    private fun requireNestedRootAllowed(
        root: HttpUrl,
        path: String,
        allowOrdinaryDirectory: Boolean,
        recognizedVaultRoot: Boolean,
    ) {
        if (path.isEmpty() || allowOrdinaryDirectory || recognizedVaultRoot) return
        val rootName =
            root.encodedPathSegments
                .dropLastWhile(String::isEmpty)
                .lastOrNull()
                ?.let(::decodePathSegment)
        if (rootName?.endsWith(".vault") != true) throw OpenCloudException(OpenCloudError.Unsupported)
    }

    private fun resolveScopedHref(
        root: HttpUrl,
        requested: HttpUrl,
        href: String,
    ): HttpUrl {
        val actual = requested.resolve(href) ?: invalidVaultResponse()
        val rootSegments = root.encodedPathSegments.dropLastWhile(String::isEmpty)
        val actualSegments = actual.encodedPathSegments.dropLastWhile(String::isEmpty)
        requireScopedUrl(actual, root)
        if (actualSegments.take(rootSegments.size) != rootSegments) invalidVaultResponse()
        return actual
    }

    private fun validateEntryHref(
        root: HttpUrl,
        href: String,
    ): HttpUrl {
        val parsed = runCatching { href.toHttpUrl() }.getOrNull() ?: invalidVaultResponse()
        val rootSegments = root.encodedPathSegments.dropLastWhile(String::isEmpty)
        val segments = parsed.encodedPathSegments.dropLastWhile(String::isEmpty)
        requireScopedUrl(parsed, root)
        if (segments.take(rootSegments.size) != rootSegments) invalidVaultResponse()
        return parsed
    }

    private fun validateRootUrl(value: String): HttpUrl {
        val root = endpoints.endpoint(value, allowQuery = false)
        return root.newBuilder().addPathSegment("").build()
    }

    private fun requireScopedUrl(
        actual: HttpUrl,
        root: HttpUrl,
    ) {
        if (!actual.sameOrigin(root) || actual.query != null || actual.fragment != null) invalidVaultResponse()
        if (actual.username.isNotEmpty() || actual.password.isNotEmpty()) invalidVaultResponse()
    }

    private fun appendRelativePath(
        root: HttpUrl,
        path: String,
    ): HttpUrl {
        if (path.startsWith('/') || path.endsWith('/') || path.contains('\\')) {
            if (path.isNotEmpty()) throw OpenCloudException(OpenCloudError.Unsupported)
        }
        val parts = if (path.isEmpty()) emptyList() else path.split('/')
        if (parts.any { it in setOf("", ".", "..") || it.any(Char::isISOControl) }) {
            throw OpenCloudException(OpenCloudError.Unsupported)
        }
        return root.newBuilder().apply { parts.forEach(::addPathSegment) }.build()
    }

    private fun readAtMost(
        input: InputStream,
        maxBytes: Int,
    ): ByteArray {
        val out = ByteArrayOutputStream(minOf(maxBytes, 64 * 1024))
        val buffer = ByteArray(8192)
        while (true) {
            val remaining = maxBytes - out.size()
            val count = input.read(buffer, 0, minOf(buffer.size, remaining + 1))
            if (count < 0) break
            if (count > remaining) invalidVaultResponse()
            out.write(buffer, 0, count)
        }
        return out.toByteArray()
    }

    private fun validateContentRange(
        header: String?,
        bodyLength: Int,
        expectedTotal: Long,
        requestedLength: Int,
    ) {
        val match = CONTENT_RANGE.matchEntire(header ?: "") ?: invalidVaultResponse()
        val start = match.groupValues[1].toLongOrNull() ?: invalidVaultResponse()
        val end = match.groupValues[2].toLongOrNull() ?: invalidVaultResponse()
        val total = match.groupValues[3].toLongOrNull() ?: invalidVaultResponse()
        val expectedEnd = minOf(requestedLength.toLong() - 1, expectedTotal - 1)
        if (start != 0L || end != expectedEnd || total <= end) invalidVaultResponse()
        if (end - start + 1 != bodyLength.toLong() || total != expectedTotal) invalidVaultResponse()
    }

    private fun isStrongETag(value: String): Boolean =
        value.length >= 2 &&
            value.first() == '"' &&
            value.last() == '"' &&
            value.substring(1, value.length - 1).none { it == '"' || it.isISOControl() }

    private fun requireAuthorization(value: String) {
        if (value.isBlank() || value.any(Char::isISOControl)) throw OpenCloudException(OpenCloudError.Unsupported)
    }

    private fun validateRawName(name: String) {
        if (name in setOf("", ".", "..")) invalidVaultResponse()
        if (name.any { it == '/' || it == '\\' || it.isISOControl() }) invalidVaultResponse()
    }

    private data class VaultDavResponseScope(
        val root: HttpUrl,
        val requested: HttpUrl,
        val rootSegments: List<String>,
        val requestedSegments: List<String>,
        val rootName: String,
    )

    private data class ParsedVaultDavResponse(
        val entry: VaultDavEntry,
        val isRequested: Boolean,
        val integrityToken: String?,
        val isVaultContentType: Boolean,
    )

    private class MutableVaultDavIdentities {
        private val ids = mutableSetOf<String>()
        private val paths = mutableSetOf<String>()

        fun requireUnique(
            id: String,
            path: String,
        ) {
            if (id.isBlank() || !ids.add(id) || !paths.add(path)) invalidVaultResponse()
        }
    }

    private fun decodePathSegment(encoded: String): String =
        runCatching { URLDecoder.decode(encoded.replace("+", "%2B"), StandardCharsets.UTF_8.name()) }
            .getOrElse { invalidVaultResponse() }

    private fun Element.directChild(
        namespace: String,
        name: String,
    ): Element? {
        for (index in 0 until childNodes.length) {
            val child = childNodes.item(index) as? Element ?: continue
            if (child.namespaceURI == namespace && child.localName == name) return child
        }
        return null
    }

    private fun Element.directChildText(
        namespace: String,
        name: String,
    ): String? = directChild(namespace, name)?.textContent

    private fun Element.directText(
        namespace: String,
        name: String,
    ): String? = directChild(namespace, name)?.textContent

    private companion object {
        const val DAV = "DAV:"
        const val OC = "http://owncloud.org/ns"
        const val OCRCLONE = "ocrclone"
        const val VAULT_CONTENT_TYPE = "application/vnd.opencloud.vault"
        const val DEFAULT_MAX_XML_BYTES = 2L * 1024 * 1024
        const val DEFAULT_MAX_CIPHERTEXT_BYTES = 8 * 1024 * 1024
        const val PROOF_PREFIX_BYTES = 65_584
        val CONTENT_RANGE = Regex("bytes (\\d+)-(\\d+)/(\\d+)")
        val PROPFIND_BODY =
            """<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:ocrclone="ocrclone"><d:prop><d:resourcetype/><d:getcontentlength/><d:getetag/><d:getcontenttype/><oc:fileid/><oc:id/><oc:name/><oc:size/><ocrclone:integrity-id/></d:prop></d:propfind>"""
                .toRequestBody("application/xml".toMediaType())
    }
}

data class VaultDavEntry(
    val id: String,
    /** Decoded, literal path relative to the advertised DAV root; each encrypted name is one segment. */
    val relativePath: String,
    /** Raw server name segment. For children this remains ciphertext. */
    val rawName: String,
    val isFolder: Boolean,
    val size: Long,
    val strongETag: String?,
    /** Validated absolute DAV href used only to bind later reads to the listing. */
    val href: String,
    /** Explicit DAV content-type or integrity marker; `.vault` naming is evaluated separately. */
    val isVaultMarker: Boolean = false,
)

data class VaultDavListing(
    val root: VaultDavEntry,
    val children: List<VaultDavEntry>,
    val integrityToken: String?,
    val vaultEvidence: Boolean,
    /** Marks the requested collection itself; useful when safely enumerating an ordinary parent. */
    val requestedIsVaultMarker: Boolean = false,
)

private fun HttpUrl.sameOrigin(other: HttpUrl): Boolean =
    scheme == other.scheme && host == other.host && port == other.port

private fun HttpUrl.samePath(other: HttpUrl): Boolean =
    sameOrigin(other) &&
        pathSegments.dropLastWhile(String::isEmpty) == other.pathSegments.dropLastWhile(String::isEmpty)

private fun isFolderVaultEntry(entry: VaultDavEntry): Boolean =
    entry.isFolder && (entry.rawName.endsWith(".vault", ignoreCase = false) || entry.isVaultMarker)

private fun invalidVaultResponse(): Nothing = throw OpenCloudException(OpenCloudError.InvalidResponse)

/** Rejects a short or oversized DAV body, including chunked responses without Content-Length. */
private class ExactLengthInputStream(
    input: InputStream,
    private val expected: Long,
) : FilterInputStream(input) {
    var bytesRead: Long = 0
        private set

    override fun read(): Int {
        val value = super.read()
        if (value >= 0) count(1)
        return value
    }

    override fun read(
        buffer: ByteArray,
        offset: Int,
        length: Int,
    ): Int {
        val count = inputRead(buffer, offset, length)
        if (count > 0) count(count)
        return count
    }

    private fun inputRead(
        buffer: ByteArray,
        offset: Int,
        length: Int,
    ): Int = `in`.read(buffer, offset, length)

    private fun count(amount: Int) {
        if (amount.toLong() > expected - bytesRead) invalidVaultResponse()
        bytesRead += amount
    }
}
