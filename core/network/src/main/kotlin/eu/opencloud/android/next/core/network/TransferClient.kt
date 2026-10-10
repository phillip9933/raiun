package eu.opencloud.android.next.core.network

import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okio.BufferedSink
import java.io.InputStream
import java.time.Clock
import java.util.concurrent.CancellationException

class TransferClient(
    client: OkHttpClient,
    private val clock: Clock = Clock.systemUTC(),
) {
    // Never forward credentials across a redirect or automatically replay an ambiguous upload.
    private val client =
        client
            .newBuilder()
            .dispatcher(okhttp3.Dispatcher())
            .followRedirects(false)
            .followSslRedirects(false)
            .retryOnConnectionFailure(false)
            .build()

    fun cancelRequests() = client.dispatcher.cancelAll()

    fun download(
        url: String,
        authorization: String,
        startOffset: Long,
        expectation: DownloadExpectation? = null,
        sink: (InputStream, Long?, Boolean) -> Unit,
    ): String? {
        if (startOffset < 0 || (startOffset > 0 && expectation?.strongETag == null)) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
        val request =
            Request
                .Builder()
                .url(url)
                .header("Authorization", authorization)
                .header("Accept-Encoding", "identity")
                .apply {
                    expectation?.strongETag?.let { header("If-Match", it) }
                    if (startOffset > 0) header("Range", "bytes=$startOffset-")
                }.get()
                .build()
        return execute(request).use { response ->
            requireSuccessful(response, setOf(200, 206))
            val resumed = expectation?.validate(response, startOffset) ?: false
            if (response.code == 206 && !resumed) throw OpenCloudException(OpenCloudError.PreconditionFailed)
            sink(
                requireNotNull(response.body).byteStream(),
                response.body?.contentLength()?.takeIf { it >= 0 },
                resumed,
            )
            response.header("ETag")
        }
    }

    /** Optional DAV checksum for the exact version already accepted by a conditional GET. */
    fun downloadChecksum(
        url: String,
        authorization: String,
        expectation: DownloadExpectation,
    ): Pair<String, String>? {
        val version = expectation.strongETag ?: return null
        val properties =
            """<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop><d:resourcetype/><d:getcontentlength/><d:getetag/><oc:checksums/></d:prop></d:propfind>"""
        val request =
            Request
                .Builder()
                .url(url)
                .header("Authorization", authorization)
                .header("Depth", "0")
                .header("Cache-Control", "no-cache")
                .method("PROPFIND", properties.toRequestBody("application/xml".toMediaType()))
                .build()
        return execute(request, metadata = true).use { response ->
            if (response.code in setOf(405, 501)) return@use null
            requireSuccessful(response, setOf(207))
            val xml = response.readBoundedMetadata(64 * 1024)
            if (xml.contains("<!DOCTYPE", true) || xml.contains("<!ENTITY", true)) {
                throw OpenCloudException(OpenCloudError.InvalidResponse)
            }
            val metadata = parseDavObject(xml, url, strictChecksumStatus = true)
            if (metadata.folder || metadata.size != expectation.length || metadata.eTag != version) {
                throw OpenCloudException(OpenCloudError.PreconditionFailed)
            }
            listOf("SHA-256", "SHA-1", "MD5")
                .firstNotNullOfOrNull { algorithm ->
                    metadata.checksums[algorithm]?.let { algorithm to it }
                }
        }
    }

    @Suppress("LongParameterList")
    fun upload(
        url: String,
        authorization: String,
        mimeType: String?,
        length: Long,
        overwrite: Boolean,
        source: () -> InputStream,
        expectedETag: String? = null,
        onProgress: (Long) -> Unit,
    ): String? {
        if (!overwrite && expectedETag == null) {
            requireUploadTargetAbsent(url, authorization)
        }
        val body = streamingBody(mimeType, length, source, onProgress)
        val request =
            Request
                .Builder()
                .url(url)
                .header("Authorization", authorization)
                .apply {
                    if (expectedETag != null) {
                        header(
                            "If-Match",
                            DownloadExpectation(0, expectedETag).strongETag
                                ?: throw OpenCloudException(OpenCloudError.PreconditionFailed),
                        )
                    } else if (!overwrite) {
                        header("If-None-Match", "*")
                    }
                }.put(body)
                .build()
        return execute(request).use { response ->
            if (response.code == 412) throw TransferConflictException()
            requireSuccessful(response, setOf(200, 201, 204))
            response.header("ETag")
        }
    }

    /** Detect existing targets before sending bytes; racing creates still require server conditional-PUT support. */
    private fun requireUploadTargetAbsent(
        url: String,
        authorization: String,
    ) {
        val request =
            Request
                .Builder()
                .url(url)
                .header("Authorization", authorization)
                .header("Cache-Control", "no-cache")
                .head()
                .build()
        execute(request).use { response ->
            when {
                response.code == 404 -> Unit
                response.isSuccessful -> throw TransferConflictException()
                else -> requireSuccessful(response, emptySet())
            }
        }
    }

    fun verifyUpload(
        url: String,
        authorization: String,
        expected: ContentFingerprint,
        useServerChecksum: Boolean = false,
        checkActive: () -> Unit = {},
    ): String? {
        if (!useServerChecksum) return verifyUploadBytes(url, authorization, expected, checkActive)
        var lastMismatch = false
        for (wait in POST_WRITE_VERIFICATION_DELAYS_MS) {
            awaitVerificationDelay(wait, checkActive)
            when (val attempt = verifyUploadAttempt(url, authorization, expected, checkActive)) {
                is UploadAttempt.Verified -> return attempt.eTag
                is UploadAttempt.Retry -> lastMismatch = attempt.mismatch
            }
        }
        if (lastMismatch) throw OpenCloudException(OpenCloudError.PreconditionFailed)
        throw OpenCloudException(OpenCloudError.NotReady(5))
    }

    private fun verifyUploadAttempt(
        url: String,
        authorization: String,
        expected: ContentFingerprint,
        checkActive: () -> Unit,
    ): UploadAttempt {
        val checksum =
            try {
                verifyServerChecksum(url, authorization, expected)
            } catch (failure: OpenCloudException) {
                if (failure.error == OpenCloudError.InvalidResponse) {
                    null
                } else if (failure.isPostWriteTransient()) {
                    return UploadAttempt.Retry(mismatch = false)
                } else {
                    throw failure
                }
            }
        return when (checksum) {
            is ChecksumVerification.Match -> UploadAttempt.Verified(checksum.eTag)
            ChecksumVerification.Unavailable, ChecksumVerification.Mismatch ->
                verifyUploadBytesAttempt(url, authorization, expected, checkActive)
            null -> verifyUploadBytesAttempt(url, authorization, expected, checkActive)
        }
    }

    private fun verifyUploadBytesAttempt(
        url: String,
        authorization: String,
        expected: ContentFingerprint,
        checkActive: () -> Unit,
    ): UploadAttempt =
        try {
            UploadAttempt.Verified(verifyUploadBytes(url, authorization, expected, checkActive))
        } catch (failure: OpenCloudException) {
            when {
                failure.error == OpenCloudError.PreconditionFailed -> UploadAttempt.Retry(mismatch = true)
                failure.isPostWriteTransient() -> UploadAttempt.Retry(mismatch = false)
                else -> throw failure
            }
        }

    private fun awaitVerificationDelay(
        delayMillis: Long,
        checkActive: () -> Unit,
    ) {
        checkActive()
        if (delayMillis == 0L) return
        try {
            Thread.sleep(delayMillis)
        } catch (cancelled: InterruptedException) {
            Thread.currentThread().interrupt()
            throw CancellationException("Verification cancelled").also { it.initCause(cancelled) }
        }
        checkActive()
    }

    private fun verifyUploadBytes(
        url: String,
        authorization: String,
        expected: ContentFingerprint,
        checkActive: () -> Unit,
    ): String? {
        val request =
            Request
                .Builder()
                .url(url)
                .header("Authorization", authorization)
                .header("Accept-Encoding", "identity")
                .header("Cache-Control", "no-cache")
                .get()
                .build()
        return execute(request).use { response ->
            requireSuccessful(response, setOf(200))
            val actual =
                ContentFingerprint.read(
                    requireNotNull(response.body).byteStream(),
                    expected.length,
                    checkActive,
                )
            if (!expected.matches(actual)) throw OpenCloudException(OpenCloudError.PreconditionFailed)
            response.header("ETag")
        }
    }

    private fun verifyServerChecksum(
        url: String,
        authorization: String,
        expected: ContentFingerprint,
    ): ChecksumVerification {
        val properties =
            """<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop>
            <d:resourcetype/><d:getcontentlength/><d:getetag/><oc:checksums/></d:prop></d:propfind>"""
        val request =
            Request
                .Builder()
                .url(url)
                .header("Authorization", authorization)
                .header("Depth", "0")
                .header(
                    "Cache-Control",
                    "no-cache",
                ).method("PROPFIND", properties.toRequestBody("application/xml".toMediaType()))
                .build()
        return execute(request).use { response ->
            if (response.code in setOf(405, 501)) return@use ChecksumVerification.Unavailable
            requireSuccessful(response, setOf(207))
            val source = requireNotNull(response.body).source()
            if (source.request(65537)) throw OpenCloudException(OpenCloudError.InvalidResponse)
            val metadata = parseDavObject(source.readUtf8(), url)
            val checksum = metadata.checksums["SHA-256"] ?: return@use ChecksumVerification.Unavailable
            if (metadata.folder || metadata.size != expected.length || !expected.matchesSha256(checksum)) {
                return@use ChecksumVerification.Mismatch
            }
            ChecksumVerification.Match(DownloadExpectation(metadata.size, metadata.eTag).strongETag)
        }
    }

    private fun OpenCloudException.isPostWriteTransient(): Boolean =
        error == OpenCloudError.NotFound ||
            error == OpenCloudError.InvalidResponse ||
            error == OpenCloudError.PreconditionFailed ||
            error is OpenCloudError.NotReady ||
            (error is OpenCloudError.ServerFailure && error.statusCode in setOf(500, 502, 503, 504))

    fun createCollection(
        url: String,
        authorization: String,
        acceptExisting: Boolean = true,
    ) {
        val request =
            Request
                .Builder()
                .url(url)
                .header("Authorization", authorization)
                .method("MKCOL", EMPTY_BODY)
                .build()
        val alreadyExists =
            execute(request).use { response ->
                requireSuccessful(response, if (acceptExisting) setOf(201, 405) else setOf(201))
                response.code == 405
            }
        if (alreadyExists) {
            RemoteDiscoveryClient(client, maxResponseBytes = 64 * 1024).requireCollection(url, authorization)
        }
    }

    fun createTusUpload(
        endpoint: String,
        authorization: String,
        length: Long,
        metadata: String,
    ): String {
        val request =
            Request
                .Builder()
                .url(endpoint)
                .header("Authorization", authorization)
                .header("Tus-Resumable", TUS_VERSION)
                .header("Upload-Length", length.toString())
                .header("Upload-Metadata", metadata)
                .post(EMPTY_BODY)
                .build()
        return execute(request).use { response ->
            requireSuccessful(response, setOf(201))
            resolveTusLocation(endpoint, requireNotNull(response.header("Location")))
        }
    }

    fun tusOffset(
        url: String,
        authorization: String,
    ): Long {
        val request =
            Request
                .Builder()
                .url(
                    url,
                ).header("Authorization", authorization)
                .header("Tus-Resumable", TUS_VERSION)
                .head()
                .build()
        return execute(request).use { response ->
            requireSuccessful(response, setOf(200, 204))
            tusResponseOffset(response)
        }
    }

    @Suppress("LongParameterList")
    fun patchTus(
        url: String,
        authorization: String,
        offset: Long,
        length: Long,
        source: () -> InputStream,
        onProgress: (Long) -> Unit,
    ): Long {
        if (offset < 0 || length < 0 || offset > Long.MAX_VALUE - length) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
        val body = streamingBody("application/offset+octet-stream", length, source, onProgress)
        val request =
            Request
                .Builder()
                .url(url)
                .header("Authorization", authorization)
                .header("Tus-Resumable", TUS_VERSION)
                .header("Upload-Offset", offset.toString())
                .patch(body)
                .build()
        return execute(request).use { response ->
            if (response.code == 409) throw TusOffsetException()
            requireSuccessful(response, setOf(204))
            tusResponseOffset(response, offset + length)
        }
    }

    private fun tusResponseOffset(
        response: Response,
        expected: Long? = null,
    ): Long =
        response.header("Upload-Offset")?.toLongOrNull()?.takeIf { it >= 0 && (expected == null || it == expected) }
            ?: throw OpenCloudException(OpenCloudError.PreconditionFailed)

    fun resolveTusLocation(
        endpoint: String,
        location: String,
    ): String {
        val base = endpoint.toHttpUrl()
        val target = base.resolve(location) ?: throw OpenCloudException(OpenCloudError.Trust)
        val sameOrigin = target.scheme == base.scheme && target.host == base.host && target.port == base.port
        val hasCredentials = target.username.isNotEmpty() || target.password.isNotEmpty()
        if (!sameOrigin || hasCredentials || target.fragment != null) {
            throw OpenCloudException(OpenCloudError.Trust)
        }
        return target.toString()
    }

    private fun streamingBody(
        mimeType: String?,
        length: Long,
        source: () -> InputStream,
        onProgress: (Long) -> Unit,
    ) = object : RequestBody() {
        override fun contentType() = mimeType?.toMediaTypeOrNull()

        override fun contentLength() = length

        override fun writeTo(sink: BufferedSink) {
            source().use { input ->
                val buffer = ByteArray(BUFFER_SIZE)
                var written = 0L
                while (written < length) {
                    val count = input.read(buffer, 0, minOf(buffer.size.toLong(), length - written).toInt())
                    if (count < 0) error("The transfer source ended before its declared length.")
                    sink.write(buffer, 0, count)
                    written += count
                    onProgress(written)
                }
            }
        }
    }

    private fun requireSuccessful(
        response: Response,
        expected: Set<Int>,
    ) {
        if (response.code !in expected) {
            throw TransferHttpException(
                statusCode = response.code,
                retryAfterSeconds = parseRetryAfter(response.header("Retry-After"), clock),
            )
        }
    }

    // Drop causes deliberately: network and source exceptions can contain credentials and paths.
    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    private fun execute(
        request: Request,
        metadata: Boolean = false,
    ): Response =
        try {
            (if (metadata) client.withMetadataDeadline() else client).newCall(request).execute()
        } catch (exception: CancellationException) {
            throw exception
        } catch (exception: java.net.SocketException) {
            throw OpenCloudException(OpenCloudError.Timeout)
        } catch (exception: Exception) {
            throw OpenCloudException(exception.toOpenCloudError())
        }

    private companion object {
        const val BUFFER_SIZE = 64 * 1024
        const val TUS_VERSION = "1.0.0"
        val EMPTY_BODY =
            object : RequestBody() {
                override fun contentType() = null

                override fun contentLength() = 0L

                override fun writeTo(sink: BufferedSink) = Unit
            }
    }
}

private sealed interface ChecksumVerification {
    data class Match(
        val eTag: String?,
    ) : ChecksumVerification

    data object Unavailable : ChecksumVerification

    data object Mismatch : ChecksumVerification
}

private sealed interface UploadAttempt {
    data class Verified(
        val eTag: String?,
    ) : UploadAttempt

    data class Retry(
        val mismatch: Boolean,
    ) : UploadAttempt
}

private val POST_WRITE_VERIFICATION_DELAYS_MS = longArrayOf(0, 150, 300, 600, 1_200, 2_400)

class TransferHttpException(
    val statusCode: Int,
    retryAfterSeconds: Long? = null,
    error: OpenCloudError = httpError(statusCode, retryAfterSeconds),
) : OpenCloudException(error)

class TransferConflictException : OpenCloudException(OpenCloudError.Conflict)

class TusOffsetException : OpenCloudException(OpenCloudError.PreconditionFailed)
