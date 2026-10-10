package eu.opencloud.android.next.core.network

import okhttp3.Response
import okhttp3.ResponseBody.Companion.asResponseBody
import okio.Buffer
import java.util.concurrent.TimeUnit.MILLISECONDS

/**
 * Reads a metadata response after OkHttp's transparent content decoding, with a hard byte cap.
 * The cap is enforced on bytes actually received, so absent or misleading Content-Length headers
 * (including compressed responses) do not bypass it.
 */
internal fun Response.readBoundedMetadata(maxBytes: Long): String {
    require(maxBytes >= 0)
    val responseBody = body ?: return ""
    val source = responseBody.source()
    val bytes = Buffer()
    while (bytes.size <= maxBytes) {
        val remaining = maxBytes + 1 - bytes.size
        val read = source.read(bytes, minOf(remaining, 8 * 1024L))
        if (read == -1L) {
            return bytes.asResponseBody(responseBody.contentType(), bytes.size).string()
        }
    }
    throw OpenCloudException(OpenCloudError.InvalidResponse)
}

internal fun okhttp3.OkHttpClient.withMetadataDeadline() =
    newBuilder()
        .callTimeout(minOf(callTimeoutMillis.takeIf { it > 0 } ?: 30_000, 30_000).toLong(), MILLISECONDS)
        .build()

internal const val AUTH_METADATA_LIMIT_BYTES = 128 * 1024L
internal const val ERROR_METADATA_LIMIT_BYTES = 32 * 1024L
internal const val LISTING_METADATA_LIMIT_BYTES = 4 * 1024 * 1024L
internal const val SMALL_METADATA_LIMIT_BYTES = 512 * 1024L
