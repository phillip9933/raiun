package eu.opencloud.android.next.core.network

import okhttp3.Response

data class DownloadExpectation(
    val length: Long,
    val eTag: String?,
) {
    val strongETag: String?
        get() = eTag?.takeIf(STRONG_ETAG::matches)

    internal fun validate(
        response: Response,
        offset: Long,
    ): Boolean {
        val encoding = response.header("Content-Encoding")
        if (encoding != null && !encoding.equals("identity", ignoreCase = true)) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
        val resumed = response.code == 206
        val bodyLength = response.body?.contentLength() ?: -1
        val expectedLength = if (resumed) length - offset else length
        val versionMatches = strongETag == null || response.header("ETag") == strongETag
        val rangeMatches =
            !resumed ||
                (
                    offset > 0 &&
                        strongETag != null &&
                        response.header("Content-Range") == "bytes $offset-${length - 1}/$length"
                )
        val lengthMatches = bodyLength < 0 || bodyLength == expectedLength
        if (!versionMatches || !rangeMatches || !lengthMatches) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
        return resumed
    }

    private companion object {
        // RFC 9110 section 8.8.3: one opaque tag, not an If-Match list or wildcard.
        val STRONG_ETAG = Regex("\"[\\x21\\x23-\\x7e\\x80-\\xff]*\"")
    }
}
