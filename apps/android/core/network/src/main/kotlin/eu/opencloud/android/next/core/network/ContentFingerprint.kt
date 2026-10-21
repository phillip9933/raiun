package eu.opencloud.android.next.core.network

import java.io.InputStream
import java.security.MessageDigest

/** Fingerprint exactly the declared bytes, without buffering the file or treating ETags as hashes. */
class ContentFingerprint private constructor(
    val length: Long,
    private val sha256: ByteArray,
) {
    fun matches(other: ContentFingerprint): Boolean =
        length == other.length && MessageDigest.isEqual(sha256, other.sha256)

    fun sha256Hex(): String = sha256.joinToString("") { "%02x".format(it) }

    internal fun matchesSha256(value: String): Boolean =
        MessageDigest.isEqual(
            sha256Hex().toByteArray(),
            value.lowercase().toByteArray(),
        )

    companion object {
        fun read(
            input: InputStream,
            length: Long,
            checkActive: () -> Unit = {},
        ): ContentFingerprint {
            requireValid(length >= 0)
            val digest = MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(64 * 1024)
            var count = 0L
            while (true) {
                checkActive()
                val read = input.read(buffer)
                if (read < 0) break
                requireValid(read > 0 && read.toLong() <= length - count)
                digest.update(buffer, 0, read)
                count += read
            }
            requireValid(count == length)
            return ContentFingerprint(count, digest.digest())
        }

        private fun requireValid(condition: Boolean) {
            if (!condition) throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
    }
}
