package eu.opencloud.android.next.feature.auth

import okhttp3.HttpUrl.Companion.toHttpUrl
import java.nio.ByteBuffer
import java.security.MessageDigest

/** Reuse a legacy ID only for its exact server/user owner, preserving existing local data. */
internal fun resolveAccountId(
    serverUrl: String,
    userId: String,
    savedIdentity: (String) -> Pair<String, String>?,
): String {
    val server = serverUrl.toHttpUrl().toString().trimEnd('/')
    val legacyId = "${serverUrl.lowercase()}#$userId"
    val previous = savedIdentity(legacyId)
    if (previous != null &&
        previous.first
            .toHttpUrl()
            .toString()
            .trimEnd('/') == server &&
        previous.second == userId
    ) {
        return legacyId
    }
    val digest = MessageDigest.getInstance("SHA-256")
    listOf(server, userId).forEach { value ->
        val bytes = value.toByteArray(Charsets.UTF_8)
        digest.update(ByteBuffer.allocate(Int.SIZE_BYTES).putInt(bytes.size).array())
        digest.update(bytes)
    }
    return "account-v2:" + digest.digest().joinToString("") { "%02x".format(it) }
}
