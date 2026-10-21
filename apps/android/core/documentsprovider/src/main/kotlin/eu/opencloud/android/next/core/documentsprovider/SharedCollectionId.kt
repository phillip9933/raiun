package eu.opencloud.android.next.core.documentsprovider

import java.util.Base64

/** A navigation collection, never a grant covering every incoming share. */
internal data class SharedCollectionId(
    val account: String,
) {
    fun encode(): String {
        require(account.isNotBlank() && '\u0000' !in account)
        return (PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(account.toByteArray())).also {
            require(it.length <= 4096)
        }
    }

    companion object {
        private const val PREFIX = "shared-collection-v1:"

        fun recognizes(value: String): Boolean = value.startsWith(PREFIX)

        fun decode(value: String): SharedCollectionId {
            if (!recognizes(value) || value.length > 4096) unavailableSharedDocument()
            return try {
                SharedCollectionId(String(Base64.getUrlDecoder().decode(value.removePrefix(PREFIX)), Charsets.UTF_8))
                    .also { if (it.encode() != value) unavailableSharedDocument() }
            } catch (_: IllegalArgumentException) {
                unavailableSharedDocument()
            }
        }
    }
}
