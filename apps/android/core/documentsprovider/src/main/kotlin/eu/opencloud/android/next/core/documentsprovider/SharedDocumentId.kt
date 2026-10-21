package eu.opencloud.android.next.core.documentsprovider

import eu.opencloud.android.next.core.database.SharedFolderEntry
import eu.opencloud.android.next.core.database.SharedFolderScopeEntity
import eu.opencloud.android.next.core.sync.SharedDownloadFile
import eu.opencloud.android.next.core.sync.SharedDownloadRequest
import java.io.FileNotFoundException
import java.util.Base64

/** A shared scope is not an ordinary drive. No URL, private path or reusable access grant is encoded. */
internal data class SharedDocumentId(
    val account: String,
    val share: String,
    val scope: String,
    val remote: String,
) {
    fun encode(): String {
        val fields = listOf(account, share, scope, remote)
        require(fields.all { it.isNotBlank() && '\u0000' !in it })
        val encoded =
            PREFIX +
                Base64.getUrlEncoder().withoutPadding().encodeToString(
                    fields.joinToString("\u0000").toByteArray(Charsets.UTF_8),
                )
        require(encoded.length <= 4096)
        return encoded
    }

    fun request(
        binding: SharedFolderScopeEntity,
        entry: SharedFolderEntry,
    ): SharedDownloadRequest {
        val scopeMatches = binding.accountId == account && binding.scopeId == scope && binding.shareId == share
        val itemMatches = entry.accountId == account && entry.scopeId == scope && entry.remoteId == remote
        if (!scopeMatches || !itemMatches || entry.isFolder) unavailableSharedDocument()
        return SharedDownloadRequest(
            account,
            share,
            scope,
            SharedDownloadFile(remote, entry.path, entry.sizeBytes, entry.eTag),
        )
    }

    companion object {
        private const val PREFIX = "shared-v1:"

        fun recognizes(value: String): Boolean = value.startsWith(PREFIX)

        fun decode(value: String): SharedDocumentId {
            if (!recognizes(value) || value.length > 4096) unavailableSharedDocument()
            return try {
                val fields =
                    String(Base64.getUrlDecoder().decode(value.removePrefix(PREFIX)), Charsets.UTF_8)
                        .split('\u0000')
                if (fields.size != 4) unavailableSharedDocument()
                SharedDocumentId(fields[0], fields[1], fields[2], fields[3]).also {
                    if (it.encode() != value) unavailableSharedDocument()
                }
            } catch (_: IllegalArgumentException) {
                unavailableSharedDocument()
            }
        }
    }
}

internal fun unavailableSharedDocument(): Nothing = throw FileNotFoundException("Shared document unavailable.")
