package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.IncomingShareEntity
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.SharedFolderResolution
import java.security.MessageDigest

/** Local scope is distinct from the server drive. Never register this as access to the whole drive. */
class SharedFolderLocation private constructor(
    private val share: IncomingShareEntity,
    val scopeId: String,
    private val server: SharedFolderResolution.Resolved,
) {
    val accountId get() = share.accountId
    val shareId get() = share.id
    val serverDriveId get() = server.driveId
    val rootItemId get() = server.itemId
    val rootWebDavUrl get() = server.webDavUrl
    val name get() = share.name
    val access get() = server.access
    val hidden: Boolean get() =
        kotlinx.serialization.json
            .Json { ignoreUnknownKeys = true }
            .decodeFromString<eu.opencloud.android.next.core.network.IncomingSharedItem>(share.metadataJson)
            .hidden

    fun parentPath(path: String): String? {
        requireSharedPath(path)
        return if (path == "/") null else path.substringBeforeLast('/').ifEmpty { "/" }
    }

    companion object {
        internal fun from(checked: CheckedShareAccess): SharedFolderLocation {
            val resolved =
                checked.resolution as? SharedFolderResolution.Resolved
                    ?: throw OpenCloudException(OpenCloudError.AccessDenied)
            if (!checked.share.isFolder || !resolved.access.canBrowse) {
                throw OpenCloudException(OpenCloudError.AccessDenied)
            }
            val share = checked.share
            val identity = listOf(share.accountId, share.id, resolved.driveId, resolved.itemId, resolved.webDavUrl)
            val digest = MessageDigest.getInstance("SHA-256")
            identity.forEach { value ->
                val bytes = value.toByteArray(Charsets.UTF_8)
                digest.update("${bytes.size}:".toByteArray(Charsets.UTF_8))
                digest.update(bytes)
            }
            val scope = "shared-folder:" + digest.digest().joinToString("") { "%02x".format(it) }
            return SharedFolderLocation(share, scope, resolved)
        }
    }
}

/** Paths are decoded, root-relative names. URL encoding belongs to the DAV client, never to navigation. */
internal fun requireSharedPath(path: String) {
    if (path == "/") return
    val segments = path.split('/').drop(1)
    if (!path.startsWith('/') || segments.isEmpty() || segments.any { invalidSharedSegment(it) }) {
        throw OpenCloudException(OpenCloudError.PreconditionFailed)
    }
}

private fun invalidSharedSegment(segment: String): Boolean =
    segment.isBlank() ||
        segment in setOf(".", "..") ||
        segment.any { it == '\\' || it.code < 32 || it.code == 127 }
