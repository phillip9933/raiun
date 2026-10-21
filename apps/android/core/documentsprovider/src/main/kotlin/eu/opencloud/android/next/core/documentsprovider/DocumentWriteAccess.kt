package eu.opencloud.android.next.core.documentsprovider

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.model.resourceCacheDirectory
import eu.opencloud.android.next.core.model.validatedCachedFile
import eu.opencloud.android.next.core.network.DownloadExpectation
import java.io.File

/** Editing starts only from a validated local version; server preconditions protect the eventual upload. */
internal class DocumentWriteAccess(
    private val context: Context,
    private val store: FileBrowserStore,
) {
    fun editable(resource: ResourceEntity): Boolean =
        resource.kind == ResourceKind.FILE && DownloadExpectation(resource.sizeBytes, resource.eTag).strongETag != null

    fun original(resource: ResourceEntity): File? {
        if (!editable(resource)) return null
        return validatedCachedFile(
            resourceCacheDirectory(context.filesDir, resource.accountId, resource.spaceId),
            resource.localPath?.takeIf { resource.hasLocalCopy },
            resource.sizeBytes,
        )
    }

    suspend fun prepare(
        expected: ResourceEntity,
        permit: () -> Boolean,
        download: suspend (ResourceEntity) -> Unit,
    ): File {
        check(editable(expected) && authorized(expected, permit)) { "Document editing is unavailable or locked." }
        if (original(expected) == null) download(expected)
        check(authorized(expected, permit)) { "The document changed or access was revoked." }
        val current = requireNotNull(store.resource(expected.accountId, expected.spaceId, expected.remoteId))
        return original(current) ?: throw java.io.FileNotFoundException("The document download did not complete.")
    }

    suspend fun authorized(
        expected: ResourceEntity,
        permit: () -> Boolean,
    ): Boolean {
        if (!permit() || store.account(expected.accountId)?.isActive != true) return false
        val space = store.space(expected.accountId, expected.spaceId)
        val available = space != null && !space.isDeleted && !space.isDisabled
        val current = store.resource(expected.accountId, expected.spaceId, expected.remoteId)
        val sameFile = current?.takeIf { it.kind == ResourceKind.FILE }?.let { sameVersion(expected, it) } == true
        return available && sameFile && permit()
    }

    private fun sameVersion(
        expected: ResourceEntity,
        current: ResourceEntity,
    ): Boolean =
        current.path == expected.path && current.eTag == expected.eTag && current.sizeBytes == expected.sizeBytes
}
