package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.DownloadExpectation
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.VaultIdentity
import java.io.InputStream
import java.io.OutputStream

/** Transformations always pass through the unlocked session's authenticated content streams. */
class VaultBoundaryEndpoint(
    private val session: VaultSession,
    private val location: VaultLocation,
) : BoundaryEndpoint {
    override val identity =
        listOf(
            "vault",
            session.identity.accountId,
            session.identity.canonicalServer,
            session.identity.driveId,
            session.identity.remoteVaultId,
        ).joinToString(":")
    override val physicalScope =
        listOf(
            session.identity.accountId,
            session.identity.canonicalServer,
            session.identity.driveId,
        ).joinToString(":")
    override val encrypted = true

    init {
        val expected =
            VaultIdentity(location.accountId, location.canonicalServer, location.driveId, location.remoteVaultId)
        if (session.identity != expected) throw OpenCloudException(OpenCloudError.PreconditionFailed)
    }

    override suspend fun physicalPath(path: String): String =
        withBoundaryRequestCancellation(session::cancelBoundaryRequests) {
            listOf(
                location.vaultPath.trim('/'),
                session.encodeDirectoryPath(path),
            ).filter(String::isNotEmpty).joinToString("/")
        }

    override suspend fun list(path: String): List<BoundaryEntry> =
        withBoundaryRequestCancellation(session::cancelBoundaryRequests) {
            session.list(path).map { entry ->
                if (entry.isVaultRoot) throw OpenCloudException(OpenCloudError.AccessDenied)
                entry.asBoundaryEntry()
            }
        }

    override suspend fun requireUnchanged(entry: BoundaryEntry) {
        withBoundaryRequestCancellation(session::cancelBoundaryRequests) { find(entry) }
    }

    override suspend fun read(
        entry: BoundaryEntry,
        sink: OutputStream,
    ) {
        withBoundaryRequestCancellation(session::cancelBoundaryRequests) {
            val remote = find(entry)
            if (DownloadExpectation(entry.size, entry.version).strongETag ==
                null
            ) {
                throw OpenCloudException(OpenCloudError.PreconditionFailed)
            }
            session.download(remote, sink, Long.MAX_VALUE)
        }
    }

    override suspend fun write(
        parent: String,
        name: String,
        source: InputStream,
        size: Long,
        mimeType: String?,
    ): BoundaryEntry =
        withBoundaryRequestCancellation(session::cancelBoundaryRequests) {
            childPath(parent, name)
            // Conditional create protects races; a pre-upload list would invalidate a concurrently issued source token.
            session.upload(parent, name, source, size, mimeType).asBoundaryEntry()
        }

    override suspend fun createDirectory(
        parent: String,
        name: String,
    ): BoundaryEntry =
        withBoundaryRequestCancellation(session::cancelBoundaryRequests) {
            childPath(parent, name)
            if (list(parent).any { it.name == name }) throw OpenCloudException(OpenCloudError.Conflict)
            session.createFolder(parent, name).asBoundaryEntry()
        }

    override suspend fun delete(entry: BoundaryEntry) {
        withBoundaryRequestCancellation(session::cancelBoundaryRequests) {
            val current = find(entry)
            if (entry.directory &&
                list(entry.path).isNotEmpty()
            ) {
                throw OpenCloudException(OpenCloudError.PreconditionFailed)
            }
            // Listing clears issued tokens. Reissue only the SAME version proved before the empty listing.
            val issued = if (entry.directory) find(entry) else current
            if (issued.strongETag != current.strongETag) throw OpenCloudException(OpenCloudError.PreconditionFailed)
            session.delete(issued)
            if (session
                    .list(
                        entry.path.substringBeforeLast('/', ""),
                    ).any { it.path.trim('/') == entry.path.trim('/') }
            ) {
                throw OpenCloudException(OpenCloudError.PreconditionFailed)
            }
        }
    }

    private suspend fun find(expected: BoundaryEntry): VaultFolder =
        session.list(expected.path.substringBeforeLast('/', "")).singleOrNull {
            !it.isVaultRoot && sameBoundaryEntry(expected, it.asBoundaryEntry())
        } ?: throw OpenCloudException(OpenCloudError.PreconditionFailed)
}

fun VaultFolder.asBoundaryEntry(): BoundaryEntry =
    BoundaryEntry(
        id = id,
        path = path.trim('/'),
        name = name,
        directory = isFolder,
        size = if (isFolder) 0 else boundaryPlaintextSize(size),
        version = strongETag,
        mimeType = contentType,
    )

private fun boundaryPlaintextSize(ciphertextSize: Long): Long {
    if (ciphertextSize < 32) throw OpenCloudException(OpenCloudError.InvalidResponse)
    val payload = ciphertextSize - 32
    val remainder = payload % 65552
    if (remainder in 1..16) throw OpenCloudException(OpenCloudError.InvalidResponse)
    return (payload / 65552) * 65536 + if (remainder == 0L) 0 else remainder - 16
}
