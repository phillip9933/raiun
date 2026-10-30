package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.network.DownloadExpectation
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.VaultIdentity
import java.io.InputStream
import java.io.OutputStream

/** Transformations always pass through the unlocked session's authenticated content streams. */
class VaultBoundaryEndpoint(
    private val session: VaultSession,
    location: VaultLocation,
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
                session.location.vaultPath.trim('/'),
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

    override suspend fun openDirectory(
        context: Context,
        path: String,
    ): BoundaryDirectorySnapshot =
        withBoundaryRequestCancellation(session::cancelBoundaryRequests) {
            session.openBoundaryDirectory(context, path)
        }

    override suspend fun openNameIndex(
        context: Context,
        path: String,
    ): BoundaryNameIndex =
        withBoundaryRequestCancellation(session::cancelBoundaryRequests) {
            session.openBoundaryNames(context, path)
        }

    override suspend fun openDestinationFolders(
        context: Context,
        path: String,
    ): BoundaryDestinationSnapshot =
        withBoundaryRequestCancellation(session::cancelBoundaryRequests) {
            session.openBoundaryDestinationFolders(context, path)
        }

    override suspend fun containsName(
        path: String,
        name: String,
    ): Boolean =
        withBoundaryRequestCancellation(session::cancelBoundaryRequests) {
            session.hasBoundaryChild(path, name)
        }

    override suspend fun requireUnchanged(entry: BoundaryEntry) {
        withBoundaryRequestCancellation(session::cancelBoundaryRequests) {
            session.withBoundaryEntry(entry) { Unit }
        }
    }

    override suspend fun read(
        entry: BoundaryEntry,
        sink: OutputStream,
    ) {
        withBoundaryRequestCancellation(session::cancelBoundaryRequests) {
            if (DownloadExpectation(entry.size, entry.version).strongETag == null) {
                throw OpenCloudException(OpenCloudError.PreconditionFailed)
            }
            session.readBoundary(entry, sink)
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
            session.uploadBoundary(parent, name, source, size, mimeType).asBoundaryEntry()
        }

    override suspend fun createDirectory(
        parent: String,
        name: String,
    ): BoundaryEntry =
        withBoundaryRequestCancellation(session::cancelBoundaryRequests) {
            childPath(parent, name)
            if (session.hasBoundaryChild(parent, name)) throw OpenCloudException(OpenCloudError.Conflict)
            session.createFolder(parent, name).asBoundaryEntry()
        }

    override suspend fun delete(entry: BoundaryEntry) {
        withBoundaryRequestCancellation(session::cancelBoundaryRequests) {
            session.withBoundaryEntry(entry) { current ->
                if (entry.directory && session.hasBoundaryChild(entry.path)) {
                    throw OpenCloudException(OpenCloudError.PreconditionFailed)
                }
                if (entry.directory) {
                    // Reissue only the SAME version captured before the complete empty proof.
                    session.withBoundaryEntry(current.asBoundaryEntry()) { issued ->
                        if (issued.strongETag != current.strongETag) {
                            throw OpenCloudException(OpenCloudError.PreconditionFailed)
                        }
                        session.delete(issued)
                    }
                } else {
                    session.delete(current)
                }
            }
            val parent = entry.path.substringBeforeLast('/', "")
            if (session.hasBoundaryChild(parent, entry.name)) {
                throw OpenCloudException(OpenCloudError.PreconditionFailed)
            }
        }
    }
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
