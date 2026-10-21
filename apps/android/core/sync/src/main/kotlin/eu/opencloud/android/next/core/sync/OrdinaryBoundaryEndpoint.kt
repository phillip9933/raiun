package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.VaultExclusionDao
import eu.opencloud.android.next.core.network.DownloadExpectation
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.RemoteDiscoveryClient
import eu.opencloud.android.next.core.network.RemoteFolderSnapshot
import eu.opencloud.android.next.core.network.RemoteResource
import eu.opencloud.android.next.core.network.TransferClient
import eu.opencloud.android.next.core.network.VaultDavClient
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import okhttp3.HttpUrl.Companion.toHttpUrl
import java.io.FilterInputStream
import java.io.FilterOutputStream
import java.io.InputStream
import java.io.OutputStream

/** Ordinary mutations retain the same account/root/exclusion checks as encrypted discovery. */
internal class OrdinaryBoundaryEndpoint(
    private val access: VaultAccess,
    private val location: VaultLocation,
    private val exclusions: VaultExclusionDao,
    private val requireRoot: suspend () -> Unit,
    endpoints: EndpointPolicy = EndpointPolicy(),
) : BoundaryEndpoint {
    override val identity = "ordinary:${location.accountId}:${location.canonicalServer}:${location.driveId}"
    override val encrypted = false
    override val physicalScope = "${location.accountId}:${location.canonicalServer}:${location.driveId}"
    private val discovery = RemoteDiscoveryClient(access.http)
    private val transfer = TransferClient(access.http)
    private val dav = VaultDavClient(access.http, endpoints = endpoints)

    override suspend fun existingNames(path: String): Set<String> {
        val snapshot = readSnapshot(path)
        return snapshot.resources.map { it.name }.toSet() +
            snapshot.excludedVaultPaths.map { it.trimEnd('/').substringAfterLast('/') }
    }

    override suspend fun list(path: String): List<BoundaryEntry> {
        val snapshot = readSnapshot(path)
        // A recursive ordinary copy must not silently omit an encrypted child.
        if (snapshot.excludedVaultPaths.isNotEmpty()) throw OpenCloudException(OpenCloudError.AccessDenied)
        return snapshot.resources.map(RemoteResource::asBoundaryEntry)
    }

    private suspend fun readSnapshot(path: String): RemoteFolderSnapshot {
        guard(path)
        val snapshot =
            withBoundaryRequestCancellation({ access.http.dispatcher.cancelAll() }) {
                discovery.folderSnapshot(location.rootWebDavUrl, path, access.authorization)
            }
        access.requireCurrent()
        return snapshot
    }

    private fun RemoteFolderSnapshot.requireOrdinaryTarget(path: String) {
        if (excludedVaultPaths.any {
                it.trim(
                    '/',
                ) == path.trim('/')
            }
        ) {
            throw OpenCloudException(OpenCloudError.AccessDenied)
        }
    }

    override suspend fun requireUnchanged(entry: BoundaryEntry) {
        if (entry.directory &&
            exclusions.denies(location.accountId, location.driveId, "/${entry.path.trim('/')}", true)
        ) {
            throw OpenCloudException(OpenCloudError.AccessDenied)
        }
        val current = find(entry.path)
        if (!sameBoundaryEntry(entry, current)) throw OpenCloudException(OpenCloudError.PreconditionFailed)
    }

    override suspend fun read(
        entry: BoundaryEntry,
        sink: OutputStream,
    ) {
        requireUnchanged(entry)
        requireVersion(entry)
        val coroutine = currentCoroutineContext()
        withBoundaryRequestCancellation(transfer::cancelRequests) {
            transfer.download(
                url(entry.path),
                access.authorization,
                0,
                DownloadExpectation(entry.size, entry.version),
            ) { input, _, _ ->
                val guarded =
                    object : FilterOutputStream(sink) {
                        override fun write(
                            bytes: ByteArray,
                            offset: Int,
                            length: Int,
                        ) {
                            coroutine.ensureActive()
                            if (!access.permit()) throw OpenCloudException(OpenCloudError.AccessDenied)
                            out.write(bytes, offset, length)
                        }

                        override fun write(value: Int) = write(byteArrayOf(value.toByte()), 0, 1)
                    }
                input.copyTo(guarded, 64 * 1024)
            }
        }
        access.requireCurrent()
    }

    override suspend fun write(
        parent: String,
        name: String,
        source: InputStream,
        size: Long,
        mimeType: String?,
    ): BoundaryEntry {
        val path = childPath(parent, name)
        guard(parent)
        guard(path)
        val coroutine = currentCoroutineContext()
        val guarded =
            object : FilterInputStream(source) {
                override fun read(
                    bytes: ByteArray,
                    offset: Int,
                    length: Int,
                ): Int {
                    coroutine.ensureActive()
                    if (!access.permit()) throw OpenCloudException(OpenCloudError.AccessDenied)
                    return super.read(bytes, offset, length)
                }

                override fun read(): Int {
                    coroutine.ensureActive()
                    if (!access.permit()) throw OpenCloudException(OpenCloudError.AccessDenied)
                    return super.read()
                }
            }
        withBoundaryRequestCancellation(transfer::cancelRequests) {
            transfer.upload(url(path), access.authorization, mimeType, size, false, { guarded }, onProgress = {})
        }
        access.requireCurrent()
        return find(path)
    }

    override suspend fun createDirectory(
        parent: String,
        name: String,
    ): BoundaryEntry {
        val path = childPath(parent, name)
        guard(parent)
        guard(path)
        val snapshot = readSnapshot(parent)
        snapshot.requireOrdinaryTarget(path)
        if (snapshot.resources.any { it.name == name }) throw OpenCloudException(OpenCloudError.Conflict)
        withBoundaryRequestCancellation({ access.http.dispatcher.cancelAll() }) {
            dav.createCollection(location.rootWebDavUrl, path, access.authorization)
        }
        access.requireCurrent()
        return find(path)
    }

    override suspend fun delete(entry: BoundaryEntry) {
        val current = find(entry.path)
        if (!sameBoundaryEntry(entry, current)) throw OpenCloudException(OpenCloudError.PreconditionFailed)
        if (entry.directory &&
            list(entry.path).isNotEmpty()
        ) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
        // Capture the current version BEFORE proving emptiness; a subsequent addition must invalidate this ETag.
        requireVersion(current)
        withBoundaryRequestCancellation({ access.http.dispatcher.cancelAll() }) {
            dav.deleteResource(
                location.rootWebDavUrl,
                current.path,
                access.authorization,
                requireNotNull(current.version),
            )
        }
        access.requireCurrent()
        val remaining = readSnapshot(current.path.substringBeforeLast('/', ""))
        if (remaining.resources.any { it.path.trim('/') == current.path.trim('/') }) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
    }

    private suspend fun find(path: String): BoundaryEntry {
        val snapshot = readSnapshot(path.substringBeforeLast('/', ""))
        snapshot.requireOrdinaryTarget(path)
        return snapshot.resources.singleOrNull { it.path.trim('/') == path.trim('/') }?.asBoundaryEntry()
            ?: throw OpenCloudException(OpenCloudError.PreconditionFailed)
    }

    private suspend fun guard(path: String) {
        validateBoundaryPath(path)
        access.requireCurrent()
        withBoundaryRequestCancellation({ access.http.dispatcher.cancelAll() }) { requireRoot() }
        if (exclusions.denies(location.accountId, location.driveId, "/${path.trim('/')}", false)) {
            throw OpenCloudException(OpenCloudError.AccessDenied)
        }
    }

    private fun url(path: String): String =
        location.rootWebDavUrl
            .toHttpUrl()
            .newBuilder()
            .apply {
                path
                    .trim('/')
                    .split('/')
                    .filter(String::isNotEmpty)
                    .forEach(::addPathSegment)
            }.build()
            .toString()
}

private fun RemoteResource.asBoundaryEntry() = BoundaryEntry(id, path.trim('/'), name, folder, size, eTag, mimeType)

internal fun childPath(
    parent: String,
    name: String,
): String {
    val validName = name.isNotBlank() && name !in setOf(".", "..")
    val invalidCharacter = name.any { it == '/' || it == '\\' || it.isISOControl() }
    if (!validName || invalidCharacter) throw OpenCloudException(OpenCloudError.InvalidResponse)
    return listOf(parent.trim('/'), name).filter(String::isNotEmpty).joinToString("/").also(::validateBoundaryPath)
}

private fun validateBoundaryPath(path: String) {
    val invalidSegments =
        path.trim('/').split('/').any { segment ->
            val invalidCharacter = segment.any { it == '\\' || it.isISOControl() }
            segment in setOf(".", "..") || invalidCharacter
        }
    if (path.length > 4096 || invalidSegments) throw OpenCloudException(OpenCloudError.InvalidResponse)
}

private fun requireVersion(entry: BoundaryEntry) {
    if (DownloadExpectation(entry.size, entry.version).strongETag ==
        null
    ) {
        throw OpenCloudException(OpenCloudError.PreconditionFailed)
    }
}
