package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.VaultDavEntry
import eu.opencloud.android.next.core.network.VaultDavListing
import eu.opencloud.android.next.core.security.VaultIdentity
import java.io.Closeable
import java.util.concurrent.atomic.AtomicBoolean

/** Borrowed live transport/cipher; only the exported preparation material and directory snapshots are owned. */
@Suppress("LongParameterList") // Every callback is bound to the same captured session and caller permit.
internal class VaultOfflineGroupSource(
    private val context: Context,
    val identity: VaultIdentity,
    val location: VaultLocation,
    val selected: VaultDavEntry,
    val rootProofDigest: String?,
    private val material: ByteArray,
    private val validateRoot: suspend () -> Unit,
    private val checkSession: () -> Unit,
    private val decryptName: (String) -> String,
    private val stream: suspend (String, Int, (VaultDavEntry) -> Unit) -> VaultDavListing,
) : Closeable {
    private val closed = AtomicBoolean()

    fun checkActive() {
        if (closed.get()) throw OpenCloudException(OpenCloudError.AccessDenied)
        checkSession()
    }

    suspend fun requireCurrent() {
        checkActive()
        validateRoot()
        checkActive()
    }

    /** Raw fields are kept exactly: ciphertext spelling and size must not round-trip through plaintext. */
    suspend fun openDirectory(expected: VaultDavEntry): BoundaryDirectorySnapshot {
        checkActive()
        requireSelectedScope(expected)
        return captureBoundaryDirectory(context, expected.relativePath, guard = { requireCurrent() }) { emit ->
            val listing =
                stream(expected.relativePath, 1) { raw ->
                    checkActive()
                    requireOrdinaryGroupChild(raw)
                    val name = decryptName(raw.rawName)
                    // Reuse the existing name and ciphertext-framing proof, without issuing a UI lease.
                    VaultFolder(
                        raw.id,
                        name,
                        raw.rawName,
                        name,
                        raw.relativePath,
                        raw.isFolder,
                        raw.size,
                        raw.strongETag,
                    ).asBoundaryEntry()
                    emit(BoundaryEntry(raw.id, raw.relativePath, raw.rawName, raw.isFolder, raw.size, raw.strongETag))
                }
            requireGroupParent(expected, listing)
            requireCurrent()
        }
    }

    fun rawEntry(entry: BoundaryEntry): VaultDavEntry {
        checkActive()
        val raw =
            VaultDavEntry(
                entry.id,
                entry.path,
                entry.name,
                entry.directory,
                entry.size,
                entry.version,
                "",
            )
        requireSelectedScope(raw)
        if (raw.relativePath.isNotEmpty() && raw.rawName != raw.relativePath.substringAfterLast('/')) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
        return raw.copy(href = resolveEntryHref(location.rootWebDavUrl, entry.path))
    }

    suspend fun <T> withMaterial(block: suspend (ByteArray) -> T): T {
        checkActive()
        return block(material)
    }

    private fun requireSelectedScope(entry: VaultDavEntry) {
        val root = selected.relativePath.trimEnd('/')
        val inScope =
            entry.relativePath == root ||
                (root.isEmpty() || entry.relativePath.startsWith("$root/"))
        if (!inScope || !validGroupEncryptedPath(entry.relativePath)) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
    }

    private fun requireGroupParent(
        expected: VaultDavEntry,
        listing: VaultDavListing,
    ) {
        val parent = listing.root
        val nestedMarker =
            expected.relativePath != location.vaultPath &&
                (parent.isVaultMarker || listing.requestedIsVaultMarker)
        if (nestedMarker || !parent.isFolder) throw OpenCloudException(OpenCloudError.PreconditionFailed)
        val sameDescriptor =
            parent.id == expected.id &&
                parent.relativePath == expected.relativePath &&
                parent.rawName == expected.rawName
        if (!sameDescriptor) throw OpenCloudException(OpenCloudError.PreconditionFailed)
    }

    override fun close() {
        if (closed.compareAndSet(false, true)) material.fill(0)
    }
}

private fun requireOrdinaryGroupChild(raw: VaultDavEntry) {
    if (raw.isVaultMarker || (raw.isFolder && raw.rawName.endsWith(".vault"))) {
        throw OpenCloudException(OpenCloudError.PreconditionFailed)
    }
}

private fun validGroupEncryptedPath(path: String): Boolean =
    path.isEmpty() || path.split('/').all(::validGroupEncryptedSegment)

private fun validGroupEncryptedSegment(segment: String): Boolean {
    if (segment.isEmpty() || segment == "." || segment == "..") return false
    return '\\' !in segment && !segment.any(Char::isISOControl)
}
