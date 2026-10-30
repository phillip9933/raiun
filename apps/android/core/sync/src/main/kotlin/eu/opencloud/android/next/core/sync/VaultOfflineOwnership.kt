package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/** Canonical identity paths, shared mutexes and durable revocation markers for one private offline root. */
internal class VaultOfflineOwnership(
    private val root: File,
    val durability: OfflineDurability,
) {
    fun accountDirectory(accountId: String): File =
        durability.requireOwnedDirectory(File(root, hash(accountId.toByteArray(StandardCharsets.UTF_8))))

    fun vaultDirectory(identity: VaultIdentity): File =
        durability.requireOwnedDirectory(File(accountDirectory(identity.accountId), hash(identityBytes(identity))))

    fun accountTombstone(accountId: String): File = File(root, "revoked-${accountDirectory(accountId).name}")

    fun identityTombstone(identity: VaultIdentity): File =
        File(accountDirectory(identity.accountId), "revoked-${vaultDirectory(identity).name}")

    fun accountRevoked(accountId: String): Boolean = accountTombstone(accountId).exists()

    fun identityRevoked(identity: VaultIdentity): Boolean = identityTombstone(identity).exists()

    fun lockFor(identity: VaultIdentity): Mutex = directoryLock(vaultDirectory(identity))

    fun directoryLock(directory: File): Mutex = locks.computeIfAbsent(directory.canonicalPath) { Mutex() }

    fun publicationLockFor(accountId: String): Mutex =
        publicationLocks.computeIfAbsent(accountDirectory(accountId).canonicalPath) { Mutex() }

    fun clearRevocationMarkers(identity: VaultIdentity) {
        listOf(accountTombstone(identity.accountId), identityTombstone(identity)).forEach { marker ->
            if (marker.exists()) durability.deleteAtomic(marker)
        }
    }

    @Suppress("ThrowsCount") // Revoked account and identity cleanup fail independently and fail closed.
    fun prepareForPin(identity: VaultIdentity) {
        if (VaultOfflineRevocations.revokePending(identity)) throw OpenCloudException(OpenCloudError.AccessDenied)
        if (accountRevoked(identity.accountId) || VaultOfflineRevocations.accountBlocked(identity.accountId)) {
            deleteOwnedTree(accountDirectory(identity.accountId))
        } else if (identityRevoked(identity) || VaultOfflineRevocations.identityBlocked(identity)) {
            deleteOwnedTree(vaultDirectory(identity))
        }
    }

    fun deleteOwnedTree(directory: File) {
        val target = durability.requireOwnedDirectory(directory)
        val ownedRoot = durability.requireOwnedDirectory(root)
        if (target == ownedRoot || !target.toPath().startsWith(ownedRoot.toPath())) {
            throw IOException("Offline removal is outside its owned root")
        }
        if (Files.notExists(target.toPath(), LinkOption.NOFOLLOW_LINKS)) return
        deletePrivateTree(target.toPath())
        durability.syncParents(requireNotNull(target.parentFile))
    }

    private fun deletePrivateTree(path: Path) {
        if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
            Files.newDirectoryStream(path).use { children ->
                for (child in children) deletePrivateTree(child)
            }
        }
        // Symlinks themselves are removed; a descendant link never redirects recursive cleanup.
        Files.deleteIfExists(path)
    }

    @Suppress("TooGenericExceptionCaught") // Every failed provisional publication must restore, including cancellation.
    suspend fun publishLocalMetadata(
        identity: VaultIdentity,
        location: VaultLocation,
        nextManifest: ByteArray,
        checkActive: () -> Unit,
    ) {
        checkActive()
        val directory = vaultDirectory(identity)
        val previousManifest = previousMetadata(File(directory, "manifest.enc"), 16 * 1024 * 1024 + 32)
        val previousCatalog = previousMetadata(File(directory, "root.json"), 64 * 1024)
        val journal =
            VaultOfflinePublicationJournal(
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                null,
                encodeLocation(location).toByteArray(Charsets.UTF_8),
                previousManifest,
                previousCatalog,
                hash(nextManifest),
                localCommitted = false,
            )
        val accountGeneration = VaultOfflineRevocations.accountGeneration(identity.accountId)
        val identityGeneration = VaultOfflineRevocations.identityGeneration(identity)
        var commitAttempted = false
        try {
            journal.write(directory, durability)
            VaultOfflineRevocations.clearIfUnchanged(identity, accountGeneration, identityGeneration) {
                checkActive()
                durability.writeAtomic(File(directory, "manifest.enc"), nextManifest)
                writeCatalog(directory, location)
                clearRevocationMarkers(identity)
            }
            withContext(NonCancellable) {
                checkActive()
                commitAttempted = true
                journal.commitLocal(directory, durability)
            }
            journal.finish(directory, accepted = true, durability = durability)
        } catch (failure: Throwable) {
            if (!commitAttempted) {
                withContext(NonCancellable) {
                    VaultOfflineRevocations.runIfUnchanged(identity, accountGeneration, identityGeneration) {
                        journal.restore(directory, durability)
                        journal.finish(directory, accepted = false, durability = durability)
                    }
                }
            }
            throw failure
        }
    }

    fun writeCatalog(
        directory: File,
        location: VaultLocation,
    ) {
        val bytes = encodeLocation(location).toByteArray(StandardCharsets.UTF_8)
        if (bytes.size > (64 * 1024)) throw OpenCloudException(OpenCloudError.Unsupported)
        durability.writeAtomic(File(directory, "root.json"), bytes)
    }

    private fun previousMetadata(
        file: File,
        maximum: Int,
    ): ByteArray? =
        if (file.isFile ||
            File(file.path + ".bak").isFile
        ) {
            readOfflineMetadata(file, maximum, durability)
        } else {
            null
        }

    private fun hash(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private companion object {
        val locks = ConcurrentHashMap<String, Mutex>()
        val publicationLocks = ConcurrentHashMap<String, Mutex>()
    }
}
