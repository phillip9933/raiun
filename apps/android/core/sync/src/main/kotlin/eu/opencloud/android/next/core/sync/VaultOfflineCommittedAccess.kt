package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.sync.withLock
import java.io.File
import java.security.MessageDigest

/** A current session never acquires a provisional root while its publisher is awaiting a decision. */
internal class VaultOfflineCommittedAccess(
    private val ownership: VaultOfflineOwnership,
    private val identity: VaultIdentity,
    private val location: VaultLocation,
    private val recover: suspend () -> Unit,
) {
    @Suppress("TooGenericExceptionCaught") // An acquired generation lease must close on cancellation too.
    suspend fun snapshot(material: ByteArray, checkActive: () -> Unit): Pair<OfflineManifest, String> {
        checkActive()
        return ownership.lockFor(identity).withLock {
            checkActive()
            recover()
            checkActive()
            val before = readDigest()
            val file = File(ownership.vaultDirectory(identity), "manifest.enc")
            val manifest = readOfflineManifest(file, identity, location, material, ownership.durability)
            try {
                checkActive()
                if (before != readDigest()) throw OpenCloudException(OpenCloudError.PreconditionFailed)
                manifest to before
            } catch (failure: Throwable) {
                manifest.close()
                throw failure
            }
        }
    }

    suspend fun authenticatedAnchorDigest(
        material: ByteArray,
        checkActive: () -> Unit,
    ): String? {
        checkActive()
        return ownership.lockFor(identity).withLock {
            checkActive()
            recover()
            checkActive()
            val file = File(ownership.vaultDirectory(identity), "manifest.enc")
            if (!file.isFile && !File(file.path + ".bak").isFile) return@withLock null
            val before = readDigest()
            val cached = boundOfflineCatalog(ownership.vaultDirectory(identity), location, ownership.durability)
            readOfflineManifest(file, identity, cached, material, ownership.durability).use {
                it.visit(checkActive) {}
            }
            checkActive()
            if (before != readDigest()) throw OpenCloudException(OpenCloudError.OfflineSnapshotChanged)
            before
        }
    }

    suspend fun digest(checkActive: () -> Unit): String {
        checkActive()
        return ownership.lockFor(identity).withLock {
            checkActive()
            recover()
            checkActive()
            readDigest().also { checkActive() }
        }
    }

    private fun readDigest(): String {
        val file = File(ownership.vaultDirectory(identity), "manifest.enc")
        val bytes = readOfflineMetadata(file, 16 * 1024 * 1024 + 32, ownership.durability)
        return try {
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        } finally {
            bytes.fill(0)
        }
    }
}
