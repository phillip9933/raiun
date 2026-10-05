package eu.opencloud.android.next.core.sync

import android.content.Context
import android.util.AtomicFile
import eu.opencloud.android.next.core.crypto.RcloneVaultCipher
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.AccountSessions
import eu.opencloud.android.next.core.security.AppLock
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Explicit, read-only offline snapshots. Child metadata and original ciphertext never enter Room. */
class VaultOfflineStore internal constructor(
    private val root: File,
    private val accountFor: suspend (String) -> AccountEntity?,
    private val permitFor: () -> () -> Boolean,
    private val endpoints: EndpointPolicy,
    private val cipherFromMaterial: (ByteArray) -> VaultCipherEngine,
    private val credentialLeaseFor: (String) -> () -> Boolean = { { true } },
) {
    constructor(context: Context) : this(
        root = File(context.noBackupFilesDir, "vault-offline"),
        accountFor = { accountId ->
            FileBrowserStore(FileBrowserDatabase.create(context.applicationContext)).account(accountId)
        },
        permitFor = { AppLock(context.applicationContext).beginAppAction() },
        endpoints = EndpointPolicy(),
        cipherFromMaterial = { RcloneVaultCipher.fromKeyMaterial(it).offlineEngine() },
        credentialLeaseFor = { accountId -> AccountSessions.get(context.applicationContext).beginLease(accountId) },
    )

    init {
        removeAbandonedStages(root)
    }

    /** Public root descriptors only; the result must be entered through an explicit offline action. */
    suspend fun locations(accountId: String): List<VaultLocation> =
        withContext(Dispatchers.IO) {
            val account = requireAccount(accountId)
            val credentialLease = credentialLeaseFor(accountId)
            if (!credentialLease()) throw OpenCloudException(OpenCloudError.AuthenticationRequired)
            val canonicalServer = endpoints.endpoint(account.serverUrl, allowQuery = false).toString()
            val accountDir = accountDirectory(accountId)
            if (accountRevoked(accountId) || VaultOfflineRevocations.accountBlocked(accountId)) {
                return@withContext emptyList()
            }
            val result =
                accountDir.listFiles().orEmpty().mapNotNull { directory ->
                    if (!directory.isDirectory || !File(directory, MANIFEST).exists()) return@mapNotNull null
                    val catalog = File(directory, CATALOG)
                    val location = runCatching { decodeLocation(readSmall(catalog, MAX_CATALOG_BYTES)) }.getOrNull()
                    location
                        ?.takeIf {
                            it.accountId == accountId &&
                                it.canonicalServer == canonicalServer &&
                                vaultDirectory(identityOf(it)) == directory &&
                                !identityRevoked(identityOf(it)) &&
                                !VaultOfflineRevocations.identityBlocked(identityOf(it))
                        }?.copy(offlineOnly = true)
                }
            if (!credentialLease() || VaultOfflineRevocations.accountBlocked(accountId)) {
                throw OpenCloudException(OpenCloudError.AuthenticationRequired)
            }
            result
        }

    suspend fun hasSnapshot(identity: VaultIdentity): Boolean =
        withContext(Dispatchers.IO) {
            requireAccount(identity.accountId, identity.canonicalServer)
            if (!credentialLeaseFor(
                    identity.accountId,
                )()
            ) {
                throw OpenCloudException(OpenCloudError.AuthenticationRequired)
            }
            !accountRevoked(identity.accountId) &&
                !identityRevoked(identity) &&
                !VaultOfflineRevocations.accountBlocked(identity.accountId) &&
                !VaultOfflineRevocations.identityBlocked(identity) &&
                File(vaultDirectory(identity), MANIFEST).exists()
        }

    /** Caller supplies a fresh, authenticated live entry and copies its original DAV ciphertext. */
    internal suspend fun pinFile(
        identity: VaultIdentity,
        location: VaultLocation,
        entry: VaultFolder,
        keyMaterial: ByteArray,
        copyCiphertext: (OutputStream) -> Unit,
    ) = withContext(Dispatchers.IO) {
        requireLocation(identity, location)
        requireAccount(identity.accountId, identity.canonicalServer)
        require(!entry.isFolder && entry.size >= 32L)
        requireScopedEntry(location, entry)
        val lockPermit = permitFor()
        val credentialLease = credentialLeaseFor(identity.accountId)
        val permit = { lockPermit() && credentialLease() }
        if (!permit()) throw OpenCloudException(OpenCloudError.AccessDenied)
        val context = currentCoroutineContext()
        val accountGeneration = VaultOfflineRevocations.accountGeneration(identity.accountId)
        val identityGeneration = VaultOfflineRevocations.identityGeneration(identity)
        lockFor(identity).withLock {
            prepareForPin(identity)
            val directory = vaultDirectory(identity)
            val blobs = File(directory, BLOBS)
            if (!blobs.isDirectory && !blobs.mkdirs()) throw OpenCloudException(OpenCloudError.Unsupported)
            val stage = File.createTempFile(STAGE_PREFIX, ".ciphertext", blobs)
            VaultOfflineStoreStageRegistry.active += stage.path
            var published: File? = null
            try {
                var written = 0L
                FileOutputStream(stage).use { file ->
                    val output =
                        object : OutputStream() {
                            override fun write(value: Int) {
                                checkPinActive(context, permit, identity, accountGeneration, identityGeneration)
                                file.write(value)
                                written = Math.addExact(written, 1L)
                            }

                            override fun write(
                                bytes: ByteArray,
                                offset: Int,
                                length: Int,
                            ) {
                                checkPinActive(context, permit, identity, accountGeneration, identityGeneration)
                                file.write(bytes, offset, length)
                                written = Math.addExact(written, length.toLong())
                            }
                        }
                    copyCiphertext(output)
                    file.fd.sync()
                }
                if (written != entry.size) throw OpenCloudException(OpenCloudError.InvalidResponse)
                checkPinActive(context, permit, identity, accountGeneration, identityGeneration)
                authenticateCiphertext(stage, keyMaterial)
                val digest =
                    sha256File(stage) {
                        checkPinActive(context, permit, identity, accountGeneration, identityGeneration)
                    }
                val manifest = readManifestOrEmpty(identity, location, keyMaterial)
                val blobId = UUID.randomUUID().toString()
                val target = File(blobs, blobId)
                if (!stage.renameTo(target)) throw OpenCloudException(OpenCloudError.Unsupported)
                published = target
                VaultOfflineStoreStageRegistry.active += target.path
                val cached = cachedEntry(entry, blobId, digest)
                val updated = manifest.withEntryAndAncestors(location, cached)
                requireAccount(identity.accountId, identity.canonicalServer)
                checkPinActive(context, permit, identity, accountGeneration, identityGeneration)
                writeManifest(identity, location, keyMaterial, updated)
                writeCatalog(directory, location)
                VaultOfflineRevocations.clearIfUnchanged(identity, accountGeneration, identityGeneration) {
                    clearRevocationMarkers(identity)
                }
                pruneOrphanBlobs(directory, updated)
                manifest.entries[entry.encryptedPath]?.blobId?.let { old ->
                    if (old != blobId) File(blobs, old).delete()
                }
                published = null
                VaultOfflineStoreStageRegistry.active -= target.path
            } finally {
                stage.delete()
                VaultOfflineStoreStageRegistry.active -= stage.path
                published?.let {
                    it.delete()
                    VaultOfflineStoreStageRegistry.active -= it.path
                }
            }
        }
    }

    /** Marks an empty directory as available and persists its encrypted ancestor path. */
    internal suspend fun pinDirectory(
        identity: VaultIdentity,
        location: VaultLocation,
        encryptedPath: String,
        keyMaterial: ByteArray,
    ) = withContext(Dispatchers.IO) {
        requireLocation(identity, location)
        requireAccount(identity.accountId, identity.canonicalServer)
        requireScopedPath(location, encryptedPath, allowRoot = true)
        val lockPermit = permitFor()
        val credentialLease = credentialLeaseFor(identity.accountId)
        val permit = { lockPermit() && credentialLease() }
        if (!permit()) throw OpenCloudException(OpenCloudError.AccessDenied)
        val context = currentCoroutineContext()
        val accountGeneration = VaultOfflineRevocations.accountGeneration(identity.accountId)
        val identityGeneration = VaultOfflineRevocations.identityGeneration(identity)
        lockFor(identity).withLock {
            prepareForPin(identity)
            val directory = vaultDirectory(identity)
            if (!directory.isDirectory && !directory.mkdirs()) throw OpenCloudException(OpenCloudError.Unsupported)
            val manifest = readManifestOrEmpty(identity, location, keyMaterial)
            checkPinActive(context, permit, identity, accountGeneration, identityGeneration)
            writeManifest(identity, location, keyMaterial, manifest.withDirectoryAndAncestors(location, encryptedPath))
            writeCatalog(directory, location)
            VaultOfflineRevocations.clearIfUnchanged(identity, accountGeneration, identityGeneration) {
                clearRevocationMarkers(identity)
            }
            pruneOrphanBlobs(directory, manifest)
        }
    }

    /** Removes stale children only after an explicit recursive pin completes successfully. */
    internal suspend fun pruneSubtree(
        identity: VaultIdentity,
        location: VaultLocation,
        encryptedRoot: String,
        seen: Set<String>,
        keyMaterial: ByteArray,
    ) = withContext(Dispatchers.IO) {
        requireLocation(identity, location)
        requireAccount(identity.accountId, identity.canonicalServer)
        requireScopedPath(location, encryptedRoot, allowRoot = true)
        val lockPermit = permitFor()
        val credentialLease = credentialLeaseFor(identity.accountId)
        val permit = { lockPermit() && credentialLease() }
        if (!permit()) throw OpenCloudException(OpenCloudError.AccessDenied)
        lockFor(identity).withLock {
            val manifest = readManifest(identity, location, keyMaterial)
            val stale =
                manifest.entries.values.filter { entry ->
                    (
                        encryptedRoot.isEmpty() ||
                            entry.encryptedPath == encryptedRoot ||
                            entry.encryptedPath.startsWith("$encryptedRoot/")
                    ) &&
                        entry.encryptedPath !in seen
                }
            if (stale.isEmpty()) return@withLock
            requireAccount(identity.accountId, identity.canonicalServer)
            if (!permit()) throw OpenCloudException(OpenCloudError.AccessDenied)
            val retained = manifest.entries - stale.map(OfflineEntry::encryptedPath).toSet()
            writeManifest(identity, location, keyMaterial, OfflineManifest(retained))
            stale.mapNotNull(OfflineEntry::blobId).forEach { File(File(vaultDirectory(identity), BLOBS), it).delete() }
        }
    }

    suspend fun openWithPassword(
        accountId: String,
        location: VaultLocation,
        password: CharArray,
    ): VaultOfflineSession? {
        val material =
            try {
                RcloneVaultCipher.fromPassword(password).use { it.exportKeyMaterial() }
            } finally {
                password.fill('\u0000')
            }
        return try {
            openWithKeyMaterial(accountId, location, material)
        } finally {
            material.fill(0)
        }
    }

    /** Caller-owned key material is copied briefly, with independent checks beside authentication. */
    @Suppress("CyclomaticComplexMethod", "ComplexCondition")
    suspend fun openWithKeyMaterial(
        accountId: String,
        location: VaultLocation,
        keyMaterial: ByteArray,
    ): VaultOfflineSession? =
        withContext(Dispatchers.IO) {
            if (location.accountId != accountId) throw OpenCloudException(OpenCloudError.PreconditionFailed)
            val identity = identityOf(location)
            requireLocation(identity, location)
            val account = requireAccount(accountId, identity.canonicalServer)
            if (accountRevoked(accountId) ||
                identityRevoked(identity) ||
                VaultOfflineRevocations.accountBlocked(accountId) ||
                VaultOfflineRevocations.identityBlocked(identity)
            ) {
                throw OpenCloudException(OpenCloudError.AccessDenied)
            }
            val lockPermit = permitFor()
            val credentialLease = credentialLeaseFor(identity.accountId)
            val permit = { lockPermit() && credentialLease() }
            if (!permit()) throw OpenCloudException(OpenCloudError.AccessDenied)
            val accountGeneration = VaultOfflineRevocations.accountGeneration(accountId)
            val identityGeneration = VaultOfflineRevocations.identityGeneration(identity)
            val directory = vaultDirectory(identity)
            if (!File(directory, MANIFEST).exists()) return@withContext null
            val manifest = readManifest(identity, location, keyMaterial)
            if (!permit() ||
                accountGeneration != VaultOfflineRevocations.accountGeneration(accountId) ||
                identityGeneration != VaultOfflineRevocations.identityGeneration(identity) ||
                accountRevoked(accountId) ||
                identityRevoked(identity) ||
                VaultOfflineRevocations.accountBlocked(accountId) ||
                VaultOfflineRevocations.identityBlocked(identity) ||
                accountFor(accountId) != account
            ) {
                throw OpenCloudException(OpenCloudError.AccessDenied)
            }
            val cipher = cipherFromMaterial(keyMaterial)
            VaultOfflineSession(
                identity = identity,
                location = location.copy(offlineOnly = true),
                directory = directory,
                manifest = manifest,
                cipher = cipher,
                keyMaterial = keyMaterial.copyOf(),
                permit = permit,
                accountAtOpen = account,
                accountFor = accountFor,
                endpoints = endpoints,
                accountGeneration = accountGeneration,
                identityGeneration = identityGeneration,
            )
        }

    suspend fun remove(identity: VaultIdentity): Unit =
        withContext(Dispatchers.IO) {
            VaultOfflineRevocations.revoke(identity)
            writeAtomic(identityTombstone(identity), byteArrayOf(1))
            lockFor(identity).withLock {
                if (!vaultDirectory(identity).deleteRecursively()) {
                    throw OpenCloudException(OpenCloudError.Unsupported)
                }
            }
            VaultOfflineRevocations.finishRevoke(identity)
        }

    /** Account removal may call this after the account row is gone. */
    fun forgetAccount(accountId: String) {
        VaultOfflineRevocations.revokeAccount(accountId)
        writeAtomic(accountTombstone(accountId), byteArrayOf(1))
        if (!accountDirectory(accountId).deleteRecursively()) {
            throw OpenCloudException(OpenCloudError.Unsupported)
        }
        VaultOfflineRevocations.finishAccountRevoke(accountId)
    }

    private fun checkPinActive(
        context: kotlin.coroutines.CoroutineContext,
        permit: () -> Boolean,
        identity: VaultIdentity,
        accountGeneration: Long,
        identityGeneration: Long,
    ) {
        context.ensureActive()
        if (!permit() ||
            accountGeneration != VaultOfflineRevocations.accountGeneration(identity.accountId) ||
            identityGeneration != VaultOfflineRevocations.identityGeneration(identity)
        ) {
            throw OpenCloudException(OpenCloudError.AccessDenied)
        }
    }

    private suspend fun requireAccount(
        accountId: String,
        server: String? = null,
    ): AccountEntity {
        currentCoroutineContext().ensureActive()
        val account = accountFor(accountId) ?: throw OpenCloudException(OpenCloudError.AuthenticationRequired)
        if (!account.isActive ||
            (server != null && endpoints.endpoint(account.serverUrl, allowQuery = false).toString() != server)
        ) {
            throw OpenCloudException(OpenCloudError.AuthenticationRequired)
        }
        return account
    }

    private fun accountDirectory(accountId: String) =
        File(root, hex(sha256(accountId.toByteArray(StandardCharsets.UTF_8))))

    private fun vaultDirectory(identity: VaultIdentity) =
        File(accountDirectory(identity.accountId), hex(sha256(identityBytes(identity))))

    private fun accountTombstone(accountId: String) = File(root, "revoked-${accountDirectory(accountId).name}")

    private fun identityTombstone(identity: VaultIdentity) =
        File(accountDirectory(identity.accountId), "revoked-${vaultDirectory(identity).name}")

    private fun accountRevoked(accountId: String) = accountTombstone(accountId).exists()

    private fun identityRevoked(identity: VaultIdentity) = identityTombstone(identity).exists()

    private fun clearRevocationMarkers(identity: VaultIdentity) {
        listOf(accountTombstone(identity.accountId), identityTombstone(identity)).forEach { marker ->
            if (marker.exists() && !marker.delete()) throw OpenCloudException(OpenCloudError.Unsupported)
        }
    }

    @Suppress("ThrowsCount") // Revoked account and identity cleanup fail independently and fail closed.
    private fun prepareForPin(identity: VaultIdentity) {
        if (VaultOfflineRevocations.revokePending(identity)) throw OpenCloudException(OpenCloudError.AccessDenied)
        if (accountRevoked(identity.accountId) || VaultOfflineRevocations.accountBlocked(identity.accountId)) {
            if (!accountDirectory(
                    identity.accountId,
                ).deleteRecursively()
            ) {
                throw OpenCloudException(OpenCloudError.Unsupported)
            }
        } else if (identityRevoked(identity) || VaultOfflineRevocations.identityBlocked(identity)) {
            if (!vaultDirectory(identity).deleteRecursively()) throw OpenCloudException(OpenCloudError.Unsupported)
        }
    }

    private fun lockFor(identity: VaultIdentity): Mutex =
        locks.computeIfAbsent(vaultDirectory(identity).path) { Mutex() }

    private fun readManifestOrEmpty(
        identity: VaultIdentity,
        location: VaultLocation,
        material: ByteArray,
    ): OfflineManifest =
        if (File(vaultDirectory(identity), MANIFEST).exists()) {
            readManifest(identity, location, material)
        } else {
            OfflineManifest(emptyMap())
        }

    @Suppress("ThrowsCount") // Malformed headers and both authentication failure types must fail closed.
    private fun readManifest(
        identity: VaultIdentity,
        location: VaultLocation,
        material: ByteArray,
    ): OfflineManifest {
        val encrypted = readSmall(File(vaultDirectory(identity), MANIFEST), MAX_MANIFEST_BYTES + 32)
        if (encrypted.size < 32 || !encrypted.copyOfRange(0, 4).contentEquals(MAGIC)) {
            throw OpenCloudException(OpenCloudError.InvalidResponse)
        }
        val nonce = encrypted.copyOfRange(4, 16)
        val key = deriveManifestKey(material, identity)
        val plain =
            try {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
                cipher.updateAAD(identityBytes(identity))
                cipher.doFinal(encrypted, 16, encrypted.size - 16)
            } catch (_: GeneralSecurityException) {
                throw OpenCloudException(OpenCloudError.AccessDenied)
            } catch (_: IllegalArgumentException) {
                throw OpenCloudException(OpenCloudError.AccessDenied)
            } finally {
                key.fill(0)
                nonce.fill(0)
                encrypted.fill(0)
            }
        return try {
            decodeManifest(plain, location)
        } finally {
            plain.fill(0)
        }
    }

    private fun writeManifest(
        identity: VaultIdentity,
        location: VaultLocation,
        material: ByteArray,
        manifest: OfflineManifest,
    ) {
        val plain = encodeManifest(manifest, location)
        if (plain.size > MAX_MANIFEST_BYTES) throw OpenCloudException(OpenCloudError.Unsupported)
        val key = deriveManifestKey(material, identity)
        val nonce = ByteArray(12).also(SecureRandom()::nextBytes)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            cipher.updateAAD(identityBytes(identity))
            val sealed = cipher.doFinal(plain)
            try {
                writeAtomic(File(vaultDirectory(identity), MANIFEST), MAGIC + nonce + sealed)
            } finally {
                sealed.fill(0)
            }
        } finally {
            plain.fill(0)
            key.fill(0)
            nonce.fill(0)
        }
    }

    private fun writeCatalog(
        directory: File,
        location: VaultLocation,
    ) {
        val bytes = encodeLocation(location).toByteArray(StandardCharsets.UTF_8)
        if (bytes.size > MAX_CATALOG_BYTES) throw OpenCloudException(OpenCloudError.Unsupported)
        writeAtomic(File(directory, CATALOG), bytes)
    }

    private fun authenticateCiphertext(
        file: File,
        material: ByteArray,
    ) {
        cipherFromMaterial(material).use { cipher ->
            FileInputStream(file).use { cipher.decryptContent(it, DiscardOutputStream, Long.MAX_VALUE) }
        }
    }

    private companion object {
        const val MANIFEST = "manifest.enc"
        const val CATALOG = "root.json"
        const val BLOBS = "blobs"
        const val STAGE_PREFIX = "staging-"
        const val MAX_CATALOG_BYTES = 64 * 1024
        const val MAX_MANIFEST_BYTES = 16 * 1024 * 1024
        val MAGIC = byteArrayOf(0x52, 0x56, 0x4f, 0x31) // RVO1
        val locks = ConcurrentHashMap<String, Mutex>()
    }
}

internal data class OfflineEntry(
    val encryptedPath: String,
    val rawName: String,
    val id: String,
    val isFolder: Boolean,
    val size: Long,
    val etag: String?,
    val blobId: String?,
    val digest: String?,
)

internal data class OfflineManifest(
    val entries: Map<String, OfflineEntry>,
) {
    fun withEntryAndAncestors(
        location: VaultLocation,
        entry: OfflineEntry,
    ): OfflineManifest =
        withDirectoryAndAncestors(location, entry.encryptedPath.substringBeforeLast('/', ""))
            .let { OfflineManifest(it.entries + (entry.encryptedPath to entry)) }

    fun withDirectoryAndAncestors(
        location: VaultLocation,
        encryptedPath: String,
    ): OfflineManifest {
        val result = entries.toMutableMap()
        val root = location.vaultPath.trimEnd('/')
        if (encryptedPath == root) return OfflineManifest(result)
        val relative = if (root.isEmpty()) encryptedPath else encryptedPath.removePrefix("$root/")
        var parent = root
        relative.split('/').filter(String::isNotEmpty).forEach { segment ->
            parent = if (parent.isEmpty()) segment else "$parent/$segment"
            result.putIfAbsent(parent, OfflineEntry(parent, segment, "", true, 0L, null, null, null))
        }
        return OfflineManifest(result)
    }
}

private object DiscardOutputStream : OutputStream() {
    override fun write(value: Int) = Unit

    override fun write(
        buffer: ByteArray,
        offset: Int,
        length: Int,
    ) = Unit
}

private fun identityOf(location: VaultLocation) =
    VaultIdentity(location.accountId, location.canonicalServer, location.driveId, location.remoteVaultId)

private fun requireLocation(
    identity: VaultIdentity,
    location: VaultLocation,
) {
    if (identity != identityOf(location) || !location.isVaultRoot || location.isDisabled) {
        throw OpenCloudException(OpenCloudError.PreconditionFailed)
    }
}

private fun requireScopedEntry(
    location: VaultLocation,
    entry: VaultFolder,
) {
    requireScopedPath(location, entry.encryptedPath, allowRoot = false)
    if (entry.rawName != entry.encryptedPath.substringAfterLast('/')) {
        throw OpenCloudException(OpenCloudError.PreconditionFailed)
    }
}

private fun requireScopedPath(
    location: VaultLocation,
    encryptedPath: String,
    allowRoot: Boolean,
) {
    val root = location.vaultPath.trimEnd('/')
    val valid =
        encryptedPath == root &&
            allowRoot ||
            encryptedPath.startsWith(if (root.isEmpty()) "" else "$root/") &&
            encryptedPath != root &&
            encryptedPath.split('/').none { it.isEmpty() || it == "." || it == ".." || it.contains('\\') }
    if (!valid) throw OpenCloudException(OpenCloudError.PreconditionFailed)
}

private fun cachedEntry(
    entry: VaultFolder,
    blobId: String,
    digest: String,
) = OfflineEntry(entry.encryptedPath, entry.rawName, entry.id, false, entry.size, entry.strongETag, blobId, digest)

private fun identityBytes(identity: VaultIdentity): ByteArray =
    ByteArrayOutputStream().use { bytes ->
        java.io.DataOutputStream(bytes).use { out ->
            listOf(
                identity.accountId,
                identity.canonicalServer,
                identity.driveId,
                identity.remoteVaultId,
            ).forEach { field ->
                val value = field.toByteArray(StandardCharsets.UTF_8)
                out.writeInt(value.size)
                out.write(value)
            }
        }
        bytes.toByteArray()
    }

internal fun deriveManifestKey(
    material: ByteArray,
    identity: VaultIdentity,
): ByteArray {
    require(material.size == 80)
    val salt = "raiun-vault-offline-manifest-v1".toByteArray(StandardCharsets.US_ASCII)
    val info = identityBytes(identity)
    return try {
        hkdfSha256(material, salt, info, 32)
    } finally {
        salt.fill(0)
        info.fill(0)
    }
}

/** RFC 5869 HKDF-SHA256, exposed internally so its published vectors can guard this primitive. */
internal fun hkdfSha256(
    inputKeyMaterial: ByteArray,
    salt: ByteArray,
    info: ByteArray,
    outputLength: Int,
): ByteArray {
    require(outputLength in 1..(255 * 32))
    val effectiveSalt = if (salt.isEmpty()) ByteArray(32) else salt
    val extract = Mac.getInstance("HmacSHA256")
    extract.init(SecretKeySpec(effectiveSalt, "HmacSHA256"))
    val prk = extract.doFinal(inputKeyMaterial)
    val output = ByteArray(outputLength)
    var previous = ByteArray(0)
    var written = 0
    var complete = false
    try {
        var counter = 1
        while (written < outputLength) {
            val expand = Mac.getInstance("HmacSHA256")
            expand.init(SecretKeySpec(prk, "HmacSHA256"))
            expand.update(previous)
            expand.update(info)
            expand.update(counter.toByte())
            val block = expand.doFinal()
            previous.fill(0)
            previous = block
            val count = minOf(block.size, outputLength - written)
            block.copyInto(output, written, 0, count)
            written += count
            counter++
        }
        complete = true
        return output
    } finally {
        prk.fill(0)
        previous.fill(0)
        if (!complete) output.fill(0)
        if (effectiveSalt !== salt) effectiveSalt.fill(0)
    }
}

private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)

private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }

internal fun sha256File(
    file: File,
    checkActive: () -> Unit = {},
): String {
    val buffer = ByteArray(64 * 1024)
    try {
        val digest = MessageDigest.getInstance("SHA-256")
        updateDigestFromFile(file, buffer, digest, checkActive)
        return hex(digest.digest())
    } finally {
        buffer.fill(0)
    }
}

private fun updateDigestFromFile(
    file: File,
    buffer: ByteArray,
    digest: MessageDigest,
    checkActive: () -> Unit,
) {
    FileInputStream(file).use { input ->
        while (true) {
            checkActive()
            val count = input.read(buffer)
            if (count < 0) break
            digest.update(buffer, 0, count)
        }
    }
}

@Suppress("TooGenericExceptionCaught") // AtomicFile must roll back on unchecked write failures too.
private fun writeAtomic(
    file: File,
    bytes: ByteArray,
) {
    file.parentFile?.mkdirs()
    val atomic = AtomicFile(file)
    val output = atomic.startWrite()
    try {
        output.write(bytes)
        atomic.finishWrite(output)
    } catch (failure: java.io.IOException) {
        atomic.failWrite(output)
        throw failure
    } catch (failure: RuntimeException) {
        atomic.failWrite(output)
        throw failure
    }
}

private fun readSmall(
    file: File,
    maximum: Int,
): ByteArray {
    if (!file.isFile || file.length() > maximum) throw OpenCloudException(OpenCloudError.InvalidResponse)
    return AtomicFile(file).openRead().use { input ->
        val bytes = input.readBytes()
        if (bytes.size > maximum) throw OpenCloudException(OpenCloudError.InvalidResponse)
        bytes
    }
}

private fun removeAbandonedStages(root: File) {
    root
        .listFiles()
        .orEmpty()
        .flatMap { it.listFiles().orEmpty().asList() }
        .flatMap { File(it, "blobs").listFiles().orEmpty().asList() }
        .filter { it.name.startsWith("staging-") && it.path !in VaultOfflineStoreStageRegistry.active }
        .forEach(File::delete)
}

private fun pruneOrphanBlobs(
    directory: File,
    manifest: OfflineManifest,
) {
    val referenced =
        manifest.entries.values
            .mapNotNull(OfflineEntry::blobId)
            .toSet()
    File(directory, "blobs")
        .listFiles()
        .orEmpty()
        .asSequence()
        .filter(File::isFile)
        .filterNot { it.name.startsWith("staging-") }
        .filterNot { it.name in referenced }
        .filterNot { it.path in VaultOfflineStoreStageRegistry.active }
        .forEach(File::delete)
}

private object VaultOfflineStoreStageRegistry {
    val active = ConcurrentHashMap.newKeySet<String>()
}

internal object VaultOfflineRevocations {
    private class State {
        val generation = AtomicLong()

        @Volatile var blocked = false

        @Volatile var pending = false
    }

    private val accounts = ConcurrentHashMap<String, State>()
    private val identities = ConcurrentHashMap<VaultIdentity, State>()

    private fun accountState(accountId: String) = accounts.computeIfAbsent(accountId) { State() }

    private fun identityState(identity: VaultIdentity) = identities.computeIfAbsent(identity) { State() }

    fun accountGeneration(accountId: String): Long = accountState(accountId).generation.get()

    fun identityGeneration(identity: VaultIdentity): Long = identityState(identity).generation.get()

    fun accountBlocked(accountId: String): Boolean = accountState(accountId).blocked

    fun identityBlocked(identity: VaultIdentity): Boolean = identityState(identity).blocked

    fun revokePending(identity: VaultIdentity): Boolean =
        accountState(identity.accountId).pending || identityState(identity).pending

    @Synchronized fun revokeAccount(accountId: String) {
        accountState(accountId).apply {
            blocked = true
            pending = true
            generation.incrementAndGet()
        }
    }

    @Synchronized fun revoke(identity: VaultIdentity) {
        identityState(identity).apply {
            blocked = true
            pending = true
            generation.incrementAndGet()
        }
    }

    @Synchronized fun finishAccountRevoke(accountId: String) {
        accountState(accountId).pending = false
    }

    @Synchronized fun finishRevoke(identity: VaultIdentity) {
        identityState(identity).pending = false
    }

    @Synchronized fun clearIfUnchanged(
        identity: VaultIdentity,
        accountGeneration: Long,
        identityGeneration: Long,
        clearMarkers: () -> Unit,
    ) {
        val account = accountState(identity.accountId)
        val vault = identityState(identity)
        if (changedSince(identity, accountGeneration, identityGeneration)) {
            throw OpenCloudException(OpenCloudError.AccessDenied)
        }
        clearMarkers()
        account.blocked = false
        vault.blocked = false
    }

    private fun changedSince(
        identity: VaultIdentity,
        accountGeneration: Long,
        identityGeneration: Long,
    ): Boolean {
        val account = accountState(identity.accountId)
        val vault = identityState(identity)
        return account.pending ||
            vault.pending ||
            account.generation.get() != accountGeneration ||
            vault.generation.get() != identityGeneration
    }
}

private fun encodeLocation(location: VaultLocation): String =
    JSONObject()
        .put("account", location.accountId)
        .put("title", location.title)
        .put("kind", location.kind.name)
        .put("drive", location.driveId)
        .put("vault", location.remoteVaultId)
        .put("sourceRoot", location.sourceRootId)
        .put("server", location.canonicalServer)
        .put("dav", location.rootWebDavUrl)
        .put("path", location.vaultPath)
        .toString()

private fun decodeLocation(bytes: ByteArray): VaultLocation =
    JSONObject(String(bytes, StandardCharsets.UTF_8)).let { json ->
        VaultLocation(
            accountId = json.getString("account"),
            title = json.getString("title"),
            kind = VaultLocationKind.valueOf(json.getString("kind")),
            driveId = json.getString("drive"),
            remoteVaultId = json.getString("vault"),
            sourceRootId = json.getString("sourceRoot"),
            canonicalServer = json.getString("server"),
            rootWebDavUrl = json.getString("dav"),
            vaultPath = json.getString("path"),
            isVaultRoot = true,
            offlineOnly = true,
        )
    }

/** Root-only descriptor codec shared with the separate app-private discovery catalog. */
internal fun encodeVaultRootDescriptor(location: VaultLocation): JSONObject = JSONObject(encodeLocation(location))

internal fun decodeVaultRootDescriptor(value: JSONObject): VaultLocation =
    decodeLocation(value.toString().toByteArray(StandardCharsets.UTF_8))

private fun encodeManifest(
    manifest: OfflineManifest,
    location: VaultLocation,
): ByteArray {
    val entries = JSONArray()
    manifest.entries.values.forEach { entry ->
        entries.put(
            JSONObject()
                .put("path", entry.encryptedPath)
                .put("name", entry.rawName)
                .put("id", entry.id)
                .put("folder", entry.isFolder)
                .put("size", entry.size)
                .put("etag", entry.etag)
                .put("blob", entry.blobId)
                .put("digest", entry.digest),
        )
    }
    return JSONObject()
        .put("version", 1)
        .put("location", encodeLocation(location))
        .put("entries", entries)
        .toString()
        .toByteArray(StandardCharsets.UTF_8)
}

// Every malformed manifest field fails closed before a snapshot opens.
@Suppress("CyclomaticComplexMethod", "ThrowsCount")
private fun decodeManifest(
    bytes: ByteArray,
    location: VaultLocation,
): OfflineManifest {
    val json = JSONObject(String(bytes, StandardCharsets.UTF_8))
    if (json.getInt("version") != 1 || json.getString("location") != encodeLocation(location)) {
        throw OpenCloudException(OpenCloudError.PreconditionFailed)
    }
    val array = json.getJSONArray("entries")
    val entries = mutableMapOf<String, OfflineEntry>()
    for (index in 0 until array.length()) {
        val item = array.getJSONObject(index)
        val entry =
            OfflineEntry(
                encryptedPath = item.getString("path"),
                rawName = item.getString("name"),
                id = item.getString("id"),
                isFolder = item.getBoolean("folder"),
                size = item.getLong("size"),
                etag = if (item.isNull("etag")) null else item.getString("etag"),
                blobId = if (item.isNull("blob")) null else item.getString("blob"),
                digest = if (item.isNull("digest")) null else item.getString("digest"),
            )
        requireScopedPath(location, entry.encryptedPath, allowRoot = false)
        if (entry.rawName != entry.encryptedPath.substringAfterLast('/') ||
            entries.put(entry.encryptedPath, entry) != null
        ) {
            throw OpenCloudException(OpenCloudError.InvalidResponse)
        }
        if (entry.isFolder) {
            if (entry.blobId != null || entry.digest != null) throw OpenCloudException(OpenCloudError.InvalidResponse)
        } else if (entry.size < 32L ||
            entry.blobId?.matches(Regex("[0-9a-fA-F-]{36}")) != true ||
            entry.digest?.matches(Regex("[0-9a-f]{64}")) != true
        ) {
            throw OpenCloudException(OpenCloudError.InvalidResponse)
        }
    }
    return OfflineManifest(entries)
}

internal fun RcloneVaultCipher.offlineEngine(): VaultCipherEngine =
    object : VaultCipherEngine {
        override fun createIntegrityToken() = this@offlineEngine.createIntegrityToken()

        override fun verifyIntegrityToken(base64Token: String) = this@offlineEngine.verifyIntegrityToken(base64Token)

        override fun decryptName(encrypted: String) = this@offlineEngine.decryptName(encrypted)

        override fun decryptPath(encrypted: String) = this@offlineEngine.decryptPath(encrypted)

        override fun encryptName(plain: String) = this@offlineEngine.encryptName(plain)

        override fun encryptPath(plain: String) = this@offlineEngine.encryptPath(plain)

        override fun encryptContent(
            input: java.io.InputStream,
            output: OutputStream,
            maximumPlaintextBytes: Long,
        ) = this@offlineEngine.encryptContent(input, output, maximumPlaintextBytes)

        override fun decryptContent(
            input: java.io.InputStream,
            output: OutputStream,
            maximumPlaintextBytes: Long,
        ) = this@offlineEngine.decryptContent(input, output, maximumPlaintextBytes)

        override fun exportKeyMaterial() = this@offlineEngine.exportKeyMaterial()

        override fun close() = this@offlineEngine.close()
    }
