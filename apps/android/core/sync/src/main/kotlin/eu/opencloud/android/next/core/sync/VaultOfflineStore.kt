package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.crypto.RcloneVaultCipher
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.VaultOfflineGroups
import eu.opencloud.android.next.core.database.vaultOfflineGroups
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.AccountSessions
import eu.opencloud.android.next.core.security.AppLock
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Explicit, read-only offline snapshots. Child metadata and original ciphertext never enter Room. */
@Suppress("LongParameterList") // Injectable filesystem, lease and publication seam for deterministic revocation tests.
class VaultOfflineStore internal constructor(
    private val root: File,
    private val accountFor: suspend (String) -> AccountEntity?,
    private val permitFor: () -> () -> Boolean,
    private val endpoints: EndpointPolicy,
    private val cipherFromMaterial: (ByteArray) -> VaultCipherEngine,
    private val credentialLeaseFor: (String) -> () -> Boolean = { { true } },
    private val beforePublication: () -> Unit = {},
    private val afterPublication: () -> Unit = {},
    private val publicationAccepted: suspend (String, VaultIdentity) -> Boolean = { _, _ -> false },
    durability: OfflineDurability = OfflineDurability(root),
    private val groupPublications: (() -> VaultOfflineGroups)? = null,
) {
    constructor(context: Context) : this(
        root = File(context.noBackupFilesDir, "vault-offline"),
        durability = OfflineDurability(context.noBackupFilesDir),
        groupPublications = {
            FileBrowserStore(
                FileBrowserDatabase.create(context.applicationContext),
            ).vaultOfflineGroups()
        },
        accountFor = { accountId ->
            FileBrowserStore(FileBrowserDatabase.create(context.applicationContext)).account(accountId)
        },
        permitFor = { AppLock(context.applicationContext).beginAppAction() },
        endpoints = EndpointPolicy(),
        cipherFromMaterial = { RcloneVaultCipher.fromKeyMaterial(it).offlineEngine() },
        credentialLeaseFor = { accountId -> AccountSessions.get(context.applicationContext).beginLease(accountId) },
        publicationAccepted = { transferId, identity ->
            val row = FileBrowserStore(FileBrowserDatabase.create(context.applicationContext)).transfer(transferId)
            row?.state == "SUCCEEDED" &&
                row.locationKind == "VAULT" &&
                row.direction == "DOWNLOAD" &&
                row.accountId == identity.accountId &&
                row.spaceId == identity.driveId &&
                row.sourceUri == "vault-offline:${identity.remoteVaultId}"
        },
    )

    private val ownership = VaultOfflineOwnership(root, durability)

    internal val groupAccess by lazy {
        VaultOfflineGroupAccess(
            ownership,
            cipherFromMaterial,
            { identity ->
                requireAccount(identity.accountId, identity.canonicalServer)
                Unit
            },
            { account ->
                val lock = permitFor()
                val credentials = credentialLeaseFor(account)
                val combined: () -> Boolean = { lock() && credentials() }
                combined
            },
            ::recoverPublication,
            ::pinDirectory,
            beforePublication,
            afterPublication,
        )
    }

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
            val accountDir = ownership.accountDirectory(accountId)
            if (ownership.accountRevoked(accountId) || VaultOfflineRevocations.accountBlocked(accountId)) {
                return@withContext emptyList()
            }
            val result =
                accountDir.listFiles().orEmpty().mapNotNull { directory ->
                    if (!directory.isDirectory || !manifestExists(File(directory, MANIFEST))) return@mapNotNull null
                    val catalog = File(directory, CATALOG)
                    val location =
                        runCatching {
                            decodeLocation(
                                readOfflineMetadata(catalog, MAX_CATALOG_BYTES, durability = ownership.durability),
                            )
                        }.getOrNull()
                    location
                        ?.takeIf {
                            it.accountId == accountId &&
                                it.canonicalServer == canonicalServer &&
                                ownership.vaultDirectory(identityOf(it)) == directory &&
                                !ownership.identityRevoked(identityOf(it)) &&
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
            !ownership.accountRevoked(identity.accountId) &&
                !ownership.identityRevoked(identity) &&
                !VaultOfflineRevocations.accountBlocked(identity.accountId) &&
                !VaultOfflineRevocations.identityBlocked(identity) &&
                manifestExists(File(ownership.vaultDirectory(identity), MANIFEST))
        }

    /** Caller supplies a fresh, authenticated live entry and copies its original DAV ciphertext. */
    @Suppress("LongParameterList", "CyclomaticComplexMethod", "LongMethod", "TooGenericExceptionCaught")
    // Authentication, durable publication and rollback must share one identity mutex; cleanup covers cancellation too.
    internal suspend fun pinFile(
        identity: VaultIdentity,
        location: VaultLocation,
        entry: VaultFolder,
        keyMaterial: ByteArray,
        additionalPermit: () -> Boolean = { true },
        commitPublication: suspend () -> Boolean = { true },
        publicationId: String? = null,
        copyCiphertext: (OutputStream) -> Unit,
    ) = withContext(Dispatchers.IO) {
        requireLocation(identity, location)
        requireAccount(identity.accountId, identity.canonicalServer)
        require(!entry.isFolder && entry.size >= 32L)
        requireScopedEntry(location, entry)
        val lockPermit = permitFor()
        val credentialLease = credentialLeaseFor(identity.accountId)
        val permit = { lockPermit() && credentialLease() && additionalPermit() }
        if (!permit()) throw OpenCloudException(OpenCloudError.AccessDenied)
        val context = currentCoroutineContext()
        val accountGeneration = VaultOfflineRevocations.accountGeneration(identity.accountId)
        val identityGeneration = VaultOfflineRevocations.identityGeneration(identity)
        ownership.publicationLockFor(identity.accountId).withLock {
            ownership.lockFor(identity).withLock {
                recoverPublication(identity, location)
                ownership.prepareForPin(identity)
                val directory = ownership.vaultDirectory(identity)
                val blobs = File(directory, BLOBS)
                check(
                    !java.nio.file.Files
                        .isSymbolicLink(blobs.toPath()),
                )
                if (!blobs.isDirectory && !blobs.mkdirs()) throw OpenCloudException(OpenCloudError.Unsupported)
                val manifestFile = File(directory, MANIFEST)
                val catalogFile = File(directory, CATALOG)
                val previousManifest =
                    manifestFile.takeIf(::manifestExists)?.let {
                        readOfflineMetadata(
                            it,
                            MAX_MANIFEST_BYTES + 32,
                            durability = ownership.durability,
                        )
                    }
                val previousCatalog =
                    catalogFile
                        .takeIf(
                            ::manifestExists,
                        )?.let { readOfflineMetadata(it, MAX_CATALOG_BYTES, durability = ownership.durability) }
                val stage = File.createTempFile(STAGE_PREFIX, ".ciphertext", blobs)
                VaultOfflineStoreStageRegistry.active += stage.canonicalPath
                var published: File? = null
                var publishedPath: String? = null
                var provisional = false
                var localCommitAttempted = false
                var journal: VaultOfflinePublicationJournal? = null
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
                    authenticateOfflineCiphertext(stage, keyMaterial, cipherFromMaterial) {
                        checkPinActive(context, permit, identity, accountGeneration, identityGeneration)
                    }
                    val digest =
                        sha256File(stage) {
                            checkPinActive(context, permit, identity, accountGeneration, identityGeneration)
                        }
                    val manifest = ownership.readManifestOrEmpty(identity, location, keyMaterial)
                    try {
                        val blobId = UUID.randomUUID().toString()
                        val target = File(blobs, blobId)
                        if (!stage.renameTo(target)) throw OpenCloudException(OpenCloudError.Unsupported)
                        published = target
                        publishedPath = target.canonicalPath
                        VaultOfflineStoreStageRegistry.active += target.canonicalPath
                        ownership.durability.syncParents(blobs)
                        val cached = cachedEntry(entry, blobId, digest)
                        val updated = manifest.withEntryAndAncestors(location, cached)
                        requireAccount(identity.accountId, identity.canonicalServer)
                        checkPinActive(context, permit, identity, accountGeneration, identityGeneration)
                        beforePublication()
                        val nextManifest =
                            VaultOfflineIndex.prepare(
                                directory,
                                identity,
                                location,
                                keyMaterial,
                                updated,
                                durability = ownership.durability,
                            ) {
                                checkPinActive(context, permit, identity, accountGeneration, identityGeneration)
                            }
                        val recovery =
                            VaultOfflinePublicationJournal(
                                publicationId ?: UUID.randomUUID().toString(),
                                blobId,
                                manifest
                                    .find(entry.encryptedPath) {
                                        checkPinActive(context, permit, identity, accountGeneration, identityGeneration)
                                    }?.blobId,
                                encodeLocation(location).toByteArray(StandardCharsets.UTF_8),
                                previousManifest,
                                previousCatalog,
                                nextManifestDigest = hex(sha256(nextManifest)),
                                localCommitted = if (publicationId == null) false else null,
                            )
                        journal = recovery
                        provisional = true
                        VaultOfflineRevocations.clearIfUnchanged(identity, accountGeneration, identityGeneration) {
                            checkPinActive(context, permit, identity, accountGeneration, identityGeneration)
                            recovery.write(directory, ownership.durability)
                            ownership.durability.writeAtomic(manifestFile, nextManifest)
                            ownership.writeCatalog(directory, location)
                            ownership.clearRevocationMarkers(identity)
                        }
                        // Room decides ownership while the identity mutex keeps provisional bytes from new readers.
                        // A committed CAS must be observed even if the caller is cancelled during its suspension.
                        withContext(NonCancellable) {
                            afterPublication()
                            checkPinActive(context, permit, identity, accountGeneration, identityGeneration)
                            if (!commitPublication()) throw OpenCloudException(OpenCloudError.AccessDenied)
                            if (publicationId == null) {
                                localCommitAttempted = true
                                recovery.commitLocal(directory, ownership.durability)
                            }
                            provisional = false
                            published = null
                        }
                        recovery.finish(directory, accepted = true, durability = ownership.durability)
                        VaultOfflineStoreStageRegistry.active -= target.canonicalPath
                    } finally {
                        manifest.close()
                    }
                    ownership.readManifest(identity, location, keyMaterial).use {
                        pruneVaultOfflineOrphanBlobs(
                            directory,
                            it,
                            ownership.durability,
                        ) { checkPinActive(context, permit, identity, accountGeneration, identityGeneration) }
                    }
                    cleanupIndexes(directory)
                } catch (failure: Throwable) {
                    if (localCommitAttempted) {
                        // The commit-receipt directory sync may be ambiguous. Keep both generations/blobs
                        // and let the persisted PREPARED/COMMITTED receipt decide on recovery.
                        published = null
                    } else if (provisional) {
                        try {
                            VaultOfflineRevocations.runIfUnchanged(identity, accountGeneration, identityGeneration) {
                                journal?.restore(directory, ownership.durability)
                                journal?.finish(directory, accepted = false, durability = ownership.durability)
                            }
                        } catch (rollbackFailure: Exception) {
                            // Keep the new blob if durable metadata could still reference it after failed restoration.
                            published = null
                            throw OpenCloudException(OpenCloudError.LocalStorageWriteFailed).apply {
                                initCause(rollbackFailure)
                                addSuppressed(failure)
                            }
                        }
                    }
                    throw failure
                } finally {
                    stage.delete()
                    VaultOfflineStoreStageRegistry.active -= stage.canonicalPath
                    published?.let {
                        it.delete()
                    }
                    // The final path is no longer active even when rollback had to retain its ciphertext.
                    publishedPath?.let { VaultOfflineStoreStageRegistry.active -= it }
                    // Cleanup must never conceal the original publication/storage error.
                    runCatching { cleanupIndexes(directory) }
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
        additionalPermit: () -> Boolean = { true },
    ) = withContext(Dispatchers.IO) {
        requireLocation(identity, location)
        requireAccount(identity.accountId, identity.canonicalServer)
        requireScopedPath(location, encryptedPath, allowRoot = true)
        val lockPermit = permitFor()
        val credentialLease = credentialLeaseFor(identity.accountId)
        val permit = { lockPermit() && credentialLease() && additionalPermit() }
        if (!permit()) throw OpenCloudException(OpenCloudError.AccessDenied)
        val context = currentCoroutineContext()
        val accountGeneration = VaultOfflineRevocations.accountGeneration(identity.accountId)
        val identityGeneration = VaultOfflineRevocations.identityGeneration(identity)
        ownership.lockFor(identity).withLock {
            recoverPublication(identity, location)
            ownership.prepareForPin(identity)
            val directory = ownership.vaultDirectory(identity)
            if (!directory.isDirectory && !directory.mkdirs()) throw OpenCloudException(OpenCloudError.Unsupported)
            val manifest = ownership.readManifestOrEmpty(identity, location, keyMaterial)
            try {
                checkPinActive(context, permit, identity, accountGeneration, identityGeneration)
                val nextManifest =
                    VaultOfflineIndex.prepare(
                        directory,
                        identity,
                        location,
                        keyMaterial,
                        manifest.withDirectoryAndAncestors(location, encryptedPath),
                        durability = ownership.durability,
                    ) {
                        checkPinActive(context, permit, identity, accountGeneration, identityGeneration)
                    }
                requireAccount(identity.accountId, identity.canonicalServer)
                beforePublication()
                ownership.publishLocalMetadata(identity, location, nextManifest) {
                    checkPinActive(context, permit, identity, accountGeneration, identityGeneration)
                }
            } finally {
                manifest.close()
                // Failed preparation/publication must not strand a generation or hide the original error.
                runCatching { cleanupIndexes(directory) }
            }
            cleanupIndexes(directory)
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
        val context = currentCoroutineContext()
        val accountGeneration = VaultOfflineRevocations.accountGeneration(identity.accountId)
        val identityGeneration = VaultOfflineRevocations.identityGeneration(identity)
        val checkActive = { checkPinActive(context, permit, identity, accountGeneration, identityGeneration) }
        ownership.lockFor(identity).withLock {
            recoverPublication(identity, location)
            val manifest = ownership.readManifest(identity, location, keyMaterial)
            try {
                var stale = false

                fun retain(entry: OfflineEntry): Boolean {
                    val inside =
                        encryptedRoot.isEmpty() ||
                            entry.encryptedPath == encryptedRoot ||
                            entry.encryptedPath.startsWith("$encryptedRoot/")
                    return !inside || entry.encryptedPath in seen
                }
                manifest.visit(checkActive) { if (!retain(it)) stale = true }
                if (!stale) return@withLock
                requireAccount(identity.accountId, identity.canonicalServer)
                if (!permit()) throw OpenCloudException(OpenCloudError.AccessDenied)
                val nextManifest =
                    VaultOfflineIndex.prepare(
                        ownership.vaultDirectory(identity),
                        identity,
                        location,
                        keyMaterial,
                        manifest.retaining(::retain),
                        durability = ownership.durability,
                        checkActive = checkActive,
                    )
                requireAccount(identity.accountId, identity.canonicalServer)
                beforePublication()
                ownership.publishLocalMetadata(identity, location, nextManifest, checkActive)
            } finally {
                manifest.close()
                runCatching { cleanupIndexes(ownership.vaultDirectory(identity)) }
            }
            ownership
                .readManifest(
                    identity,
                    location,
                    keyMaterial,
                ).use {
                    pruneVaultOfflineOrphanBlobs(
                        ownership.vaultDirectory(identity),
                        it,
                        ownership.durability,
                        checkActive,
                    )
                }
            cleanupIndexes(ownership.vaultDirectory(identity))
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
    suspend fun openWithKeyMaterial(
        accountId: String,
        location: VaultLocation,
        keyMaterial: ByteArray,
    ): VaultOfflineSession? {
        var opened: VaultOfflineSession? = null
        var delivered = false
        try {
            val result =
                withContext(Dispatchers.IO) {
                    openOfflineSession(accountId, location, keyMaterial).also { opened = it }
                }
            delivered = true
            return result
        } finally {
            // withContext can cancel at dispatcher delivery after the session acquired a key/reader lease.
            if (!delivered) opened?.close()
        }
    }

    @Suppress("CyclomaticComplexMethod", "ComplexCondition", "ThrowsCount", "TooGenericExceptionCaught")
    // Every failed construction must close/wipe keys, including cancellation and native allocation errors.
    private suspend fun openOfflineSession(
        accountId: String,
        location: VaultLocation,
        keyMaterial: ByteArray,
    ): VaultOfflineSession? {
        if (location.accountId != accountId) throw OpenCloudException(OpenCloudError.PreconditionFailed)
        val identity = identityOf(location)
        requireLocation(identity, location)
        val account = requireAccount(accountId, identity.canonicalServer)
        if (ownership.accountRevoked(accountId) ||
            ownership.identityRevoked(identity) ||
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
        val context = currentCoroutineContext()
        val checkActive = { checkPinActive(context, permit, identity, accountGeneration, identityGeneration) }
        return ownership.lockFor(identity).withLock {
            recoverPublication(identity, location)
            val directory = ownership.vaultDirectory(identity)
            if (!manifestExists(File(directory, MANIFEST))) return@withLock null
            val manifest = ownership.readManifest(identity, location, keyMaterial)
            try {
                manifest.visit(checkActive) {}
                if (!permit() ||
                    accountGeneration != VaultOfflineRevocations.accountGeneration(accountId) ||
                    identityGeneration != VaultOfflineRevocations.identityGeneration(identity) ||
                    ownership.accountRevoked(accountId) ||
                    ownership.identityRevoked(identity) ||
                    VaultOfflineRevocations.accountBlocked(accountId) ||
                    VaultOfflineRevocations.identityBlocked(identity) ||
                    accountFor(accountId) != account
                ) {
                    throw OpenCloudException(OpenCloudError.AccessDenied)
                }
                // Cleanup can use metadata only after the complete authenticated membership barrier.
                pruneVaultOfflineOrphanBlobs(directory, manifest, ownership.durability, checkActive)
                cleanupIndexes(directory)
                checkActive()
                val cipher = cipherFromMaterial(keyMaterial)
                val copiedMaterial = keyMaterial.copyOf()
                try {
                    VaultOfflineSession(
                        identity = identity,
                        location = location.copy(offlineOnly = true),
                        directory = directory,
                        manifest = manifest,
                        cipher = cipher,
                        keyMaterial = copiedMaterial,
                        permit = permit,
                        accountAtOpen = account,
                        accountFor = accountFor,
                        endpoints = endpoints,
                        accountGeneration = accountGeneration,
                        identityGeneration = identityGeneration,
                        committedAccess =
                            VaultOfflineCommittedAccess(ownership, identity, location) {
                                recoverPublication(identity, location)
                            },
                    )
                } catch (failure: Throwable) {
                    copiedMaterial.fill(0)
                    cipher.close()
                    throw failure
                }
            } catch (failure: Throwable) {
                manifest.close()
                throw failure
            }
        }
    }

    suspend fun remove(identity: VaultIdentity): Unit =
        withContext(Dispatchers.IO) {
            VaultOfflineRevocations.revoke(identity)
            ownership.durability.writeAtomic(ownership.identityTombstone(identity), byteArrayOf(1))
            ownership.lockFor(identity).withLock {
                ownership.deleteOwnedTree(ownership.vaultDirectory(identity))
            }
            VaultOfflineRevocations.finishRevoke(identity)
        }

    /** Account removal may call this after the account row is gone. */
    fun forgetAccount(accountId: String) {
        VaultOfflineRevocations.revokeAccount(accountId)
        ownership.durability.writeAtomic(ownership.accountTombstone(accountId), byteArrayOf(1))
        ownership.deleteOwnedTree(ownership.accountDirectory(accountId))
        VaultOfflineRevocations.finishAccountRevoke(accountId)
    }

    /** History deletion and publication share the account lock before either acquires an identity lock. */
    internal suspend fun mutateTransferHistory(
        accountId: String,
        mutation: suspend () -> Unit,
    ) {
        ownership.publicationLockFor(accountId).withLock {
            recoverPendingPublications(accountId)
            mutation()
        }
    }

    /** Reconcile before durable transfer rows are removed; readers also recover under the same mutex. */
    internal suspend fun recoverPendingPublications(accountId: String? = null) =
        withContext(Dispatchers.IO) {
            scanOfflinePublications(
                root,
                accountId?.let(ownership::accountDirectory),
                ownership::directoryLock,
            ) { directory, journal ->
                val location = decodeLocation(journal.locationDescriptor)
                val identity = identityOf(location)
                if (directory.canonicalFile != ownership.vaultDirectory(identity).canonicalFile) {
                    throw OpenCloudException(OpenCloudError.DownloadIntegrity)
                }
                recoverPublication(identity, location)
            }
        }

    private suspend fun recoverPublication(
        identity: VaultIdentity,
        location: VaultLocation,
        groupAuthority: VaultOfflineGroups? = null,
    ) {
        recoverOfflinePublication(
            ownership,
            identity,
            location,
            groupAuthority ?: groupPublications?.invoke(),
            {
                requireAccount(identity.accountId, identity.canonicalServer)
                Unit
            },
            publicationAccepted,
        )
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

    private fun cleanupIndexes(directory: File) {
        // Keep every prepared generation until a pending publication has an authoritative decision.
        if (VaultOfflinePublicationJournal.read(directory) != null) return
        val roots = mutableListOf<ByteArray>()
        File(directory, MANIFEST).takeIf(::manifestExists)?.let {
            roots +=
                readOfflineMetadata(it, MAX_MANIFEST_BYTES + 32, durability = ownership.durability)
        }
        VaultOfflineIndex.cleanup(directory, roots)
    }

    private companion object {
        const val MANIFEST = "manifest.enc"
        const val CATALOG = "root.json"
        const val BLOBS = "blobs"
        const val STAGE_PREFIX = "staging-"
        const val MAX_CATALOG_BYTES = 64 * 1024
    }
}

private fun VaultOfflineOwnership.readManifestOrEmpty(
    identity: VaultIdentity,
    location: VaultLocation,
    material: ByteArray,
): OfflineManifest =
    if (manifestExists(File(vaultDirectory(identity), "manifest.enc"))) {
        readManifest(identity, location, material)
    } else {
        LegacyOfflineManifest(emptyMap())
    }

private fun VaultOfflineOwnership.readManifest(
    identity: VaultIdentity,
    location: VaultLocation,
    material: ByteArray,
): OfflineManifest =
    readOfflineManifest(
        File(vaultDirectory(identity), "manifest.enc"),
        identity,
        location,
        material,
        durability = durability,
    )

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

private fun identityOf(location: VaultLocation) =
    VaultIdentity(location.accountId, location.canonicalServer, location.driveId, location.remoteVaultId)

internal fun requireLocation(
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

internal fun identityBytes(identity: VaultIdentity): ByteArray =
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

private fun manifestExists(file: File): Boolean = file.isFile || File(file.path + ".bak").isFile

private fun removeAbandonedStages(root: File) {
    forEachPrivateDirectory(root) { account ->
        forEachPrivateDirectory(account) { vault ->
            val blobs = File(vault, "blobs")
            if (blobs.isDirectory &&
                !java.nio.file.Files
                    .isSymbolicLink(blobs.toPath())
            ) {
                java.nio.file.Files.newDirectoryStream(blobs.toPath(), "staging-*").use { paths ->
                    for (path in paths) {
                        val file = path.toFile()
                        if (file.canonicalPath !in VaultOfflineStoreStageRegistry.active) file.delete()
                    }
                }
            }
        }
    }
}

private fun forEachPrivateDirectory(
    root: File,
    consume: (File) -> Unit,
) {
    if (!root.isDirectory ||
        java.nio.file.Files
            .isSymbolicLink(root.toPath())
    ) {
        return
    }
    java.nio.file.Files.newDirectoryStream(root.toPath()).use { paths ->
        for (path in paths) {
            if (java.nio.file.Files
                    .isDirectory(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)
            ) {
                consume(path.toFile())
            }
        }
    }
}

internal fun pruneVaultOfflineOrphanBlobs(
    directory: File,
    manifest: OfflineManifest,
    durability: OfflineDurability,
    checkActive: () -> Unit,
) {
    val root = readOfflineMetadata(File(directory, "manifest.enc"), MAX_MANIFEST_BYTES + 32, durability)
    if (VaultOfflineIndex.previousGenerationInUse(directory, root)) return
    val table = File.createTempFile("reachability-", ".db", directory)
    try {
        android.database.sqlite.SQLiteDatabase.openOrCreateDatabase(table, null).use { database ->
            database.execSQL("CREATE TABLE blobs (id TEXT PRIMARY KEY)")
            manifest.visit(checkActive) { entry ->
                entry.blobId?.let { blob ->
                    database.insertWithOnConflict(
                        "blobs",
                        null,
                        android.content.ContentValues().apply {
                            put("id", blob)
                        },
                        android.database.sqlite.SQLiteDatabase.CONFLICT_IGNORE,
                    )
                }
            }
            // The visitor must finish before any content is removed.
            removeUnreferencedBlobs(directory, database, checkActive)
        }
    } finally {
        listOf(
            table,
            File(table.path + "-journal"),
            File(table.path + "-wal"),
            File(table.path + "-shm"),
        ).forEach(File::delete)
    }
}

private fun removeUnreferencedBlobs(
    directory: File,
    references: android.database.sqlite.SQLiteDatabase,
    checkActive: () -> Unit,
) {
    val blobs = File(directory, "blobs")
    if (!blobs.isDirectory) return
    java.nio.file.Files.newDirectoryStream(blobs.toPath()).use { paths ->
        for (path in paths) {
            checkActive()
            val file = path.toFile()
            if (!isPrunableBlob(file)) continue
            val referenced =
                references
                    .rawQuery(
                        "SELECT 1 FROM blobs WHERE id = ?",
                        arrayOf(file.name),
                    ).use { it.moveToFirst() }
            if (!referenced) file.delete()
        }
    }
}

private fun isPrunableBlob(file: File): Boolean =
    file.isFile &&
        !file.name.startsWith("staging-") &&
        file.canonicalPath !in VaultOfflineStoreStageRegistry.active &&
        !VaultOfflineIndex.blobInUse(file)

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

    /** Restoration must never recreate files after a concurrent account or vault removal. */
    @Synchronized fun runIfUnchanged(
        identity: VaultIdentity,
        accountGeneration: Long,
        identityGeneration: Long,
        action: () -> Unit,
    ) {
        if (!changedSince(identity, accountGeneration, identityGeneration)) action()
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

internal fun encodeLocation(location: VaultLocation): String =
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

internal fun decodeLocation(bytes: ByteArray): VaultLocation =
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

// Every malformed manifest field fails closed before a snapshot opens.
@Suppress("CyclomaticComplexMethod", "ThrowsCount")
private fun decodeManifest(
    bytes: ByteArray,
    location: VaultLocation,
    directory: File,
    rootDigest: String,
): OfflineManifest {
    val json = JSONObject(VaultOfflineIndexCodec.text(bytes))
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
        validateOfflineEntry(entry, location)
        if (entries.put(entry.encryptedPath, entry) != null) throw OpenCloudException(OpenCloudError.InvalidResponse)
    }
    return LegacyOfflineManifest(entries, directory, rootDigest)
}

@Suppress("ThrowsCount") // Reject scope/name, folder payload and invalid file payload before issuing metadata.
internal fun validateOfflineEntry(
    entry: OfflineEntry,
    location: VaultLocation,
) {
    requireScopedPath(location, entry.encryptedPath, allowRoot = false)
    if (entry.rawName !=
        entry.encryptedPath.substringAfterLast('/')
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
        ) = authenticatedVaultContent { this@offlineEngine.decryptContent(input, output, maximumPlaintextBytes) }

        override fun exportKeyMaterial() = this@offlineEngine.exportKeyMaterial()

        override fun close() = this@offlineEngine.close()
    }

private const val MAX_MANIFEST_BYTES = 16 * 1024 * 1024
private val MAGIC = byteArrayOf(0x52, 0x56, 0x4f, 0x31) // RVO1

@Suppress("ThrowsCount") // Malformed headers and both authentication failure types must fail closed.
internal fun readOfflineManifest(
    file: File,
    identity: VaultIdentity,
    location: VaultLocation,
    material: ByteArray,
    durability: OfflineDurability = OfflineDurability(requireNotNull(file.parentFile)),
): OfflineManifest {
    val encrypted = readOfflineMetadata(file, MAX_MANIFEST_BYTES + 32, durability)
    if (VaultOfflineIndex.recognizes(encrypted)) {
        return try {
            VaultOfflineIndex.open(file.parentFile!!, identity, location, material, encrypted)
        } finally {
            encrypted.fill(0)
        }
    }
    if (encrypted.size < 32 || !encrypted.copyOfRange(0, 4).contentEquals(MAGIC)) {
        throw OpenCloudException(OpenCloudError.InvalidResponse)
    }
    val legacyRootDigest = hex(sha256(encrypted))
    val nonce = encrypted.copyOfRange(4, 16)
    val key = deriveManifestKey(material, identity)
    val plain =
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            cipher.updateAAD(identityBytes(identity))
            cipher.doFinal(encrypted, 16, encrypted.size - 16)
        } catch (_: GeneralSecurityException) {
            throw OpenCloudException(OpenCloudError.EncryptedUnlockFailed)
        } catch (_: IllegalArgumentException) {
            throw OpenCloudException(OpenCloudError.EncryptedUnlockFailed)
        } finally {
            key.fill(0)
            nonce.fill(0)
            encrypted.fill(0)
        }
    return try {
        decodeManifest(plain, location, file.parentFile!!, legacyRootDigest)
    } finally {
        plain.fill(0)
    }
}
