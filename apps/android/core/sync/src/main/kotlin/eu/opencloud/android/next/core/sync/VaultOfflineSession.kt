package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FilterOutputStream
import java.io.OutputStream
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.coroutines.CoroutineContext

/** Read-only snapshot bound to identity, account/lock permits and revocation generations at open. */
@Suppress("LongParameterList")
class VaultOfflineSession internal constructor(
    val identity: VaultIdentity,
    val location: VaultLocation,
    private val directory: File,
    @Volatile private var manifest: OfflineManifest,
    private val cipher: VaultCipherEngine,
    private val keyMaterial: ByteArray,
    private val permit: () -> Boolean,
    private val accountAtOpen: AccountEntity,
    private val accountFor: suspend (String) -> AccountEntity?,
    private val endpoints: EndpointPolicy,
    private val accountGeneration: Long,
    private val identityGeneration: Long,
    private val committedAccess: VaultOfflineCommittedAccess,
) : AutoCloseable {
    private val closed = AtomicBoolean(false)
    private val exported = AtomicBoolean(false)
    private val issuedEntries = ConcurrentHashMap<String, VaultFolder>()

    private val directoryGeneration = AtomicLong()
    private val stateLock = Any()
    private var directoryIndex: VaultDirectoryIndex? = null

    @Volatile private var manifestDigest = sha256File(File(directory, "manifest.enc"))

    /** Authenticates the current manifest before sorting any child names into private staging. */
    suspend fun openDirectory(
        path: String = "",
        showHidden: Boolean = false,
        excludedPath: String? = null,
    ): VaultDirectorySnapshot {
        val epoch = invalidateDirectorySnapshot()
        var staged: VaultDirectoryIndex? = null
        var delivered = false
        try {
            val snapshot =
                withContext(Dispatchers.IO) {
                    requireAccess()
                    refreshCurrentManifest()
                    val context = currentCoroutineContext()
                    val parent = joinEncrypted(location.vaultPath, cipher.encryptPath(path))
                    val excluded = validateVaultExcludedPath(excludedPath)
                    val index = VaultDirectoryIndex(directory) { checkActive(context) }
                    staged = index
                    val (retained, digest) = retainManifestState()
                    retained.use { current ->
                        current.visit({ checkActive(context) }) { cached ->
                            stageCachedChild(index, cached, path, parent, showHidden, excluded)
                        }
                    }
                    index.finish()
                    requireAccess()
                    requireManifestCurrent(digest)
                    synchronized(stateLock) {
                        requireDirectoryEpoch(epoch)
                        directoryIndex = index
                    }
                    VaultDirectorySnapshot(
                        index,
                        checkCurrent = {
                            requireAccess()
                            requireManifestCurrent(digest)
                            requireDirectoryEpoch(epoch)
                        },
                        publish = { entries ->
                            synchronized(stateLock) {
                                requireDirectoryEpoch(epoch)
                                issuedEntries.clear()
                                entries.forEach { issuedEntries[requireNotNull(it.leaseId)] = it }
                            }
                        },
                        revoke = {
                            synchronized(stateLock) {
                                if (directoryGeneration.get() == epoch) invalidateDirectorySnapshot()
                            }
                        },
                    )
                }
            delivered = true
            return snapshot
        } finally {
            if (!delivered) {
                staged?.close()
                synchronized(stateLock) {
                    if (directoryGeneration.get() == epoch) invalidateDirectorySnapshot()
                }
            }
        }
    }

    private fun stageCachedChild(
        index: VaultDirectoryIndex,
        cached: OfflineEntry,
        path: String,
        parent: String,
        showHidden: Boolean,
        excludedPath: String?,
    ) {
        val immediateChild = cached.encryptedPath.substringBeforeLast('/', "") == parent
        val available = cached.isFolder || cached.blobId != null
        if (!immediateChild || !available) return
        val name = decryptChildName(cached.rawName)
        val childPath = joinEncrypted(path, name)
        if (!vaultChildVisible(name, childPath, showHidden, excludedPath)) return
        index.add(
            VaultFolder(
                cached.id.ifBlank { cached.encryptedPath },
                name,
                cached.rawName,
                childPath,
                cached.encryptedPath,
                cached.isFolder,
                cached.size,
                cached.etag,
            ),
        )
    }

    private fun decryptChildName(rawName: String): String {
        val name = cipher.decryptName(rawName)
        val invalidSegment = name.isEmpty() || name in setOf(".", "..")
        val invalidCharacters = name.any { it == '/' || it == '\\' || it.isISOControl() }
        if (invalidSegment || invalidCharacters) throw OpenCloudException(OpenCloudError.InvalidResponse)
        return name
    }

    private fun requireDirectoryEpoch(epoch: Long) {
        checkActive(kotlin.coroutines.EmptyCoroutineContext)
        if (directoryGeneration.get() != epoch) throw OpenCloudException(OpenCloudError.PreconditionFailed)
    }

    private fun invalidateDirectorySnapshot(): Long =
        synchronized(stateLock) {
            val epoch = directoryGeneration.incrementAndGet()
            directoryIndex?.close()
            directoryIndex = null
            issuedEntries.clear()
            epoch
        }

    private fun retainManifestState(): Pair<OfflineManifest, String> =
        synchronized(stateLock) {
            checkActive(kotlin.coroutines.EmptyCoroutineContext)
            manifest.retain() to manifestDigest
        }

    private suspend fun refreshCurrentManifest() {
        val context = currentCoroutineContext()
        val (current, before) = committedAccess.snapshot(keyMaterial) { checkActive(context) }
        var accepted = false
        try {
            current.visit({ checkActive(context) }) {}
            val after = committedAccess.digest { checkActive(context) }
            if (before != after) throw OpenCloudException(OpenCloudError.PreconditionFailed)
            requireAccess()
            synchronized(stateLock) {
                checkActive(context)
                val old = manifest
                manifest = current
                manifestDigest = after
                accepted = true
                old.close()
            }
        } finally {
            if (!accepted) current.close()
        }
    }

    private suspend fun requireManifestCurrent(expected: String) {
        val context = currentCoroutineContext()
        if (committedAccess.digest { checkActive(context) } != expected) {
            invalidateDirectorySnapshot()
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
    }

    /** Checks only supplied opaque versions; no offline child names are decrypted or issued. */
    internal suspend fun matchingFiles(entries: List<VaultFolder>): List<VaultFolder> =
        withContext(Dispatchers.IO) {
            require(entries.size <= 256)
            requireAccess()
            val (retained, digest) = retainManifestState()
            val context = currentCoroutineContext()
            val matched =
                retained.use { current ->
                    requireManifestCurrent(digest)
                    val selected = entries.associateBy(VaultFolder::encryptedPath)
                    val present = mutableSetOf<String>()
                    current.visit({ checkActive(context) }) { cached ->
                        selected[cached.encryptedPath]?.takeIf { matchesVersion(cached, it) }?.let {
                            present +=
                                it.encryptedPath
                        }
                    }
                    entries.filter { it.encryptedPath in present }
                }
            requireAccess()
            requireManifestCurrent(digest)
            matched
        }

    private fun matchesVersion(
        cached: OfflineEntry,
        entry: VaultFolder,
    ): Boolean {
        val savedFile = !cached.isFolder && cached.blobId != null && !entry.isFolder
        val sameIdentity = cached.id == entry.id && cached.rawName == entry.rawName
        val sameVersion = cached.size == entry.size && cached.etag == entry.strongETag
        return savedFile && sameIdentity && sameVersion
    }

    suspend fun list(path: String = ""): List<VaultFolder> =
        withContext(Dispatchers.IO) {
            invalidateDirectorySnapshot()
            requireAccess()
            refreshCurrentManifest()
            val encoded = cipher.encryptPath(path)
            val parent = joinEncrypted(location.vaultPath, encoded)
            val context = currentCoroutineContext()
            val children = mutableListOf<VaultFolder>()
            val (retained, digest) = retainManifestState()
            retained.use { current ->
                current.visit({ checkActive(context) }) { cached ->
                    if (cached.encryptedPath.substringBeforeLast('/', "") == parent &&
                        (cached.isFolder || cached.blobId != null)
                    ) {
                        val plainName = decryptChildName(cached.rawName)
                        val plainPath = if (path.isEmpty()) plainName else "$path/$plainName"
                        children +=
                            VaultFolder(
                                cached.id.ifBlank { cached.encryptedPath },
                                plainName,
                                cached.rawName,
                                plainPath,
                                cached.encryptedPath,
                                cached.isFolder,
                                cached.size,
                                cached.etag,
                                leaseId = UUID.randomUUID().toString(),
                            )
                    }
                }
            }
            children.sortWith(compareBy<VaultFolder> { !it.isFolder }.thenBy { it.name.lowercase() })
            requireManifestCurrent(digest)
            requireAccess()
            issuedEntries.clear()
            children.forEach { issuedEntries[it.leaseId!!] = it }
            children
        }

    /** The caller owns the sink and must remove a newly created destination if any block fails. */
    suspend fun download(
        entry: VaultFolder,
        sink: OutputStream,
        maxPlaintextBytes: Long = Long.MAX_VALUE,
    ): Long =
        withContext(Dispatchers.IO) {
            requireAccess()
            val context = currentCoroutineContext()
            val (retained, digest) = retainManifestState()
            retained.use { current ->
                requireManifestCurrent(digest)
                if (maxPlaintextBytes < 0 || entry.isFolder || issuedEntries[entry.leaseId] != entry) {
                    throw OpenCloudException(OpenCloudError.PreconditionFailed)
                }
                val cached =
                    current.find(entry.encryptedPath) { checkActive(context) }
                        ?: throw OpenCloudException(OpenCloudError.PreconditionFailed)
                if (!matchesVersion(cached, entry)) throw OpenCloudException(OpenCloudError.PreconditionFailed)
                val blobId = cached.blobId ?: throw OpenCloudException(OpenCloudError.PreconditionFailed)
                val blob = File(File(directory, "blobs"), blobId)
                VaultOfflineIndex.beginBlobRead(directory, blobId).use {
                    requireManifestCurrent(digest)
                    requireVerifiedBlob(blob, cached, context)
                    requireAccess()
                    val guardedSink =
                        object : FilterOutputStream(sink) {
                            override fun write(value: Int) {
                                checkActive(context)
                                out.write(value)
                            }

                            override fun write(
                                bytes: ByteArray,
                                offset: Int,
                                length: Int,
                            ) {
                                checkActive(context)
                                out.write(bytes, offset, length)
                            }
                        }
                    val written =
                        FileInputStream(
                            blob,
                        ).use { cipher.decryptContent(it, guardedSink, maxPlaintextBytes) }
                    requireAccess()
                    requireManifestCurrent(digest)
                    sink.flush()
                    written
                }
            }
        }

    private fun requireVerifiedBlob(
        blob: File,
        cached: OfflineEntry,
        context: CoroutineContext,
    ) {
        if (!blob.isFile ||
            blob.length() != cached.size ||
            sha256File(blob) { checkActive(context) } != cached.digest
        ) {
            throw OpenCloudException(OpenCloudError.InvalidResponse)
        }
    }

    suspend fun preview(entry: VaultFolder): ByteArray {
        val output = WipingPreviewBuffer()
        return try {
            download(entry, output, VaultSession.MAX_PREVIEW_BYTES.toLong())
            output.toByteArray()
        } finally {
            output.wipe()
        }
    }

    suspend fun encodeDirectoryPath(path: String): String =
        withContext(Dispatchers.IO) {
            requireAccess()
            cipher.encryptPath(path)
        }

    suspend fun decodeDirectoryPath(encryptedRelativePath: String): String =
        withContext(Dispatchers.IO) {
            requireAccess()
            cipher.decryptPath(encryptedRelativePath)
        }

    /** One-shot copy for biometric enrollment after the local encrypted manifest was proven. */
    internal suspend fun publishBackgroundDownload(
        job: VaultDownloadJob,
        payloads: VaultDownloadStore,
        offline: VaultOfflineStore,
        jobPermit: () -> Boolean,
        commitPublication: suspend () -> Boolean = { true },
    ) = withContext(Dispatchers.IO) {
        requireAccess()
        if (!job.matchesLocation(location)) throw OpenCloudException(OpenCloudError.PreconditionFailed)
        val entry = job.decryptedOfflineEntry(cipher)
        val material = keyMaterial.copyOf()
        val context = currentCoroutineContext()
        val active = {
            checkActive(context)
            jobPermit()
        }
        try {
            offline.pinFile(
                identity,
                location,
                entry,
                material,
                additionalPermit = active,
                commitPublication = {
                    commitPublication().also { accepted ->
                        // Room acknowledgement runs in Store's NonCancellable scope. Release the UI's
                        // baseline lease even when delivery to the caller is already cancelled.
                        if (accepted) releasePublishedBaseline()
                    }
                },
                publicationId = job.id,
            ) { output ->
                FileInputStream(payloads.partial(job)).use { input ->
                    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                    while (true) {
                        if (!active()) throw OpenCloudException(OpenCloudError.AccessDenied)
                        val count = input.read(buffer)
                        if (count < 0) break
                        output.write(buffer, 0, count)
                    }
                }
            }
            requireAccess()
            invalidateDirectorySnapshot()
            refreshCurrentManifest()
        } finally {
            material.fill(0)
        }
    }

    private fun releasePublishedBaseline() =
        synchronized(stateLock) {
            invalidateDirectorySnapshot()
            val previous = manifest
            manifest = StaleOfflineManifest
            previous.close()
        }

    /** Borrowed material is wiped before return; the accepted acknowledgement performs no root IO. */
    internal suspend fun <T> withGroupMaterial(
        block: suspend (ByteArray, livePermit: () -> Boolean, publicationAccepted: () -> Unit) -> T,
    ): T =
        withContext(Dispatchers.IO) {
            requireAccess()
            val context = currentCoroutineContext()
            val material = keyMaterial.copyOf()
            val livePermit = {
                checkActive(context)
                true
            }
            try {
                livePermit()
                block(material, livePermit, ::releasePublishedBaseline).also { requireAccess() }
            } finally {
                material.fill(0)
            }
        }

    /** One-shot copy for biometric enrollment after the local encrypted manifest was proven. */
    suspend fun exportVerifiedKeyMaterial(): ByteArray =
        withContext(Dispatchers.IO) {
            requireAccess()
            check(exported.compareAndSet(false, true)) { "Verified key material was already exported." }
            keyMaterial.copyOf()
        }

    @Suppress("ComplexCondition") // Each account and cache binding is required to fail closed.
    private suspend fun requireAccess() {
        currentCoroutineContext().ensureActive()
        checkActive(currentCoroutineContext())
        val current = accountFor(identity.accountId)
        if (current == null ||
            current != accountAtOpen ||
            !current.isActive ||
            endpoints.endpoint(current.serverUrl, allowQuery = false).toString() != identity.canonicalServer ||
            !File(directory, "manifest.enc").exists()
        ) {
            throw OpenCloudException(OpenCloudError.AuthenticationRequired)
        }
    }

    @Suppress("ComplexCondition") // Revocation, closure and credential permits must be checked together.
    private fun checkActive(context: CoroutineContext) {
        context.ensureActive()
        if (closed.get() ||
            !permit() ||
            accountGeneration != VaultOfflineRevocations.accountGeneration(identity.accountId) ||
            identityGeneration != VaultOfflineRevocations.identityGeneration(identity) ||
            VaultOfflineRevocations.accountBlocked(identity.accountId) ||
            VaultOfflineRevocations.identityBlocked(identity)
        ) {
            throw OpenCloudException(OpenCloudError.AccessDenied)
        }
    }

    override fun close() {
        if (closed.compareAndSet(false, true)) {
            invalidateDirectorySnapshot()
            synchronized(stateLock) { manifest.close() }
            keyMaterial.fill(0)
            cipher.close()
        }
    }
}

private class WipingPreviewBuffer : ByteArrayOutputStream(64 * 1024) {
    fun wipe() {
        buf.fill(0)
        reset()
    }
}

private fun joinEncrypted(
    parent: String,
    child: String,
): String =
    when {
        parent.isEmpty() -> child
        child.isEmpty() -> parent
        else -> "$parent/$child"
    }

/** A completed publication revokes the UI baseline while operation-specific readers retain their own leases. */
private object StaleOfflineManifest : OfflineManifest {
    override fun visit(
        checkActive: () -> Unit,
        consume: (OfflineEntry) -> Unit,
    ): Unit = throw OpenCloudException(OpenCloudError.PreconditionFailed)
}
