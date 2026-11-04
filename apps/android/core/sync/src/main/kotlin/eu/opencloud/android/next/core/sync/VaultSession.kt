package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.VaultDavClient
import eu.opencloud.android.next.core.network.VaultDavEntry
import eu.opencloud.android.next.core.network.VaultDavListing
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.FilterInputStream
import java.io.FilterOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.coroutines.CoroutineContext

/** A live session binds network, crypto and account leases to one root for all operations. */
@Suppress("LargeClass", "LongParameterList")
class VaultSession internal constructor(
    val identity: VaultIdentity,
    val location: VaultLocation,
    private val cipher: VaultCipherEngine,
    private val dav: VaultDavClient,
    private val access: VaultAccess,
    private val generationIsCurrent: () -> Boolean,
    private val spoolDirectory: File? = null,
) : AutoCloseable {
    private val closed = AtomicBoolean(false)
    private val keyMaterialExported = AtomicBoolean(false)
    private val issuedEntries = ConcurrentHashMap<String, VaultFolder>()
    private val boundaryEntries = ConcurrentHashMap<String, VaultFolder>()
    private val stateLock = Any()
    private val directoryGeneration = AtomicLong()
    private var directoryIndex: VaultDirectoryIndex? = null

    /** Full validation precedes publication; each page replaces the previous page's entry leases. */
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
                    requireLease()
                    val plainPath = validatePlainPath(path)
                    val excluded = validateVaultExcludedPath(excludedPath)
                    val context = currentCoroutineContext()
                    val parent = spoolDirectory ?: File(requireNotNull(System.getProperty("java.io.tmpdir")))
                    if (!parent.mkdirs() &&
                        !parent.isDirectory
                    ) {
                        throw OpenCloudException(OpenCloudError.LocalStorageWriteFailed)
                    }
                    val index = VaultDirectoryIndex(parent) { checkTransferActive(context) }
                    staged = index
                    verifyVaultRoot()
                    streamDirectory(
                        joinDavPaths(location.vaultPath, cipher.encryptPath(plainPath)),
                        depth = 1,
                    ) { entry ->
                        checkTransferActive(context)
                        val name = validateSingleName(cipher.decryptName(entry.rawName))
                        val childPath = joinDavPaths(plainPath, name)
                        if (vaultChildVisible(name, childPath, showHidden, excluded)) {
                            index.add(entry.toFolder(childPath, false, name, null))
                        }
                    }
                    requireLease()
                    verifyVaultRoot()
                    index.finish()
                    requireLease()
                    synchronized(stateLock) {
                        requireDirectoryEpoch(epoch)
                        directoryIndex = index
                    }
                    VaultDirectorySnapshot(
                        index,
                        checkCurrent = {
                            requireLease()
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

    private fun requireDirectoryEpoch(epoch: Long) {
        val liveSession = !closed.get() && access.permit() && generationIsCurrent()
        if (!liveSession || directoryGeneration.get() != epoch) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
    }

    private fun invalidateDirectorySnapshot(): Long =
        synchronized(stateLock) {
            val epoch = directoryGeneration.incrementAndGet()
            directoryIndex?.close()
            directoryIndex = null
            issuedEntries.clear()
            epoch
        }

    private suspend fun streamDirectory(
        path: String,
        depth: Int = 0,
        consume: (VaultDavEntry) -> Unit = {},
    ): VaultDavListing {
        val context = currentCoroutineContext()
        val directory = spoolDirectory ?: File(requireNotNull(System.getProperty("java.io.tmpdir")))
        return StagedRemoteFolder.create(directory).use { identities ->
            dav.streamDirectory(
                location.rootWebDavUrl,
                path,
                access.authorization,
                registerIdentity = { id, childPath ->
                    checkTransferActive(context)
                    identities.registerCanonicalPath("id:$id") && identities.registerCanonicalPath("path:$childPath")
                },
                consume = consume,
                depth = depth,
            )
        }
    }

    internal suspend fun ensureOfflineUnlockAnchor(offline: VaultOfflineStore) =
        withContext(Dispatchers.IO) {
            requireLease()
            val material = cipher.exportKeyMaterial()
            try {
                offline.pinDirectory(identity, location, location.vaultPath, material)
                requireLease()
                access.requireCurrent()
            } finally {
                material.fill(0)
            }
        }

    /** Preparation borrows the live transport, but never persists an unlock grant or decrypted path. */
    internal suspend fun <T> withOfflineGroupSource(
        context: Context,
        path: String,
        selectedEntry: VaultFolder? = null,
        additionalPermit: () -> Boolean,
        block: suspend (VaultOfflineGroupSource) -> T,
    ): T =
        withContext(Dispatchers.IO) {
            requireLease()
            val plainPath = validatePlainPath(path)
            selectedEntry?.let {
                requireIssuedEntry(it)
                if (!it.isFolder || it.path != plainPath) throw OpenCloudException(OpenCloudError.PreconditionFailed)
            }
            val coroutine = currentCoroutineContext()
            val checkActive = {
                checkTransferActive(coroutine)
                if (!additionalPermit()) throw OpenCloudException(OpenCloudError.AccessDenied)
            }
            checkActive()
            val root = streamDirectory(location.vaultPath)
            requireRootIdentity(root.root.id)
            if (!root.root.isFolder || root.root.relativePath != location.vaultPath) {
                throw OpenCloudException(OpenCloudError.PreconditionFailed)
            }
            root.integrityToken?.let(::requireAuthenticatedRootToken)
            val proofDigest = root.integrityToken?.let(::vaultProofDigest)
            val selected = captureOfflineGroupDirectory(plainPath, selectedEntry, root.root)
            requireLease()
            checkActive()
            val material = cipher.exportKeyMaterial()
            VaultOfflineGroupSource(
                context,
                identity,
                location,
                selected,
                proofDigest,
                material,
                validateRoot = {
                    requireLease()
                    val current = streamDirectory(location.vaultPath)
                    if (!current.root.isFolder ||
                        current.root.id != identity.remoteVaultId ||
                        current.integrityToken?.let(::vaultProofDigest) != proofDigest
                    ) {
                        throw OpenCloudException(OpenCloudError.PreconditionFailed)
                    }
                    current.integrityToken?.let(::requireAuthenticatedRootToken)
                    requireLease()
                },
                checkSession = checkActive,
                decryptName = { validateSingleName(cipher.decryptName(it)) },
                stream = { requested, depth, consume -> streamDirectory(requested, depth, consume) },
            ).use { source -> block(source) }
        }

    private suspend fun captureOfflineGroupDirectory(
        plainPath: String,
        selectedEntry: VaultFolder?,
        root: VaultDavEntry,
    ): VaultDavEntry {
        val encryptedPath = joinDavPaths(location.vaultPath, cipher.encryptPath(plainPath))
        val selected = if (encryptedPath == location.vaultPath) root else streamDirectory(encryptedPath).root
        val sameIssued =
            selectedEntry == null ||
                (selected.id == selectedEntry.id && selected.rawName == selectedEntry.rawName)
        if (!selected.isFolder || selected.relativePath != encryptedPath || !sameIssued) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
        return selected
    }

    internal suspend fun captureBackgroundDownload(
        payloads: VaultDownloadStore,
        entry: VaultFolder,
    ): VaultDownloadJob =
        withContext(Dispatchers.IO) {
            requireLease()
            requireIssuedEntry(entry)
            if (entry.isFolder) throw OpenCloudException(OpenCloudError.Unsupported)
            verifyVaultRoot()
            val root = streamDirectory(location.vaultPath)
            root.integrityToken?.let(::requireAuthenticatedRootToken)
            access.requireCurrent()
            requireLease()
            payloads.create(
                location,
                entry.toDavEntry(location.rootWebDavUrl),
                root.integrityToken?.let(::vaultProofDigest),
            )
        }

    /** Uses the unlocked cipher to validate original blocks before publishing a protected offline manifest. */
    internal suspend fun publishBackgroundDownload(
        job: VaultDownloadJob,
        payloads: VaultDownloadStore,
        offline: VaultOfflineStore,
        permit: () -> Boolean,
        commitPublication: suspend () -> Boolean = { true },
    ) = withContext(Dispatchers.IO) {
        requireLease()
        if (!job.matchesLocation(location)) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
        val entry = job.decryptedOfflineEntry(cipher)
        val material = cipher.exportKeyMaterial()
        val context = currentCoroutineContext()
        try {
            offline.pinFile(
                identity,
                location,
                entry,
                material,
                additionalPermit = {
                    checkTransferActive(context)
                    permit()
                },
                commitPublication = commitPublication,
                publicationId = job.id,
            ) { output ->
                FileInputStream(payloads.partial(job)).use { input ->
                    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                    while (true) {
                        checkTransferActive(context)
                        if (!permit()) throw OpenCloudException(OpenCloudError.AccessDenied)
                        val count = input.read(buffer)
                        if (count < 0) break
                        output.write(buffer, 0, count)
                    }
                }
            }
            requireLease()
            access.requireCurrent()
        } finally {
            material.fill(0)
        }
    }

    /** Completes encryption while unlocked; the committed job never contains a vault key. */
    @Suppress("TooGenericExceptionCaught")
    internal suspend fun prepareBackgroundUpload(
        payloads: VaultUploadStore,
        parentPath: String,
        name: String,
        source: InputStream,
        size: Long,
        preparationPermit: () -> Boolean,
    ): VaultUploadJob = prepareBackgroundCiphertext(payloads, parentPath, name, source, size, preparationPermit, null)

    internal suspend fun prepareBackgroundReplacement(
        payloads: VaultUploadStore,
        entry: VaultFolder,
        source: InputStream,
        size: Long,
        preparationPermit: () -> Boolean,
    ): VaultUploadJob =
        prepareBackgroundCiphertext(
            payloads,
            entry.path.substringBeforeLast('/', ""),
            entry.name,
            source,
            size,
            preparationPermit,
            entry,
        )

    /** A durable admission consumes the version even when scheduling or caller delivery is interrupted. */
    internal fun acknowledgeBackgroundReplacement(entry: VaultFolder) {
        removeIssuedEntry(entry)
        invalidateDirectorySnapshot()
    }

    // Create and issued replacement share ciphertext staging.
    @Suppress("LongParameterList", "TooGenericExceptionCaught")
    private suspend fun prepareBackgroundCiphertext(
        payloads: VaultUploadStore,
        parentPath: String,
        name: String,
        source: InputStream,
        size: Long,
        preparationPermit: () -> Boolean,
        replacement: VaultFolder?,
    ): VaultUploadJob =
        withContext(Dispatchers.IO) {
            requireLease()
            val parent = validatePlainPath(parentPath)
            val safeName = validateSingleName(name)
            require(size >= -1)
            replacement?.let {
                requireIssuedEntry(it)
                if (it.isFolder || it.path != joinDavPaths(parent, safeName)) {
                    throw OpenCloudException(OpenCloudError.PreconditionFailed)
                }
            }
            val expectedETag = replacement?.let(::requiredEntryETag)
            verifyWritableVaultRoot()
            val listing = streamDirectory(location.vaultPath)
            val proof = listing.integrityToken ?: throw OpenCloudException(OpenCloudError.PreconditionFailed)
            requireAuthenticatedRootToken(proof)
            val destination =
                joinDavPaths(location.vaultPath, joinDavPaths(cipher.encryptPath(parent), cipher.encryptName(safeName)))
            if (replacement != null && replacement.encryptedPath != destination) {
                throw OpenCloudException(OpenCloudError.PreconditionFailed)
            }
            val context = currentCoroutineContext()

            fun checkPreparing() {
                checkTransferActive(context)
                if (!preparationPermit()) throw OpenCloudException(OpenCloudError.AccessDenied)
            }
            val guarded =
                object : FilterInputStream(source) {
                    override fun read(): Int {
                        checkPreparing()
                        return `in`.read()
                    }

                    override fun read(
                        buffer: ByteArray,
                        offset: Int,
                        length: Int,
                    ): Int {
                        checkPreparing()
                        return `in`.read(buffer, offset, length)
                    }
                }
            val job =
                payloads.prepare(location, destination, expectedETag, vaultProofDigest(proof)) { output ->
                    val count =
                        cipher.encryptContent(
                            guarded,
                            object : FilterOutputStream(output) {
                                override fun write(value: Int) {
                                    checkPreparing()
                                    out.write(value)
                                }

                                override fun write(
                                    buffer: ByteArray,
                                    offset: Int,
                                    length: Int,
                                ) {
                                    checkPreparing()
                                    out.write(buffer, offset, length)
                                }
                            },
                            if (size <
                                0
                            ) {
                                Long.MAX_VALUE
                            } else {
                                size
                            },
                        )
                    if (size >= 0 &&
                        (count != size || guarded.read() != -1)
                    ) {
                        throw OpenCloudException(OpenCloudError.InvalidResponse)
                    }
                    checkPreparing()
                }
            try {
                requireLease()
                verifyWritableVaultRoot()
                replacement?.let(::requireIssuedEntry)
                job
            } catch (error: Exception) {
                payloads.delete(job.id)
                throw error
            }
        }

    /** Legacy complete decrypted list for recursive operations; retains the bounded DAV DOM limit. */
    suspend fun list(path: String = ""): List<VaultFolder> {
        invalidateDirectorySnapshot()
        var publishedEntries: List<VaultFolder>? = null
        var delivered = false
        try {
            val entries =
                withContext(Dispatchers.IO) {
                    requireLease()
                    val relativePlainPath = validatePlainPath(path)
                    verifyVaultRoot()
                    val encryptedPath = cipher.encryptPath(relativePlainPath)
                    val fullPath = joinDavPaths(location.vaultPath, encryptedPath)
                    val listing =
                        dav.list(
                            location.rootWebDavUrl,
                            fullPath,
                            access.authorization,
                            recognizedVaultRoot = true,
                        )
                    access.requireCurrent()
                    requireLease()
                    verifyVaultRoot()
                    val decryptedEntries =
                        listing.children.map { entry ->
                            val name = cipher.decryptName(entry.rawName)
                            val plainPath = joinDavPaths(relativePlainPath, name)
                            entry.toFolder(
                                plainPath,
                                isVaultRoot = false,
                                displayName = name,
                                leaseId = newEntryToken(),
                            )
                        }
                    access.requireCurrent()
                    requireLease()
                    synchronized(stateLock) {
                        if (closed.get() ||
                            !generationIsCurrent()
                        ) {
                            throw OpenCloudException(OpenCloudError.AccessDenied)
                        }
                        issuedEntries.clear()
                        decryptedEntries.forEach { issuedEntries[it.leaseId!!] = it }
                    }
                    // Set this before leaving the IO block so prompt cancellation during result
                    // dispatch can remove only the entries published by this invocation.
                    publishedEntries = decryptedEntries
                    decryptedEntries
                }
            delivered = true
            return entries
        } finally {
            if (!delivered) publishedEntries?.let(::removePublishedEntries)
        }
    }

    /** Includes the public mutation's dispatcher handoff in single-entry publication cleanup. */
    private suspend fun withMutationResult(block: suspend () -> VaultFolder): VaultFolder {
        var published: VaultFolder? = null
        var delivered = false
        try {
            val result = withContext(Dispatchers.IO) { block().also { published = it } }
            delivered = true
            return result
        } finally {
            if (!delivered) published?.let { removePublishedEntries(listOf(it)) }
        }
    }

    /** Post-write lookup validates every child before authorizing only the exact destination. */
    private suspend fun issueDestination(
        parentPath: String,
        encryptedName: String,
        expectedFolder: Boolean,
    ): VaultFolder {
        val epoch = invalidateDirectorySnapshot()
        var published: VaultFolder? = null
        var delivered = false
        try {
            val result =
                withContext(Dispatchers.IO) {
                    requireLease()
                    val parent = validatePlainPath(parentPath)
                    val context = currentCoroutineContext()
                    verifyVaultRoot()
                    var matched: VaultFolder? = null
                    streamDirectory(joinDavPaths(location.vaultPath, cipher.encryptPath(parent)), depth = 1) { raw ->
                        checkTransferActive(context)
                        val name = validateSingleName(cipher.decryptName(raw.rawName))
                        if (raw.rawName == encryptedName) {
                            // Full-stream path validation permits only one matching raw child name.
                            matched = raw.toFolder(joinDavPaths(parent, name), false, name, newEntryToken())
                        }
                    }
                    access.requireCurrent()
                    requireLease()
                    verifyVaultRoot()
                    val entry = matched ?: throw OpenCloudException(OpenCloudError.InvalidResponse)
                    if (entry.isFolder != expectedFolder) throw OpenCloudException(OpenCloudError.InvalidResponse)
                    synchronized(stateLock) {
                        requireDirectoryEpoch(epoch)
                        context.ensureActive()
                        issuedEntries.clear()
                        issuedEntries[requireNotNull(entry.leaseId)] = entry
                        published = entry
                    }
                    context.ensureActive()
                    entry
                }
            delivered = true
            return result
        } finally {
            if (!delivered) published?.let { removePublishedEntries(listOf(it)) }
        }
    }

    /** Capture metadata independently of UI pages; descriptors never authorize an operation. */
    internal suspend fun openBoundaryDirectory(
        context: Context,
        path: String,
    ): BoundaryDirectorySnapshot {
        val parent = validatePlainPath(path)
        return captureBoundaryDirectory(context, parent, guard = { requireLease() }) { emit ->
            requireLease()
            verifyVaultRoot()
            val coroutine = currentCoroutineContext()
            streamDirectory(joinDavPaths(location.vaultPath, cipher.encryptPath(parent)), depth = 1) { raw ->
                checkTransferActive(coroutine)
                val name = validateSingleName(cipher.decryptName(raw.rawName))
                emit(raw.toFolder(joinDavPaths(parent, name), false, name).asBoundaryEntry())
            }
            requireLease()
            verifyVaultRoot()
        }
    }

    /** Whole-parent names only: every child is validated, but no readable descriptor escapes. */
    internal suspend fun openBoundaryNames(
        context: Context,
        path: String,
    ): BoundaryNameIndex {
        val parent = validatePlainPath(path)
        return captureBoundaryNames(context, parent, guard = { requireLease() }) { emit ->
            requireLease()
            verifyVaultRoot()
            val coroutine = currentCoroutineContext()
            streamDirectory(joinDavPaths(location.vaultPath, cipher.encryptPath(parent)), depth = 1) { raw ->
                checkTransferActive(coroutine)
                val name = validateSingleName(cipher.decryptName(raw.rawName))
                // Keep the legacy names-list framing proof even for unrelated children.
                raw.toFolder(joinDavPaths(parent, name), false, name).asBoundaryEntry()
                emit(name)
            }
            requireLease()
            verifyVaultRoot()
        }
    }

    /** Chooser metadata never participates in UI issuance or scoped content-operation leases. */
    internal suspend fun openBoundaryDestinationFolders(
        context: Context,
        path: String,
    ): BoundaryDestinationSnapshot {
        val parent = validatePlainPath(path)
        return captureBoundaryDestinationFolders(context, parent, guard = { requireLease() }) { emit ->
            requireLease()
            verifyVaultRoot()
            val coroutine = currentCoroutineContext()
            streamDirectory(joinDavPaths(location.vaultPath, cipher.encryptPath(parent)), depth = 1) { raw ->
                checkTransferActive(coroutine)
                val name = validateSingleName(cipher.decryptName(raw.rawName))
                // Ignored files must still prove valid ciphertext framing and complete metadata.
                val child = raw.toFolder(joinDavPaths(parent, name), false, name).asBoundaryEntry()
                if (child.directory) emit(BoundaryDestinationFolder(child.id, child.path, child.name, false))
            }
            requireLease()
            verifyVaultRoot()
        }
    }

    /** A fresh exact operation lease is independent of UI pages and never escapes its callback. */
    internal suspend fun <T> withBoundaryEntry(
        expected: BoundaryEntry,
        operation: suspend (VaultFolder) -> T,
    ): T =
        withContext(Dispatchers.IO) {
            val current =
                findBoundaryChild(expected.path.substringBeforeLast('/', "")) {
                    sameBoundaryEntry(expected, it.asBoundaryEntry())
                } ?: throw OpenCloudException(OpenCloudError.PreconditionFailed)
            val entry = current.copy(leaseId = newEntryToken())
            val context = currentCoroutineContext()
            requireLease()
            synchronized(stateLock) {
                checkTransferActive(context)
                boundaryEntries[requireNotNull(entry.leaseId)] = entry
            }
            try {
                operation(entry)
            } finally {
                synchronized(stateLock) { boundaryEntries.remove(entry.leaseId, entry) }
            }
        }

    /** Names and emptiness are published only after validating the entire encrypted directory. */
    internal suspend fun hasBoundaryChild(
        path: String,
        name: String? = null,
    ): Boolean {
        name?.let { childPath(path, it) }
        return findBoundaryChild(path) { name == null || it.name == name } != null
    }

    private suspend fun findBoundaryChild(
        parentPath: String,
        matches: (VaultFolder) -> Boolean,
    ): VaultFolder? =
        withContext(Dispatchers.IO) {
            requireLease()
            val parent = validatePlainPath(parentPath)
            val context = currentCoroutineContext()
            verifyVaultRoot()
            var found: VaultFolder? = null
            streamDirectory(joinDavPaths(location.vaultPath, cipher.encryptPath(parent)), depth = 1) { raw ->
                checkTransferActive(context)
                val name = validateSingleName(cipher.decryptName(raw.rawName))
                val entry = raw.toFolder(joinDavPaths(parent, name), false, name)
                // Boundary plaintext-size validation applies to every child, including non-matches.
                entry.asBoundaryEntry()
                if (matches(entry)) found = entry
            }
            requireLease()
            verifyVaultRoot()
            found
        }

    private fun consumeIssuedEntryForMutation(entry: VaultFolder) =
        synchronized(stateLock) {
            requireIssuedEntry(entry)
            entry.leaseId?.let { boundaryEntries.remove(it, entry) }
        }

    /** Encodes a directory path relative to this vault for a short-lived transfer handoff. */
    suspend fun encodeDirectoryPath(plainPath: String): String =
        withContext(Dispatchers.IO) {
            requireLease()
            val safePath = validatePlainPath(plainPath)
            verifyVaultRoot()
            val encoded = cipher.encryptPath(safePath)
            access.requireCurrent()
            requireLease()
            verifyVaultRoot()
            encoded
        }

    suspend fun createFolder(
        parentPath: String,
        name: String,
    ): VaultFolder =
        withMutationResult {
            requireLease()
            val parent = validatePlainPath(parentPath)
            val safeName = validateSingleName(name)
            verifyWritableVaultRoot()
            val encryptedName = cipher.encryptName(safeName)
            val destination = joinDavPaths(location.vaultPath, joinDavPaths(cipher.encryptPath(parent), encryptedName))
            invalidateDirectorySnapshot()
            dav.createCollection(location.rootWebDavUrl, destination, access.authorization)
            access.requireCurrent()
            requireLease()
            verifyVaultRoot()
            issueDestination(parent, encryptedName, expectedFolder = true)
        }

    suspend fun delete(entry: VaultFolder) {
        var mutationAttempted = false
        try {
            withContext(Dispatchers.IO) {
                requireLease()
                requireIssuedEntry(entry)
                verifyWritableVaultRoot()
                val etag = entry.strongETag ?: throw OpenCloudException(OpenCloudError.PreconditionFailed)
                consumeIssuedEntryForMutation(entry)
                mutationAttempted = true
                invalidateDirectorySnapshot()
                dav.deleteResource(location.rootWebDavUrl, entry.encryptedPath, access.authorization, etag)
                access.requireCurrent()
                requireLease()
                verifyVaultRoot()
            }
        } finally {
            if (mutationAttempted) removeIssuedEntry(entry)
        }
    }

    /** Renames a folder vault root in its ordinary parent and closes this now-stale session. */
    suspend fun renameVaultRoot(newName: String): VaultLocation {
        var moveAttempted = false
        return try {
            withContext(Dispatchers.IO) {
                requireFolderVaultRootOperation()
                val newRootName = vaultFolderName(newName)
                val oldPath = location.vaultPath
                val parentPath = oldPath.substringBeforeLast('/', missingDelimiterValue = "")
                val newPath = joinDavPaths(parentPath, newRootName)
                requireLease()
                verifyVaultRoot()
                val parent = dav.inspectOrdinaryDirectory(location.rootWebDavUrl, parentPath, access.authorization)
                access.requireCurrent()
                requireRenameTargetAvailable(parent, newRootName)
                val before = streamDirectory(oldPath)
                access.requireCurrent()
                requireRootIdentity(before.root.id)
                requireAuthenticatedRootToken(before.integrityToken)
                moveAttempted = true
                dav.moveOrCopy(
                    location.rootWebDavUrl,
                    oldPath,
                    newPath,
                    access.authorization,
                    requiredRootETag(before.root),
                    copy = false,
                )
                access.requireCurrent()
                requireLease()
                val after = streamDirectory(newPath)
                access.requireCurrent()
                requireSameRenamedRoot(before, after)
                location.copy(title = newRootName, vaultPath = newPath)
            }
        } finally {
            // A failed MOVE response can be ambiguous; this session is stale either way.
            if (moveAttempted) close()
        }
    }

    /** Deletes only the vault collection itself; WebDAV/server policy decides non-empty behavior. */
    suspend fun deleteVaultRoot() {
        var deleteAttempted = false
        try {
            withContext(Dispatchers.IO) {
                requireFolderVaultRootOperation()
                requireLease()
                verifyVaultRoot()
                val listing =
                    dav.list(
                        location.rootWebDavUrl,
                        location.vaultPath,
                        access.authorization,
                        recognizedVaultRoot = true,
                    )
                access.requireCurrent()
                requireEmptyVaultRoot(listing)
                requireRootIdentity(listing.root.id)
                requireAuthenticatedRootToken(listing.integrityToken)
                deleteAttempted = true
                dav.deleteResource(
                    location.rootWebDavUrl,
                    location.vaultPath,
                    access.authorization,
                    requiredRootETag(listing.root),
                )
                access.requireCurrent()
            }
        } finally {
            if (deleteAttempted) close()
        }
    }

    private suspend fun requireFolderVaultRootOperation() {
        requireLease()
        if (location.kind != VaultLocationKind.FOLDER_VAULT || !location.isVaultRoot || location.vaultPath.isEmpty()) {
            throw OpenCloudException(OpenCloudError.Unsupported)
        }
    }

    private fun requireAuthenticatedRootToken(token: String?) {
        if (token.isNullOrBlank() || !cipher.verifyIntegrityToken(token)) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
    }

    private fun requireRootIdentity(remoteId: String) {
        if (remoteId != identity.remoteVaultId) throw OpenCloudException(OpenCloudError.PreconditionFailed)
    }

    private fun requiredRootETag(root: VaultDavEntry): String =
        root.strongETag ?: throw OpenCloudException(OpenCloudError.PreconditionFailed)

    private fun requireRenameTargetAvailable(
        parent: VaultDavListing,
        newRootName: String,
    ) {
        if (parent.requestedIsVaultMarker || parent.children.any { it.rawName == newRootName }) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
    }

    private fun requireSameRenamedRoot(
        before: VaultDavListing,
        after: VaultDavListing,
    ) {
        if (after.root.id != before.root.id || after.integrityToken != before.integrityToken) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
    }

    private fun requireEmptyVaultRoot(listing: VaultDavListing) {
        if (listing.children.isNotEmpty()) throw OpenCloudException(OpenCloudError.Unsupported)
    }

    suspend fun rename(
        entry: VaultFolder,
        newName: String,
    ): VaultFolder {
        requireIssuedEntry(entry)
        val safeName = validateSingleName(newName)
        val parent = entry.path.substringBeforeLast('/', missingDelimiterValue = "")
        return moveOrCopy(entry, parent, safeName, copy = false)
    }

    suspend fun move(
        entry: VaultFolder,
        destinationPath: String,
        newName: String = entry.name,
    ): VaultFolder = moveOrCopy(entry, validatePlainPath(destinationPath), validateSingleName(newName), copy = false)

    suspend fun copy(
        entry: VaultFolder,
        destinationPath: String,
        newName: String = entry.name,
    ): VaultFolder = moveOrCopy(entry, validatePlainPath(destinationPath), validateSingleName(newName), copy = true)

    private suspend fun moveOrCopy(
        entry: VaultFolder,
        destinationPath: String,
        newName: String,
        copy: Boolean,
    ): VaultFolder {
        var mutationAttempted = false
        return try {
            withMutationResult {
                requireLease()
                requireIssuedEntry(entry)
                val parent = validatePlainPath(destinationPath)
                requireMoveDestination(entry, parent)
                verifyWritableVaultRoot()
                val encryptedName = cipher.encryptName(newName)
                val destination =
                    joinDavPaths(location.vaultPath, joinDavPaths(cipher.encryptPath(parent), encryptedName))
                val etag = requiredEntryETag(entry)
                consumeIssuedEntryForMutation(entry)
                mutationAttempted = true
                invalidateDirectorySnapshot()
                dav.moveOrCopy(
                    location.rootWebDavUrl,
                    entry.encryptedPath,
                    destination,
                    access.authorization,
                    etag,
                    copy,
                )
                access.requireCurrent()
                requireLease()
                verifyVaultRoot()
                issueDestination(parent, encryptedName, expectedFolder = entry.isFolder)
            }
        } finally {
            if (mutationAttempted && !copy) removeIssuedEntry(entry)
        }
    }

    /**
     * Encrypts a caller-owned stream and conditionally creates or replaces one ciphertext file.
     * Parameters remain explicit so the ciphertext target and precondition are visible at callsites.
     */
    @Suppress("LongParameterList", "CyclomaticComplexMethod")
    suspend fun upload(
        parentPath: String,
        name: String,
        source: InputStream,
        size: Long,
        mimeType: String? = null,
        overwrite: VaultFolder? = null,
    ): VaultFolder = uploadWithCipher(parentPath, name, source, size, mimeType, overwrite, cipher)

    internal suspend fun uploadBoundary(
        parentPath: String,
        name: String,
        source: InputStream,
        size: Long,
        mimeType: String?,
    ): VaultFolder =
        withMutationResult {
            withBoundaryContentCipher { content ->
                uploadWithCipher(parentPath, name, source, size, mimeType, null, content)
            }
        }

    @Suppress("LongParameterList", "CyclomaticComplexMethod")
    private suspend fun uploadWithCipher(
        parentPath: String,
        name: String,
        source: InputStream,
        size: Long,
        mimeType: String? = null,
        overwrite: VaultFolder? = null,
        contentCipher: VaultCipherEngine,
    ): VaultFolder =
        withMutationResult {
            requireLease()
            val parent = validatePlainPath(parentPath)
            val safeName = validateSingleName(name)
            if (size < -1L) {
                throw OpenCloudException(OpenCloudError.Unsupported)
            }
            overwrite?.let(::requireIssuedEntry)
            if (overwrite != null && (overwrite.isFolder || overwrite.path != joinDavPaths(parent, safeName))) {
                throw OpenCloudException(OpenCloudError.PreconditionFailed)
            }
            verifyWritableVaultRoot()
            val encryptedName = cipher.encryptName(safeName)
            val destination = joinDavPaths(location.vaultPath, joinDavPaths(cipher.encryptPath(parent), encryptedName))
            val coroutineContext = currentCoroutineContext()
            val guardedSource = transferInput(source, coroutineContext)
            val spool =
                if (size ==
                    -1L
                ) {
                    VaultCiphertextSpools.create(spoolDirectory ?: throw OpenCloudException(OpenCloudError.Unsupported))
                } else {
                    null
                }
            try {
                val ciphertextSize =
                    if (spool != null) {
                        FileOutputStream(spool).use { fileOutput ->
                            contentCipher.encryptContent(
                                guardedSource,
                                transferOutput(fileOutput, coroutineContext),
                                Long.MAX_VALUE,
                            )
                        }
                        spool.length()
                    } else {
                        encryptedSize(size)
                    }
                access.requireCurrent()
                requireLease()
                val expectedETag =
                    overwrite?.strongETag?.also(::requireStrongETagForVault)
                        ?: if (overwrite == null) null else throw OpenCloudException(OpenCloudError.PreconditionFailed)
                var mutationAttempted = false
                try {
                    verifyWritableVaultRoot()
                    overwrite?.let(::consumeIssuedEntryForMutation)
                    mutationAttempted = true
                    invalidateDirectorySnapshot()
                    dav.putCiphertext(
                        location.rootWebDavUrl,
                        destination,
                        access.authorization,
                        contentLength = ciphertextSize,
                        expectedETag = expectedETag,
                        contentType = mimeType?.takeIf(String::isNotBlank) ?: "application/octet-stream",
                    ) { encryptedOutput ->
                        val guardedOutput = transferOutput(encryptedOutput, coroutineContext)
                        if (spool != null) {
                            val copied =
                                FileInputStream(spool).use { input ->
                                    input.copyTo(guardedOutput, DEFAULT_BUFFER_SIZE)
                                }
                            if (copied != ciphertextSize) throw OpenCloudException(OpenCloudError.InvalidResponse)
                        } else {
                            val written = contentCipher.encryptContent(guardedSource, guardedOutput, size)
                            if (written != size || guardedSource.read() != -1) {
                                throw OpenCloudException(OpenCloudError.InvalidResponse)
                            }
                        }
                    }
                } finally {
                    if (mutationAttempted && overwrite != null) removeIssuedEntry(overwrite)
                }
            } finally {
                spool?.let(VaultCiphertextSpools::delete)
            }
            access.requireCurrent()
            requireLease()
            verifyVaultRoot()
            issueDestination(parent, encryptedName, expectedFolder = false)
        }

    /** Streams authenticated blocks to the caller's new destination; caller removes it on failure. */
    suspend fun download(
        entry: VaultFolder,
        sink: OutputStream,
        maxPlaintextBytes: Long = Long.MAX_VALUE,
    ): Long = downloadWithCipher(entry, sink, maxPlaintextBytes, cipher)

    internal suspend fun readBoundary(
        entry: BoundaryEntry,
        sink: OutputStream,
    ) {
        withBoundaryEntry(entry) { issued ->
            withBoundaryContentCipher { content -> downloadWithCipher(issued, sink, Long.MAX_VALUE, content) }
        }
    }

    private suspend fun <T> withBoundaryContentCipher(operation: suspend (VaultCipherEngine) -> T): T =
        withContext(Dispatchers.IO) {
            requireLease()
            val content = cipher.forkForContent()
            try {
                requireLease()
                operation(content)
            } finally {
                content.close()
            }
        }

    /** Streams authenticated blocks to the caller's new destination; caller removes it on failure. */
    private suspend fun downloadWithCipher(
        entry: VaultFolder,
        sink: OutputStream,
        maxPlaintextBytes: Long = Long.MAX_VALUE,
        contentCipher: VaultCipherEngine,
    ): Long =
        withContext(Dispatchers.IO) {
            requireLease()
            requireIssuedEntry(entry)
            if (entry.isFolder || maxPlaintextBytes < 0L) {
                throw OpenCloudException(OpenCloudError.Unsupported)
            }
            verifyVaultRoot()
            val rawEntry = entry.toDavEntry(location.rootWebDavUrl)
            val coroutineContext = currentCoroutineContext()
            val plainSize =
                dav.withCiphertextStream(location.rootWebDavUrl, rawEntry, access.authorization) { encryptedInput ->
                    contentCipher.decryptContent(
                        transferInput(encryptedInput, coroutineContext),
                        transferOutput(sink, coroutineContext),
                        maxPlaintextBytes,
                    )
                }
            access.requireCurrent()
            requireLease()
            verifyVaultRoot()
            sink.flush()
            plainSize
        }

    /** Bounded current-page status; authenticates offline metadata without decrypting a child list. */
    suspend fun offlineFiles(
        store: VaultOfflineStore,
        entries: List<VaultFolder>,
    ): List<VaultFolder> =
        withContext(Dispatchers.IO) {
            require(entries.size <= 256)
            val page = entries.toList()
            requireLease()
            page.forEach(::requireIssuedEntry)
            val epoch = directoryGeneration.get()
            val material = cipher.exportKeyMaterial()
            try {
                val snapshot = store.openWithKeyMaterial(identity.accountId, location, material)
                val matched =
                    try {
                        snapshot?.matchingFiles(page).orEmpty()
                    } finally {
                        snapshot?.close()
                    }
                requireLease()
                requireDirectoryEpoch(epoch)
                page.forEach(::requireIssuedEntry)
                matched
            } finally {
                material.fill(0)
            }
        }

    /** Legacy complete cached child list; current-page status uses the bounded entries overload. */
    suspend fun offlineFiles(
        store: VaultOfflineStore,
        path: String,
    ): List<VaultFolder> =
        withContext(Dispatchers.IO) {
            requireLease()
            access.requireCurrent()
            val material = cipher.exportKeyMaterial()
            try {
                val snapshot = store.openWithKeyMaterial(identity.accountId, location, material)
                try {
                    val files = snapshot?.list(path).orEmpty().filterNot { it.isFolder }
                    requireLease()
                    access.requireCurrent()
                    files
                } finally {
                    snapshot?.close()
                }
            } finally {
                material.fill(0)
            }
        }

    /** Pins one issued file, or recursively pins an issued folder, into the separate offline store. */
    suspend fun pinOffline(
        store: VaultOfflineStore,
        entry: VaultFolder,
    ) = withContext(Dispatchers.IO) {
        requireLease()
        requireIssuedEntry(entry)
        if (entry.isFolder) {
            pinOfflineDirectory(store, entry.path)
        } else {
            val material = cipher.exportKeyMaterial()
            try {
                pinOfflineFile(store, entry, material)
            } finally {
                material.fill(0)
            }
        }
    }

    /** Explicitly pins the selected directory snapshot, including empty directories. */
    suspend fun pinOfflineDirectory(
        store: VaultOfflineStore,
        path: String = "",
    ) = withContext(Dispatchers.IO) {
        requireLease()
        val safePath = validatePlainPath(path)
        verifyVaultRoot()
        val material = cipher.exportKeyMaterial()
        val visited = mutableSetOf<String>()
        val seen = mutableSetOf<String>()
        try {
            suspend fun visit(plainPath: String) {
                requireLease()
                val encryptedPath = joinDavPaths(location.vaultPath, cipher.encryptPath(plainPath))
                if (!visited.add(encryptedPath)) throw OpenCloudException(OpenCloudError.InvalidResponse)
                seen += encryptedPath
                store.pinDirectory(identity, location, encryptedPath, material)
                val children = list(plainPath)
                children.filterNot(VaultFolder::isFolder).forEach {
                    pinOfflineFile(store, it, material)
                    seen += it.encryptedPath
                }
                children.filter(VaultFolder::isFolder).forEach { visit(it.path) }
            }
            visit(safePath)
            requireLease()
            store.pruneSubtree(
                identity,
                location,
                joinDavPaths(location.vaultPath, cipher.encryptPath(safePath)),
                seen,
                material,
            )
        } finally {
            material.fill(0)
        }
    }

    private suspend fun pinOfflineFile(
        store: VaultOfflineStore,
        entry: VaultFolder,
        material: ByteArray,
    ) {
        requireLease()
        requireIssuedEntry(entry)
        if (entry.isFolder) throw OpenCloudException(OpenCloudError.PreconditionFailed)
        verifyVaultRoot()
        val raw = entry.toDavEntry(location.rootWebDavUrl)
        val context = currentCoroutineContext()
        store.pinFile(identity, location, entry, material) { output ->
            dav.withCiphertextStream(location.rootWebDavUrl, raw, access.authorization) { input ->
                val guardedOutput = transferOutput(output, context)
                val buffer = ByteArray(64 * 1024)
                try {
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        guardedOutput.write(buffer, 0, count)
                    }
                } finally {
                    buffer.fill(0)
                }
            }
        }
        access.requireCurrent()
        requireLease()
    }

    private fun requireIssuedEntry(entry: VaultFolder) {
        val issued = entry.leaseId?.let { issuedEntries[it] ?: boundaryEntries[it] }
        if (issued != entry || entry.isVaultRoot) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
        requireEntryInsideVault(entry)
    }

    private fun removeIssuedEntry(entry: VaultFolder) {
        synchronized(stateLock) {
            entry.leaseId?.let { token ->
                if (issuedEntries[token] === entry) issuedEntries.remove(token)
                boundaryEntries.remove(token, entry)
            }
        }
    }

    private fun transferInput(
        input: InputStream,
        context: CoroutineContext,
    ): InputStream =
        object : FilterInputStream(input) {
            override fun read(): Int {
                checkTransferActive(context)
                return super.read()
            }

            override fun read(
                buffer: ByteArray,
                offset: Int,
                length: Int,
            ): Int {
                checkTransferActive(context)
                return `in`.read(buffer, offset, length)
            }
        }

    private fun transferOutput(
        output: OutputStream,
        context: CoroutineContext,
    ): OutputStream =
        object : FilterOutputStream(output) {
            override fun write(value: Int) {
                checkTransferActive(context)
                out.write(value)
            }

            override fun write(
                buffer: ByteArray,
                offset: Int,
                length: Int,
            ) {
                checkTransferActive(context)
                out.write(buffer, offset, length)
            }
        }

    private fun checkTransferActive(context: CoroutineContext) {
        context.ensureActive()
        if (closed.get() || !access.permit() || !generationIsCurrent()) {
            throw OpenCloudException(OpenCloudError.AccessDenied)
        }
    }

    /** Decodes a path captured relative to this vault, never relative to its enclosing drive. */
    suspend fun decodeDirectoryPath(encryptedRelativePath: String): String =
        withContext(Dispatchers.IO) {
            requireLease()
            validatePlainPath(encryptedRelativePath)
            verifyVaultRoot()
            val decoded = cipher.decryptPath(encryptedRelativePath)
            val safeDecoded = validatePlainPath(decoded)
            access.requireCurrent()
            requireLease()
            verifyVaultRoot()
            safeDecoded
        }

    private fun removePublishedEntries(entries: List<VaultFolder>) {
        synchronized(stateLock) {
            entries.forEach { entry ->
                entry.leaseId?.let { token ->
                    if (issuedEntries[token] === entry) issuedEntries.remove(token)
                }
            }
        }
    }

    /** Registry size only; keeps cancellation cleanup assertions from exposing plaintext entries. */
    internal fun issuedEntryCountForTesting(): Int = issuedEntries.size + boundaryEntries.size

    suspend fun preview(entry: VaultFolder): ByteArray {
        var pendingPlaintext: ByteArray? = null
        var delivered = false
        try {
            val plaintext =
                withContext(Dispatchers.IO) {
                    requireLease()
                    val issued = entry.leaseId?.let(issuedEntries::get)
                    requireIssuedFile(issued, entry)
                    requireEntryInsideVault(entry)
                    verifyVaultRoot()
                    val rawEntry =
                        VaultDavEntry(
                            id = entry.id,
                            relativePath = entry.encryptedPath,
                            rawName = entry.rawName,
                            isFolder = false,
                            size = entry.size,
                            strongETag = entry.strongETag,
                            href = resolveEntryHref(location.rootWebDavUrl, entry.encryptedPath),
                        )
                    val ciphertext = dav.readCiphertext(location.rootWebDavUrl, rawEntry, access.authorization)
                    try {
                        access.requireCurrent()
                        requireLease()
                        val output = WipingByteArrayOutputStream(MAX_PREVIEW_BYTES)
                        try {
                            cipher.decryptContent(ByteArrayInputStream(ciphertext), output, MAX_PREVIEW_BYTES.toLong())
                            access.requireCurrent()
                            requireLease()
                            verifyVaultRoot()
                            output.copyBytes().also { pendingPlaintext = it }
                        } finally {
                            output.wipe()
                        }
                    } finally {
                        ciphertext.fill(0)
                    }
                }
            delivered = true
            return plaintext
        } finally {
            if (!delivered) pendingPlaintext?.fill(0)
        }
    }

    private fun requireIssuedFile(
        issued: VaultFolder?,
        requested: VaultFolder,
    ) {
        if (issued != requested || requested.isFolder) throw OpenCloudException(OpenCloudError.PreconditionFailed)
    }

    internal suspend fun <T> withGroupMaterial(block: suspend (ByteArray, () -> Boolean, () -> Unit) -> T): T =
        withContext(Dispatchers.IO) {
            requireLease()
            val coroutine = currentCoroutineContext()
            val material = cipher.exportKeyMaterial()
            try {
                block(material, {
                    checkTransferActive(coroutine)
                    true
                }, {})
            } finally {
                material.fill(0)
            }
        }

    /** One-shot defensive copy for biometric enrollment after this session proved the remote vault. */
    suspend fun exportVerifiedKeyMaterial(): ByteArray {
        var pendingCopy: ByteArray? = null
        var delivered = false
        try {
            val keyMaterial =
                withContext(Dispatchers.IO) {
                    requireLease()
                    check(
                        keyMaterialExported.compareAndSet(false, true),
                    ) { "Verified key material was already exported." }
                    var copy: ByteArray? = null
                    try {
                        copy = cipher.exportKeyMaterial()
                        access.requireCurrent()
                        requireLease()
                        copy.also { pendingCopy = it }
                    } finally {
                        if (pendingCopy !== copy) copy?.fill(0)
                    }
                }
            delivered = true
            return keyMaterial
        } finally {
            if (!delivered) pendingCopy?.fill(0)
        }
    }

    override fun close() {
        dav.cancelRequests()
        val shouldClose =
            synchronized(stateLock) {
                if (!closed.compareAndSet(false, true)) {
                    false
                } else {
                    invalidateDirectorySnapshot()
                    boundaryEntries.clear()
                    true
                }
            }
        if (shouldClose) {
            cipher.close()
        }
    }

    /** Cancels this session's independently owned transport without weakening its key/lock lease. */
    fun cancelBoundaryRequests() = dav.cancelRequests()

    private suspend fun requireLease() {
        if (closed.get() || !access.permit() || !generationIsCurrent()) {
            throw OpenCloudException(OpenCloudError.AccessDenied)
        }
        access.requireCurrent()
    }

    private suspend fun verifyVaultRoot() {
        requireLease()
        val listing = streamDirectory(location.vaultPath)
        access.requireCurrent()
        requireLease()
        if (!listing.root.isFolder || listing.root.id != identity.remoteVaultId) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
    }

    /** Writes require a fresh authenticated token; read-only unlock may still use file-block proof. */
    private suspend fun verifyWritableVaultRoot() {
        requireLease()
        val listing = streamDirectory(location.vaultPath)
        access.requireCurrent()
        requireLease()
        if (!listing.root.isFolder || listing.root.id != identity.remoteVaultId) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
        requireAuthenticatedRootToken(listing.integrityToken)
    }

    private fun requireEntryInsideVault(entry: VaultFolder) {
        val prefix = location.vaultPath.trimEnd('/')
        val path = entry.encryptedPath
        if (!isVaultChildPath(prefix, path)) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
        if (path.substringAfterLast('/') != entry.rawName) throw OpenCloudException(OpenCloudError.PreconditionFailed)
    }

    private fun isVaultChildPath(
        prefix: String,
        path: String,
    ): Boolean = path.isNotEmpty() && path != prefix && (prefix.isEmpty() || path.startsWith("$prefix/"))

    private fun newEntryToken(): String = UUID.randomUUID().toString()

    companion object {
        const val MAX_PREVIEW_BYTES = 8 * 1024 * 1024

        /** Kept for existing UI callers during migration; transfers no longer use this limit. */
        const val MAX_TRANSFER_BYTES = MAX_PREVIEW_BYTES
    }
}

private fun VaultFolder.toDavEntry(rootWebDavUrl: String): VaultDavEntry =
    VaultDavEntry(
        id = id,
        relativePath = encryptedPath,
        rawName = rawName,
        isFolder = isFolder,
        size = size,
        strongETag = strongETag,
        href = resolveEntryHref(rootWebDavUrl, encryptedPath),
    )

private fun requireStrongETagForVault(value: String) {
    if (value.length < 2) throw OpenCloudException(OpenCloudError.PreconditionFailed)
    if (value.first() != '"' || value.last() != '"') {
        throw OpenCloudException(OpenCloudError.PreconditionFailed)
    }
}

private fun requiredEntryETag(entry: VaultFolder): String =
    entry.strongETag?.also(::requireStrongETagForVault)
        ?: throw OpenCloudException(OpenCloudError.PreconditionFailed)

private fun requireMoveDestination(
    entry: VaultFolder,
    parent: String,
) {
    if (entry.isFolder && (parent == entry.path || parent.startsWith(entry.path + "/"))) {
        throw OpenCloudException(OpenCloudError.PreconditionFailed)
    }
}

private fun encryptedSize(plainSize: Long): Long {
    val blocks = if (plainSize == 0L) 0L else 1L + (plainSize - 1L) / 65_536L
    return try {
        Math.addExact(32L, Math.addExact(plainSize, Math.multiplyExact(blocks, 16L)))
    } catch (_: ArithmeticException) {
        throw OpenCloudException(OpenCloudError.Unsupported)
    }
}
