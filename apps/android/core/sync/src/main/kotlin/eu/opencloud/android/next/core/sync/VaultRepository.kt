package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.crypto.RcloneVaultCipher
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.HttpClients
import eu.opencloud.android.next.core.network.LibreGraphSpacesClient
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.RemoteSpace
import eu.opencloud.android.next.core.network.RemoteSpacesSnapshot
import eu.opencloud.android.next.core.network.TransferConflictException
import eu.opencloud.android.next.core.network.VaultDavClient
import eu.opencloud.android.next.core.network.VaultDavEntry
import eu.opencloud.android.next.core.network.VaultDavListing
import eu.opencloud.android.next.core.security.AppLock
import eu.opencloud.android.next.core.security.TlsPolicy
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileOutputStream
import java.io.FilterInputStream
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/** Account-scoped discovery, authorization, and stable root validation for encrypted content. */
@Suppress("LargeClass", "LongParameterList")
class VaultRepository internal constructor(
    private val store: FileBrowserStore,
    private val authorizationFor: (AccountEntity) -> String,
    private val clientFor: (AccountEntity) -> OkHttpClient,
    private val endpointPolicy: EndpointPolicy,
    private val permitFor: () -> () -> Boolean,
    private val cipherFactories: VaultCipherFactories =
        VaultCipherFactories(
            password = { RcloneVaultCipher.fromPassword(it).asVaultCipher() },
            keyMaterial = { RcloneVaultCipher.fromKeyMaterial(it).asVaultCipher() },
        ),
    private val spoolDirectory: File? = null,
) {
    constructor(
        context: Context,
        store: FileBrowserStore = FileBrowserStore(FileBrowserDatabase.create(context)),
    ) : this(
        store = store,
        authorizationFor = { account ->
            WorkerAuthorizationProvider(context.applicationContext).authorization(account)
        },
        clientFor = { account ->
            TlsPolicy(context.applicationContext).applyTo(HttpClients.newClient(), account.serverUrl)
        },
        endpointPolicy = EndpointPolicy(),
        permitFor = { AppLock(context.applicationContext).beginAppAction() },
        spoolDirectory = File(context.noBackupFilesDir, "vault-transfer-spool"),
    )

    init {
        spoolDirectory?.let(VaultCiphertextSpools::removeStale)
    }

    private val generations = ConcurrentHashMap<VaultIdentity, AtomicLong>()

    /** Fetches only ciphertext; authentication and offline publication are deferred to live unlock. */
    @Suppress("CyclomaticComplexMethod")
    internal suspend fun executePreparedDownload(
        job: VaultDownloadJob,
        payloads: VaultDownloadStore,
        permit: () -> Boolean,
        onProgress: (Long) -> Unit,
    ): Long =
        withContext(Dispatchers.IO) {
            val account = requireActiveAccount(job.location.accountId)
            val server = endpointPolicy.endpoint(account.serverUrl, allowQuery = false).toString()
            if (server != job.location.canonicalServer) throw OpenCloudException(OpenCloudError.PreconditionFailed)
            val access = VaultAccess(account, server, "", null, permit) { store.account(account.id) }
            access.requireCurrent()
            access.authorization = authorizationFor(account)
            access.http = clientFor(account)
            access.requireCurrent()
            val dav = VaultDavClient(access.http, endpoints = endpointPolicy)
            requireCurrentLocation(access, graphSnapshot(access), job.location, dav)

            suspend fun checkRoot() {
                access.requireCurrent()
                val listing = streamListing(access, dav, job.location.rootWebDavUrl, job.location.vaultPath)
                if (!listing.root.isFolder ||
                    listing.root.id != job.location.remoteVaultId ||
                    listing.integrityToken?.let(::vaultProofDigest) != job.rootProofDigest
                ) {
                    throw OpenCloudException(OpenCloudError.PreconditionFailed)
                }
                access.requireCurrent()
            }
            checkRoot()
            val source =
                withRequestCancellation(dav::cancelRequests, permit) {
                    dav.statResource(job.location.rootWebDavUrl, job.source.relativePath, access.authorization)
                }
            if (source != job.source) throw OpenCloudException(OpenCloudError.PreconditionFailed)
            access.requireCurrent()
            val partial = payloads.partial(job)
            val checkpoint = payloads.checkpoint(job)
            val expectation =
                eu.opencloud.android.next.core.network
                    .DownloadExpectation(source.size, source.strongETag)
            val identity =
                "${job.location.accountId}|${job.location.canonicalServer}|${job.location.driveId}|" +
                    "${job.location.remoteVaultId}|${source.id}|${source.relativePath}|${source.size}|${source.strongETag}"
            val offset =
                prepareDownloadCheckpoint(
                    partial,
                    checkpoint,
                    identity,
                    source.size,
                    expectation.strongETag != null,
                )
            val transferContext = currentCoroutineContext()
            val client =
                eu.opencloud.android.next.core.network
                    .TransferClient(access.http)
            withRequestCancellation(client::cancelRequests, { permit() }) {
                client.download(source.href, access.authorization, offset, expectation) { input, _, resumed ->
                    var written = if (resumed) offset else 0L
                    vaultJobWrite { FileOutputStream(partial, resumed) }.use { output ->
                        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                        while (true) {
                            transferContext.ensureActive()
                            if (!permit()) throw OpenCloudException(OpenCloudError.AccessDenied)
                            val count = input.read(buffer)
                            if (count < 0) break
                            if (written >
                                source.size - count
                            ) {
                                throw OpenCloudException(OpenCloudError.DownloadIntegrity)
                            }
                            if (partial.parentFile!!.usableSpace < count + 16L * 1024 * 1024) {
                                throw OpenCloudException(OpenCloudError.LocalStorage)
                            }
                            vaultJobWrite { output.write(buffer, 0, count) }
                            written += count
                            onProgress(written)
                        }
                        vaultJobWrite { output.fd.sync() }
                        if (written != source.size) throw OpenCloudException(OpenCloudError.DownloadIntegrity)
                    }
                }
            }
            checkRoot()
            partial.length().also { if (it != source.size) throw OpenCloudException(OpenCloudError.DownloadIntegrity) }
        }

    /** Keyless network phase. Lock grants are intentionally absent; only committed ciphertext is used. */
    @Suppress("CyclomaticComplexMethod", "ComplexCondition")
    internal suspend fun executePreparedUpload(
        job: VaultUploadJob,
        payloads: VaultUploadStore,
        permit: () -> Boolean,
        mayHaveCommitted: Boolean,
        onMutationStarted: () -> Unit,
        onProgress: (Long) -> Unit,
    ): String =
        withContext(Dispatchers.IO) {
            val account = requireActiveAccount(job.location.accountId)
            val server = endpointPolicy.endpoint(account.serverUrl, allowQuery = false).toString()
            if (server != job.location.canonicalServer) throw OpenCloudException(OpenCloudError.PreconditionFailed)
            val access = VaultAccess(account, server, "", null, permit) { store.account(account.id) }
            access.requireCurrent()
            access.authorization = authorizationFor(account)
            access.http = clientFor(account)
            access.requireCurrent()
            val dav = VaultDavClient(access.http, endpoints = endpointPolicy)
            val transferContext = currentCoroutineContext()

            fun checkActive() {
                transferContext.ensureActive()
                if (!permit()) throw OpenCloudException(OpenCloudError.AccessDenied)
            }
            try {
                requireCurrentLocation(access, graphSnapshot(access), job.location, dav)
            } catch (failure: OpenCloudException) {
                if (mayHaveCommitted && failure.error == OpenCloudError.NotFound) {
                    throw OpenCloudException(OpenCloudError.NotReady(null))
                }
                throw failure
            }

            suspend fun checkRoot() {
                access.requireCurrent()
                val root = streamListing(access, dav, job.location.rootWebDavUrl, job.location.vaultPath)
                if (root.root.id != job.location.remoteVaultId ||
                    !root.root.isFolder ||
                    root.integrityToken?.let(::vaultProofDigest) != job.rootProofDigest
                ) {
                    throw OpenCloudException(OpenCloudError.PreconditionFailed)
                }
                access.requireCurrent()
            }

            suspend fun destination(): VaultDavEntry? {
                checkRoot()
                val parent = job.destination.substringBeforeLast('/', "")
                var matched: VaultDavEntry? = null
                streamListing(access, dav, job.location.rootWebDavUrl, parent, depth = 1) { entry ->
                    if (entry.relativePath == job.destination) matched = entry
                }
                access.requireCurrent()
                return matched
            }

            fun verify(entry: VaultDavEntry): Boolean {
                if (entry.isFolder || entry.size != job.size || entry.strongETag == null) return false
                return dav.withCiphertextStream(job.location.rootWebDavUrl, entry, access.authorization) { input ->
                    vaultUploadDigest(
                        object : FilterInputStream(input) {
                            override fun read(
                                buffer: ByteArray,
                                offset: Int,
                                length: Int,
                            ): Int {
                                checkActive()
                                return `in`.read(buffer, offset, length)
                            }
                        },
                    ) == job.digest
                }
            }

            fun pendingVerification(entry: VaultDavEntry): Boolean =
                try {
                    if (!entry.isFolder && entry.size == job.size && entry.strongETag == null) {
                        throw OpenCloudException(OpenCloudError.NotReady(null))
                    }
                    verify(entry)
                } catch (failure: OpenCloudException) {
                    if (failure.error == OpenCloudError.NotFound) {
                        throw OpenCloudException(OpenCloudError.NotReady(null))
                    }
                    throw failure
                }

            suspend fun pendingDestination(): VaultDavEntry? =
                try {
                    destination()
                } catch (failure: OpenCloudException) {
                    if (failure.error == OpenCloudError.NotFound) {
                        throw OpenCloudException(OpenCloudError.NotReady(null))
                    }
                    throw failure
                }

            val previous = if (mayHaveCommitted) pendingDestination() else destination()
            if (mayHaveCommitted && previous != null && pendingVerification(previous)) {
                checkRoot()
                return@withContext requireNotNull(previous.strongETag)
            }
            if (job.expectedETag == null && previous != null) throw OpenCloudException(OpenCloudError.Conflict)
            if (job.expectedETag != null && previous?.strongETag != job.expectedETag) {
                throw OpenCloudException(OpenCloudError.PreconditionFailed)
            }
            checkRoot()
            onMutationStarted()
            try {
                dav.putCiphertext(
                    job.location.rootWebDavUrl,
                    job.destination,
                    access.authorization,
                    job.size,
                    job.expectedETag,
                ) { output ->
                    payloads.open(job).use { input ->
                        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                        var count = 0L
                        while (true) {
                            checkActive()
                            val size = input.read(buffer)
                            if (size < 0) break
                            output.write(buffer, 0, size)
                            count += size
                            onProgress(count)
                        }
                        if (count != job.size) throw OpenCloudException(OpenCloudError.InvalidResponse)
                    }
                }
            } catch (collision: TransferConflictException) {
                if (!mayHaveCommitted) throw collision
                val committed = pendingDestination() ?: throw OpenCloudException(OpenCloudError.NotReady(null))
                if (!pendingVerification(committed)) throw collision
                checkRoot()
                return@withContext requireNotNull(committed.strongETag)
            }
            val after = pendingDestination() ?: throw OpenCloudException(OpenCloudError.NotReady(null))
            if (!pendingVerification(after)) throw OpenCloudException(OpenCloudError.InvalidResponse)
            checkRoot()
            requireNotNull(after.strongETag)
        }

    /** Returns safe Personal/project sources, direct `.vault` children, and Graph vault Spaces. */
    suspend fun locations(accountId: String): List<VaultLocation> =
        withContext(Dispatchers.IO) {
            val access = access(accountId)
            val snapshot = graphSnapshot(access)
            val sourceSpaces = snapshot.spaces.filter(::isUsableSource)
            val sources = sourceSpaces.map { it.toLocation(accountId, access.canonicalServer, isVaultRoot = false) }
            val dav = VaultDavClient(access.http, endpoints = endpointPolicy)
            val discovered = mutableListOf<VaultLocation>()
            for (space in sourceSpaces) {
                access.requireCurrent()
                val source = space.toLocation(accountId, access.canonicalServer, isVaultRoot = false)
                val root = safeRoot(access, source.rootWebDavUrl)
                val children = dav.discoverFolderVaults(root.toString(), authorization = access.authorization)
                access.requireCurrent()
                children.forEach { child ->
                    discovered +=
                        source.copy(
                            title = child.rawName,
                            kind = VaultLocationKind.FOLDER_VAULT,
                            remoteVaultId = child.id,
                            vaultPath = child.relativePath,
                            isVaultRoot = true,
                        )
                }
            }

            val graphVaults =
                snapshot.vaultSpaces.filter(::isUsableSource).map { space ->
                    val source =
                        space.toLocation(
                            accountId,
                            access.canonicalServer,
                            isVaultRoot = true,
                            kind = VaultLocationKind.SPACE_VAULT,
                        )
                    val root = safeRoot(access, source.rootWebDavUrl)
                    val rootEntry =
                        streamListing(access, dav, root.toString()).root
                    access.requireCurrent()
                    if (!graphRootMatchesDav(space.rootId, rootEntry.id)) {
                        throw OpenCloudException(OpenCloudError.PreconditionFailed)
                    }
                    source.copy(remoteVaultId = rootEntry.id)
                }
            access.requireCurrent()
            (sources + discovered + graphVaults).distinctBy { Triple(it.kind, it.driveId, it.vaultPath) }
        }

    /**
     * Returns only encrypted Graph Spaces for presentation alongside ordinary locations.
     * These entries are intentionally not written to the ordinary file-browser store.
     */
    suspend fun encryptedSpaces(accountId: String): List<VaultLocation> =
        withContext(Dispatchers.IO) {
            val access = access(accountId)
            val snapshot = graphSnapshot(access)
            val dav = VaultDavClient(access.http, endpoints = endpointPolicy)
            snapshot.vaultSpaces.filter(::isUsableSource).map { space ->
                access.requireCurrent()
                val source =
                    space.toLocation(
                        accountId,
                        access.canonicalServer,
                        isVaultRoot = true,
                        kind = VaultLocationKind.SPACE_VAULT,
                    )
                val root = safeRoot(access, source.rootWebDavUrl)
                val rootEntry =
                    streamListing(access, dav, root.toString()).root
                access.requireCurrent()
                if (!graphRootMatchesDav(space.rootId, rootEntry.id)) {
                    throw OpenCloudException(OpenCloudError.PreconditionFailed)
                }
                source.copy(remoteVaultId = rootEntry.id)
            }
        }

    /** Lists only immediate encrypted folder markers beneath an ordinary Space directory. */
    suspend fun encryptedFolders(
        accountId: String,
        driveId: String,
        parentPath: String = "",
    ): List<VaultLocation> =
        withContext(Dispatchers.IO) {
            val path = validatePlainPath(parentPath)
            if (path.split('/').any { it.endsWith(".vault", ignoreCase = false) }) {
                throw OpenCloudException(OpenCloudError.PreconditionFailed)
            }
            val access = access(accountId)
            val snapshot = graphSnapshot(access)
            val space =
                snapshot.spaces.firstOrNull { it.id == driveId && isUsableSource(it) }
                    ?: throw OpenCloudException(OpenCloudError.PreconditionFailed)
            val source = space.toLocation(accountId, access.canonicalServer, isVaultRoot = false)
            val root = safeRoot(access, source.rootWebDavUrl)
            val dav = VaultDavClient(access.http, endpoints = endpointPolicy)

            val rootListing = inspectVaultMarkers(dav, root.toString(), "", access.authorization)
            access.requireCurrent()
            if (rootListing.requestedIsVaultMarker || !graphRootMatchesDav(space.rootId, rootListing.root.id)) {
                throw OpenCloudException(OpenCloudError.PreconditionFailed)
            }
            val listing =
                if (path.isEmpty()) {
                    rootListing
                } else {
                    inspectVaultMarkers(dav, root.toString(), path, access.authorization)
                }
            access.requireCurrent()
            if (listing.requestedIsVaultMarker) throw OpenCloudException(OpenCloudError.PreconditionFailed)
            listing.children.filter(::isFolderVault).map { entry ->
                source.copy(
                    title = entry.rawName,
                    kind = VaultLocationKind.FOLDER_VAULT,
                    remoteVaultId = entry.id,
                    vaultPath = entry.relativePath,
                    isVaultRoot = true,
                )
            }
        }

    /** Validates a complete listing while callers retain only bounded metadata they need. */
    private suspend fun streamListing(
        access: VaultAccess,
        dav: VaultDavClient,
        root: String,
        path: String = "",
        depth: Int = 0,
        consume: (VaultDavEntry) -> Unit = {},
    ): VaultDavListing {
        val context = currentCoroutineContext()
        val directory = spoolDirectory ?: File(requireNotNull(System.getProperty("java.io.tmpdir")))
        access.requireCurrent()
        return StagedRemoteFolder.create(directory).use { identities ->
            val listing =
                dav.streamDirectory(
                    root,
                    path,
                    access.authorization,
                    registerIdentity = { id, childPath ->
                        context.ensureActive()
                        requireActionPermit(access.permit)
                        identities.registerCanonicalPath("id:$id") &&
                            identities.registerCanonicalPath("path:$childPath")
                    },
                    consume = consume,
                    depth = depth,
                )
            access.requireCurrent()
            listing
        }
    }

    private suspend fun inspectVaultMarkers(
        dav: VaultDavClient,
        root: String,
        path: String,
        authorization: String,
    ): eu.opencloud.android.next.core.network.VaultDavListing {
        val coroutine = currentCoroutineContext()
        val directory = spoolDirectory ?: File(requireNotNull(System.getProperty("java.io.tmpdir")))
        return StagedRemoteFolder.create(directory).use { identities ->
            dav.streamOrdinaryVaultMarkers(root, path, authorization) { id, childPath ->
                coroutine.ensureActive()
                identities.registerCanonicalPath("id:$id") && identities.registerCanonicalPath("path:$childPath")
            }
        }
    }

    /**
     * Creates a Web-compatible `.vault` collection inside a fresh ordinary Space listing.
     * After MKCOL, preserving non-cancellation causes prevents unsafe retries after partial creation.
     */
    @Suppress("TooGenericExceptionCaught", "CyclomaticComplexMethod")
    suspend fun createFolderVault(
        accountId: String,
        driveId: String,
        parentPath: String,
        name: String,
        password: CharArray,
    ): VaultLocation =
        try {
            withContext(Dispatchers.IO) {
                val parent = validatePlainPath(parentPath)
                val vaultName = vaultFolderName(name)
                val access = access(accountId)
                val snapshot = graphSnapshot(access)
                val sourceSpace =
                    snapshot.spaces.firstOrNull { it.id == driveId && isUsableSource(it) }
                        ?: throw OpenCloudException(OpenCloudError.PreconditionFailed)
                val source = sourceSpace.toLocation(accountId, access.canonicalServer, isVaultRoot = false)
                val root = safeRoot(access, source.rootWebDavUrl)
                val dav = VaultDavClient(access.http, endpoints = endpointPolicy)
                if (parent.split('/').any { it.endsWith(".vault") }) {
                    throw OpenCloudException(OpenCloudError.PreconditionFailed)
                }
                val sourceRootListing =
                    dav.inspectOrdinaryDirectory(
                        root.toString(),
                        authorization = access.authorization,
                    )
                access.requireCurrent()
                if (sourceRootListing.requestedIsVaultMarker ||
                    !graphRootMatchesDav(sourceSpace.rootId, sourceRootListing.root.id)
                ) {
                    throw OpenCloudException(OpenCloudError.PreconditionFailed)
                }
                val parentListing = dav.inspectOrdinaryDirectory(root.toString(), parent, access.authorization)
                access.requireCurrent()
                if (parentListing.requestedIsVaultMarker) {
                    throw OpenCloudException(OpenCloudError.PreconditionFailed)
                }
                if (parentListing.children.any { it.rawName == vaultName }) {
                    throw OpenCloudException(OpenCloudError.PreconditionFailed)
                }
                val cipher = cipherFactories.password(password)
                var collectionMayExist = false
                try {
                    val integrityToken = cipher.createIntegrityToken()
                    val vaultPath = joinDavPaths(parent, vaultName)
                    access.requireCurrent()
                    collectionMayExist = true
                    dav.createCollection(root.toString(), vaultPath, access.authorization)
                    access.requireCurrent()
                    dav.writeIntegrityToken(root.toString(), vaultPath, access.authorization, integrityToken)
                    access.requireCurrent()
                    val proof = streamListing(access, dav, root.toString(), vaultPath)
                    access.requireCurrent()
                    val proofToken = proof.integrityToken
                    if (proof.root.id.isBlank() || !matchesProofToken(cipher, proofToken, integrityToken)) {
                        throw OpenCloudException(OpenCloudError.InvalidResponse)
                    }
                    source.copy(
                        title = vaultName,
                        kind = VaultLocationKind.FOLDER_VAULT,
                        remoteVaultId = proof.root.id,
                        vaultPath = vaultPath,
                        isVaultRoot = true,
                    )
                } catch (failure: kotlinx.coroutines.CancellationException) {
                    throw failure
                } catch (failure: Exception) {
                    if (collectionMayExist) {
                        throw VaultCreationException(vaultName, failure)
                    }
                    throw failure
                } finally {
                    cipher.close()
                }
            }
        } finally {
            password.fill('\u0000')
        }

    /**
     * Creates a LibreGraph vault Space, then writes and re-reads Web's authenticated proof token.
     * After Graph POST, callers must inspect ambiguous outcomes before retrying.
     */
    @Suppress("TooGenericExceptionCaught")
    suspend fun createVaultSpace(
        accountId: String,
        name: String,
        password: CharArray,
    ): VaultLocation =
        try {
            withContext(Dispatchers.IO) {
                val safeTitle = validateSingleName(name)
                val access = access(accountId)
                val client = LibreGraphSpacesClient(access.http, endpoints = endpointPolicy)
                var spaceMayExist = false
                var createdDriveId: String? = null
                try {
                    access.requireCurrent()
                    spaceMayExist = true
                    createdDriveId = client.createVaultSpace(access.account.serverUrl, access.authorization, safeTitle)
                    access.requireCurrent()
                    val snapshot = graphSnapshot(access)
                    val space =
                        snapshot.vaultSpaces.firstOrNull { it.id == createdDriveId }
                            ?: throw OpenCloudException(OpenCloudError.InvalidResponse)
                    val source =
                        space.toLocation(
                            accountId,
                            access.canonicalServer,
                            isVaultRoot = true,
                            kind = VaultLocationKind.SPACE_VAULT,
                        )
                    val root = safeRoot(access, source.rootWebDavUrl)
                    val dav = VaultDavClient(access.http, endpoints = endpointPolicy)
                    val before =
                        streamListing(access, dav, root.toString())
                    access.requireCurrent()
                    if (!graphRootMatchesDav(space.rootId, before.root.id) || !before.integrityToken.isNullOrBlank()) {
                        throw OpenCloudException(OpenCloudError.PreconditionFailed)
                    }
                    val cipher = cipherFactories.password(password)
                    try {
                        val token = cipher.createIntegrityToken()
                        dav.writeIntegrityToken(root.toString(), "", access.authorization, token)
                        access.requireCurrent()
                        val after =
                            streamListing(access, dav, root.toString())
                        access.requireCurrent()
                        val proofToken = after.integrityToken
                        if (after.root.id != before.root.id || !matchesProofToken(cipher, proofToken, token)) {
                            throw OpenCloudException(OpenCloudError.InvalidResponse)
                        }
                        source.copy(remoteVaultId = after.root.id)
                    } finally {
                        cipher.close()
                    }
                } catch (failure: kotlinx.coroutines.CancellationException) {
                    throw failure
                } catch (failure: Exception) {
                    if (spaceMayExist) {
                        throw VaultCreationException(createdDriveId ?: safeTitle, failure)
                    }
                    throw failure
                }
            }
        } finally {
            password.fill('\u0000')
        }

    /** Binds an ordinary copy/move endpoint to the same current Graph/DAV root used by vault discovery. */
    suspend fun ordinaryBoundaryEndpoint(
        context: Context,
        accountId: String,
        location: VaultLocation,
    ): BoundaryEndpoint =
        withContext(Dispatchers.IO) {
            requireRequestedAccount(accountId, location)
            if (location.isVaultRoot || location.kind !in setOf(VaultLocationKind.PERSONAL, VaultLocationKind.SPACE)) {
                throw OpenCloudException(OpenCloudError.AccessDenied)
            }
            val access = access(accountId)
            val dav = VaultDavClient(access.http, endpoints = endpointPolicy)
            val revalidate: suspend () -> Unit = {
                requireLocationAccount(access, location)
                requireCurrentLocation(access, graphSnapshot(access), location, dav)
                access.requireCurrent()
            }
            revalidate()
            OrdinaryBoundaryEndpoint(
                access,
                location,
                FileBrowserDatabase.create(context).vaultExclusionDao(),
                revalidate,
                endpointPolicy,
                File(context.noBackupFilesDir, "boundary-lookup-stage"),
            )
        }

    /** Legacy complete child list for explicit walkers; vault browsing uses paged session snapshots. */
    suspend fun folders(
        accountId: String,
        location: VaultLocation,
        path: String = "",
    ): List<VaultFolder> =
        withContext(Dispatchers.IO) {
            requireRequestedAccount(accountId, location)
            val access = access(accountId)
            requireLocationAccount(access, location)
            val safePath = validatePlainPath(path)
            val dav = VaultDavClient(access.http, endpoints = endpointPolicy)
            val current = requireCurrentLocation(access, graphSnapshot(access), location, dav)
            val root = safeRoot(access, current.rootWebDavUrl)
            val entries =
                if (location.isVaultRoot) {
                    val fullPath = joinDavPaths(location.vaultPath, safePath)
                    verifyVaultRoot(access, dav, root, location)
                    val listing = dav.list(root.toString(), fullPath, access.authorization, recognizedVaultRoot = true)
                    if (fullPath == location.vaultPath && listing.root.id != location.remoteVaultId) {
                        throw OpenCloudException(OpenCloudError.PreconditionFailed)
                    }
                    access.requireCurrent()
                    listing.children
                } else {
                    dav.discoverDirectories(root.toString(), safePath, access.authorization)
                }
            access.requireCurrent()
            entries.map { entry ->
                val name = entry.rawName
                val childPath = joinDavPaths(safePath, name)
                entry.toFolder(childPath, isVaultRoot = !location.isVaultRoot && isFolderVault(entry))
            }
        }

    suspend fun unlock(
        accountId: String,
        location: VaultLocation,
        vaultPath: String = location.vaultPath,
        password: CharArray,
    ): VaultSession =
        try {
            unlockWithCipher(accountId, location, vaultPath) { cipherFactories.password(password) }
        } finally {
            password.fill('\u0000')
        }

    /** The caller retains ownership of [keyMaterial] and should clear it after this call. */
    suspend fun unlockWithKeyMaterial(
        accountId: String,
        location: VaultLocation,
        vaultPath: String = location.vaultPath,
        keyMaterial: ByteArray,
    ): VaultSession = unlockWithCipher(accountId, location, vaultPath) { cipherFactories.keyMaterial(keyMaterial) }

    private suspend fun unlockWithCipher(
        accountId: String,
        location: VaultLocation,
        vaultPath: String,
        cipherFactory: () -> VaultCipherEngine,
    ): VaultSession {
        var createdSession: VaultSession? = null
        var delivered = false
        try {
            val session =
                withContext(Dispatchers.IO) {
                    requireRequestedAccount(accountId, location)
                    val access = access(accountId)
                    requireLocationAccount(access, location)
                    val path = validatePlainPath(vaultPath)
                    require(path.isNotEmpty() || location.isVaultRoot) { "Choose a vault folder first." }
                    val dav = VaultDavClient(access.http, endpoints = endpointPolicy)
                    val candidate = locateVault(access, location, path, dav)
                    createVaultSession(access, location, path, candidate, cipherFactory).also { createdSession = it }
                }
            delivered = true
            return session
        } finally {
            // Close a session if prompt cancellation wins while withContext dispatches its result.
            if (!delivered) createdSession?.close()
        }
    }

    private suspend fun locateVault(
        access: VaultAccess,
        location: VaultLocation,
        path: String,
        dav: VaultDavClient,
    ): VaultUnlockCandidate {
        val current = requireCurrentLocation(access, graphSnapshot(access), location, dav)
        val root = safeRoot(access, current.rootWebDavUrl)
        if (location.isVaultRoot &&
            path != location.vaultPath
        ) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
        access.requireCurrent()
        val proofFiles = ArrayList<VaultDavEntry>(MAX_PROOF_FILE_ATTEMPTS)
        val metadata =
            streamListing(access, dav, root.toString(), path, depth = 1) { entry ->
                if (proofFiles.size < MAX_PROOF_FILE_ATTEMPTS && isProofCandidate(entry)) proofFiles += entry
            }
        val listing = metadata.copy(children = proofFiles)
        access.requireCurrent()
        requireVaultCollection(listing)
        if (location.isVaultRoot && path == location.vaultPath && listing.root.id != location.remoteVaultId) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
        if (location.kind != VaultLocationKind.SPACE_VAULT) requireFolderVault(listing.root)
        return VaultUnlockCandidate(current, root, dav, listing)
    }

    private fun requireVaultCollection(listing: VaultDavListing) {
        if (!listing.root.isFolder) throw OpenCloudException(OpenCloudError.InvalidResponse)
    }

    private fun requireFolderVault(entry: VaultDavEntry) {
        if (!isFolderVault(entry)) throw OpenCloudException(OpenCloudError.Unsupported)
    }

    private suspend fun createVaultSession(
        access: VaultAccess,
        location: VaultLocation,
        path: String,
        candidate: VaultUnlockCandidate,
        cipherFactory: () -> VaultCipherEngine,
    ): VaultSession {
        access.requireCurrent()
        val cipher = cipherFactory()
        var transferred = false
        try {
            access.requireCurrent()
            val proved =
                proveKey(
                    VaultProofContext(cipher, candidate.dav, candidate.root, access),
                    candidate.listing.integrityToken,
                    candidate.listing.children,
                )
            if (!proved) throw VaultUnlockException(VaultUnlockFailure.PASSWORD_NOT_PROVEN)
            access.requireCurrent()
            val identity =
                VaultIdentity(
                    access.account.id,
                    access.canonicalServer,
                    candidate.current.driveId,
                    candidate.listing.root.id,
                )
            val generation = generations.computeIfAbsent(identity) { AtomicLong() }.incrementAndGet()
            val openedLocation =
                candidate.current.copy(
                    title = candidate.listing.root.rawName,
                    kind =
                        if (location.kind ==
                            VaultLocationKind.SPACE_VAULT
                        ) {
                            VaultLocationKind.SPACE_VAULT
                        } else {
                            VaultLocationKind.FOLDER_VAULT
                        },
                    remoteVaultId = candidate.listing.root.id,
                    vaultPath = path,
                    isVaultRoot = true,
                )
            val session =
                VaultSession(
                    identity = identity,
                    location = openedLocation,
                    cipher = cipher,
                    dav = candidate.dav,
                    access = access,
                    generationIsCurrent = { generations[identity]?.get() == generation },
                    spoolDirectory = spoolDirectory,
                )
            currentCoroutineContext().ensureActive()
            transferred = true
            return session
        } finally {
            if (!transferred) cipher.close()
        }
    }

    private suspend fun proveKey(
        context: VaultProofContext,
        integrityToken: String?,
        children: List<VaultDavEntry>,
    ): Boolean {
        var proven = !integrityToken.isNullOrBlank() && context.cipher.verifyIntegrityToken(integrityToken)
        val candidates = children.asSequence().filter(::isProofCandidate).take(MAX_PROOF_FILE_ATTEMPTS)
        if (!proven) {
            for (entry in candidates) {
                if (proveFromFile(context, entry)) {
                    proven = true
                    break
                }
            }
        }
        return proven
    }

    private fun isProofCandidate(entry: VaultDavEntry): Boolean = !entry.isFolder && entry.size > RCLONE_HEADER_BYTES

    private suspend fun proveFromFile(
        context: VaultProofContext,
        entry: VaultDavEntry,
    ): Boolean {
        context.access.requireCurrent()
        val prefix = context.dav.readProofPrefix(context.root.toString(), entry, context.access.authorization)
        return try {
            context.access.requireCurrent()
            val authenticated = decryptProofBlock(context.cipher, prefix)
            context.access.requireCurrent()
            authenticated
        } finally {
            prefix.fill(0)
        }
    }

    private fun decryptProofBlock(
        cipher: VaultCipherEngine,
        prefix: ByteArray,
    ): Boolean {
        val output = WipingByteArrayOutputStream(MAX_PROOF_PLAINTEXT_BYTES)
        return try {
            try {
                cipher.decryptContent(ByteArrayInputStream(prefix), output, MAX_PROOF_PLAINTEXT_BYTES.toLong()) > 0
            } catch (_: IllegalArgumentException) {
                false
            } catch (_: SecurityException) {
                false
            } catch (failure: OpenCloudException) {
                if (failure.error != OpenCloudError.DownloadIntegrity) throw failure
                false
            } catch (_: java.io.IOException) {
                false
            }
        } finally {
            output.wipe()
        }
    }

    private suspend fun graphSnapshot(access: VaultAccess): RemoteSpacesSnapshot =
        LibreGraphSpacesClient(access.http, endpoints = endpointPolicy)
            // `/me/drives` limits discovery to the authenticated user's authorized roots.
            .snapshot(access.account.serverUrl, access.authorization, includeVaultDetails = true)
            .also { access.requireCurrent() }

    private suspend fun requireCurrentLocation(
        access: VaultAccess,
        snapshot: RemoteSpacesSnapshot,
        location: VaultLocation,
        dav: VaultDavClient,
    ): VaultLocation {
        requireVaultKindMatches(location)
        val candidates =
            if (location.kind == VaultLocationKind.SPACE_VAULT) snapshot.vaultSpaces else snapshot.spaces
        val space =
            candidates.firstOrNull {
                it.id == location.driveId &&
                    it.rootId == location.sourceRootId &&
                    it.rootWebDavUrl == location.rootWebDavUrl &&
                    isUsableSource(it)
            } ?: throw OpenCloudException(OpenCloudError.PreconditionFailed)
        val root = safeRoot(access, space.rootWebDavUrl)
        val current = location.copy(rootWebDavUrl = root.toString())
        verifyLocationVaultRoot(access, dav, root, location, space)
        return current
    }

    private fun requireVaultKindMatches(location: VaultLocation) {
        if (location.isVaultRoot != isVaultKind(location.kind)) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
    }

    private fun isVaultKind(kind: VaultLocationKind): Boolean =
        kind == VaultLocationKind.FOLDER_VAULT || kind == VaultLocationKind.SPACE_VAULT

    private suspend fun verifyLocationVaultRoot(
        access: VaultAccess,
        dav: VaultDavClient,
        root: HttpUrl,
        location: VaultLocation,
        space: RemoteSpace,
    ) {
        when (location.kind) {
            VaultLocationKind.FOLDER_VAULT -> verifyFolderVaultRoot(access, dav, root, location)

            VaultLocationKind.SPACE_VAULT -> verifyGraphVaultRoot(location, space)

            else -> Unit
        }
    }

    private suspend fun verifyFolderVaultRoot(
        access: VaultAccess,
        dav: VaultDavClient,
        root: HttpUrl,
        location: VaultLocation,
    ) {
        if (location.vaultPath.isEmpty()) throw OpenCloudException(OpenCloudError.PreconditionFailed)
        val folder = streamListing(access, dav, root.toString(), location.vaultPath).root
        access.requireCurrent()
        if (!folder.isFolder || !isFolderVault(folder) || folder.id != location.remoteVaultId) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
    }

    private fun verifyGraphVaultRoot(
        location: VaultLocation,
        space: RemoteSpace,
    ) {
        if (!graphRootMatchesDav(space.rootId, location.remoteVaultId)) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
    }

    private fun requireLocationAccount(
        access: VaultAccess,
        location: VaultLocation,
    ) {
        if (location.accountId != access.account.id || location.canonicalServer != access.canonicalServer) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
    }

    private fun requireRequestedAccount(
        accountId: String,
        location: VaultLocation,
    ) {
        if (location.accountId != accountId) throw OpenCloudException(OpenCloudError.PreconditionFailed)
    }

    private fun safeRoot(
        access: VaultAccess,
        value: String,
    ): HttpUrl {
        val root = endpointPolicy.endpoint(value, allowQuery = false)
        val server = access.canonicalServer.toHttpUrl()
        if (root.scheme != server.scheme || root.host != server.host || root.port != server.port) {
            throw OpenCloudException(OpenCloudError.Trust)
        }
        return root
    }

    private suspend fun verifyVaultRoot(
        access: VaultAccess,
        dav: VaultDavClient,
        root: HttpUrl,
        location: VaultLocation,
    ) {
        val listing = streamListing(access, dav, root.toString(), location.vaultPath)
        access.requireCurrent()
        if (!listing.root.isFolder || listing.root.id != location.remoteVaultId) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
    }

    private suspend fun access(accountId: String): VaultAccess {
        val account = requireActiveAccount(accountId)
        val permit = permitFor()
        requireActionPermit(permit)
        val canonicalServer = endpointPolicy.endpoint(account.serverUrl, allowQuery = false).toString()
        val access =
            VaultAccess(
                account = account,
                canonicalServer = canonicalServer,
                authorizationValue = "",
                httpClient = null,
                permit = permit,
                currentAccount = { store.account(accountId) },
            )
        access.requireCurrent()
        // Authorization can refresh tokens and perform I/O, so capture/check the lock permit first.
        val authorization = authorizationFor(account)
        access.requireCurrent()
        access.authorization = authorization
        access.http = clientFor(account)
        access.requireCurrent()
        return access
    }

    private suspend fun requireActiveAccount(accountId: String): AccountEntity {
        val account = store.account(accountId) ?: throw OpenCloudException(OpenCloudError.AuthenticationRequired)
        if (!account.isActive) throw OpenCloudException(OpenCloudError.AuthenticationRequired)
        return account
    }

    private fun requireActionPermit(permit: () -> Boolean) {
        if (!permit()) throw OpenCloudException(OpenCloudError.AccessDenied)
    }

    private fun RemoteSpace.toLocation(
        accountId: String,
        canonicalServer: String,
        isVaultRoot: Boolean,
        kind: VaultLocationKind = if (type == PERSONAL_TYPE) VaultLocationKind.PERSONAL else VaultLocationKind.SPACE,
    ) = VaultLocation(
        accountId = accountId,
        title = name,
        kind = kind,
        driveId = id,
        remoteVaultId = rootId,
        sourceRootId = rootId,
        canonicalServer = canonicalServer,
        rootWebDavUrl = rootWebDavUrl,
        vaultPath = "",
        isVaultRoot = isVaultRoot,
    )

    private fun isUsableSource(space: RemoteSpace): Boolean =
        space.type in setOf(PERSONAL_TYPE, PROJECT_TYPE) && !space.disabled && !space.deleted

    private companion object {
        const val PERSONAL_TYPE = "personal"
        const val PROJECT_TYPE = "project"
        const val RCLONE_HEADER_BYTES = 32L
        const val MAX_PROOF_PLAINTEXT_BYTES = 65_536
        const val MAX_PROOF_FILE_ATTEMPTS = 8
    }
}

private data class VaultProofContext(
    val cipher: VaultCipherEngine,
    val dav: VaultDavClient,
    val root: HttpUrl,
    val access: VaultAccess,
)

private fun matchesProofToken(
    cipher: VaultCipherEngine,
    actual: String?,
    expected: String,
): Boolean = actual == expected && actual != null && cipher.verifyIntegrityToken(actual)

private data class VaultUnlockCandidate(
    val current: VaultLocation,
    val root: HttpUrl,
    val dav: VaultDavClient,
    val listing: VaultDavListing,
)

/** Graph elides a space root's repeated opaque ID; DAV retains it as `!spaceId`. */
internal fun graphRootMatchesDav(
    graphRootId: String,
    davRootId: String,
): Boolean =
    graphRootId == davRootId ||
        run {
            val parts = graphRootId.split('$')
            val isShortRoot = parts.size == 2 && parts.all(String::isNotEmpty) && '!' !in graphRootId
            isShortRoot && davRootId == "$graphRootId!${parts[1]}"
        }

private fun isFolderVault(entry: VaultDavEntry): Boolean =
    entry.isFolder && (entry.rawName.endsWith(".vault") || entry.isVaultMarker)
