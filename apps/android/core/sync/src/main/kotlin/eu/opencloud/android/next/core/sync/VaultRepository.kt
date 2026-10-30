package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.crypto.RcloneVaultCipher
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.network.EndpointPolicy
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
import java.io.ByteArrayOutputStream
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
        clientFor = { account -> TlsPolicy(context.applicationContext).applyTo(OkHttpClient(), account.serverUrl) },
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
            val access = VaultAccess(account, server, "", OkHttpClient(), permit) { store.account(account.id) }
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
            val access = VaultAccess(account, server, "", OkHttpClient(), permit) { store.account(account.id) }
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
                httpClient = OkHttpClient(),
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

data class VaultLocation(
    val accountId: String,
    val title: String,
    val kind: VaultLocationKind,
    val driveId: String,
    /** Stable DAV file id for the vault root, distinct from Graph's drive id. */
    val remoteVaultId: String,
    /** Stable Graph root id for source revalidation. */
    val sourceRootId: String,
    val canonicalServer: String,
    val rootWebDavUrl: String,
    val vaultPath: String,
    val isVaultRoot: Boolean,
    val isDisabled: Boolean = false,
    val offlineOnly: Boolean = false,
    val offlineUnavailable: Boolean = false,
)

enum class VaultLocationKind {
    PERSONAL,
    SPACE,
    FOLDER_VAULT,
    SPACE_VAULT,
}

data class VaultFolder(
    val id: String,
    val name: String,
    val rawName: String,
    /** Plain relative path for navigation in an unlocked session or a plain source root. */
    val path: String,
    /** Opaque relative DAV path; never use as a local filesystem path. */
    val encryptedPath: String,
    val isFolder: Boolean,
    val size: Long,
    val strongETag: String?,
    val contentType: String? = null,
    val isVaultRoot: Boolean = false,
    internal val leaseId: String? = null,
)

enum class VaultUnlockFailure {
    PASSWORD_NOT_PROVEN,
}

/** The remote root may already exist; callers must show this state and must not auto-retry. */
class VaultCreationException(
    val remoteIdentifierOrPath: String,
    cause: Throwable,
) : IllegalStateException("Vault creation may have completed remotely; inspect before retrying.", cause)

class VaultUnlockException(
    val failure: VaultUnlockFailure,
) : IllegalStateException("The vault password could not be verified.")

/** Narrow seam permits transport/session tests without loading Android's native Sodium binding. */
internal interface VaultCipherEngine : AutoCloseable {
    fun createIntegrityToken(): String

    fun verifyIntegrityToken(base64Token: String): Boolean

    fun decryptName(encrypted: String): String

    fun decryptPath(encrypted: String): String

    fun encryptName(plain: String): String

    fun encryptPath(plain: String): String

    fun encryptContent(
        input: InputStream,
        output: OutputStream,
        maximumPlaintextBytes: Long,
    ): Long

    fun decryptContent(
        input: InputStream,
        output: OutputStream,
        maximumPlaintextBytes: Long,
    ): Long

    fun exportKeyMaterial(): ByteArray

    /** Only engines with an independent content cipher may support concurrent boundary pipes. */
    fun forkForContent(): VaultCipherEngine = throw OpenCloudException(OpenCloudError.Unsupported)
}

internal data class VaultCipherFactories(
    val password: (CharArray) -> VaultCipherEngine,
    val keyMaterial: (ByteArray) -> VaultCipherEngine,
)

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

internal fun RcloneVaultCipher.asVaultCipher(): VaultCipherEngine =
    object : VaultCipherEngine {
        override fun createIntegrityToken() = this@asVaultCipher.createIntegrityToken()

        override fun verifyIntegrityToken(base64Token: String) = this@asVaultCipher.verifyIntegrityToken(base64Token)

        override fun decryptName(encrypted: String) = this@asVaultCipher.decryptName(encrypted)

        override fun decryptPath(encrypted: String) = this@asVaultCipher.decryptPath(encrypted)

        override fun encryptName(plain: String) = this@asVaultCipher.encryptName(plain)

        override fun encryptPath(plain: String) = this@asVaultCipher.encryptPath(plain)

        override fun encryptContent(
            input: InputStream,
            output: OutputStream,
            maximumPlaintextBytes: Long,
        ) = this@asVaultCipher.encryptContent(input, output, maximumPlaintextBytes)

        override fun decryptContent(
            input: InputStream,
            output: OutputStream,
            maximumPlaintextBytes: Long,
        ) = authenticatedVaultContent { this@asVaultCipher.decryptContent(input, output, maximumPlaintextBytes) }

        override fun exportKeyMaterial() = this@asVaultCipher.exportKeyMaterial()

        override fun forkForContent(): VaultCipherEngine {
            val material = this@asVaultCipher.exportKeyMaterial()
            return try {
                RcloneVaultCipher.fromKeyMaterial(material).asVaultCipher()
            } finally {
                material.fill(0)
            }
        }

        override fun close() = this@asVaultCipher.close()
    }

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

internal class VaultAccess(
    val account: AccountEntity,
    val canonicalServer: String,
    authorizationValue: String,
    httpClient: OkHttpClient,
    val permit: () -> Boolean,
    private val currentAccount: suspend () -> AccountEntity?,
) {
    var authorization: String = authorizationValue
        internal set
    var http: OkHttpClient = httpClient
        internal set

    suspend fun requireCurrent() {
        currentCoroutineContext().ensureActive()
        if (!permit()) throw OpenCloudException(OpenCloudError.AccessDenied)
        if (currentAccount() != account) throw OpenCloudException(OpenCloudError.PreconditionFailed)
        currentCoroutineContext().ensureActive()
    }
}

private class WipingByteArrayOutputStream(
    initialSize: Int,
) : ByteArrayOutputStream(initialSize) {
    fun wipe() {
        buf.fill(0)
        reset()
    }

    fun copyBytes(): ByteArray = toByteArray()
}

private fun VaultDavEntry.toFolder(
    path: String,
    isVaultRoot: Boolean,
    displayName: String = rawName,
    leaseId: String? = null,
) = VaultFolder(
    id = id,
    name = displayName,
    rawName = rawName,
    path = path,
    encryptedPath = relativePath,
    isFolder = isFolder,
    size = size,
    strongETag = strongETag,
    isVaultRoot = isVaultRoot,
    leaseId = leaseId,
)

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

private fun joinDavPaths(
    first: String,
    second: String,
): String = listOf(first, second).filter(String::isNotEmpty).joinToString("/")

internal fun validateVaultExcludedPath(path: String?): String? =
    path?.let {
        if (it.isEmpty()) throw OpenCloudException(OpenCloudError.Unsupported)
        validatePlainPath(it)
    }

internal fun vaultChildVisible(
    name: String,
    path: String,
    showHidden: Boolean,
    excludedPath: String?,
): Boolean {
    val hidden = !showHidden && name.startsWith('.')
    val excluded = excludedPath != null && (path == excludedPath || path.startsWith("$excludedPath/"))
    return !hidden && !excluded
}

private fun validatePlainPath(path: String): String {
    if (path.isEmpty()) return path
    val segments = path.split('/')
    if (path.startsWith('/') ||
        path.endsWith('/') ||
        segments.any(::isInvalidPlainSegment)
    ) {
        throw OpenCloudException(OpenCloudError.Unsupported)
    }
    return path
}

private fun validateSingleName(name: String): String {
    if (name.isEmpty() || name.length > 255) throw OpenCloudException(OpenCloudError.Unsupported)
    if (hasInvalidNameStructure(name)) throw OpenCloudException(OpenCloudError.Unsupported)
    return name
}

private fun hasInvalidNameStructure(name: String): Boolean {
    val traversal = name == "." || name == ".."
    val separator = name.contains('/') || name.contains('\\')
    return traversal || separator || name.any(Char::isISOControl)
}

private fun vaultFolderName(name: String): String {
    val safeName = validateSingleName(name.removeSuffix(".vault"))
    return "$safeName.vault"
}

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

/** Private ciphertext-only staging for SAF providers that omit a source length. */
private object VaultCiphertextSpools {
    private val active = mutableSetOf<String>()

    @Suppress("ComplexCondition") // Only abandoned ciphertext stages with this exact naming scheme are deleted.
    @Synchronized
    fun removeStale(directory: File) {
        if (!directory.exists()) return
        if (!directory.isDirectory) throw OpenCloudException(OpenCloudError.Unsupported)
        directory.listFiles()?.forEach { file ->
            if (file.isFile &&
                file.name.startsWith("vault-") &&
                file.name.endsWith(".ciphertext") &&
                file.path !in active
            ) {
                file.delete()
            }
        }
    }

    @Synchronized fun create(directory: File): File {
        if (!directory.isDirectory && !directory.mkdirs()) throw OpenCloudException(OpenCloudError.Unsupported)
        val file = File.createTempFile("vault-", ".ciphertext", directory)
        active += file.path
        return file
    }

    @Synchronized fun delete(file: File) {
        file.delete()
        active -= file.path
    }
}

private fun isInvalidPlainSegment(segment: String): Boolean =
    segment in setOf("", ".", "..") || segment.any(Char::isISOControl) || segment.contains('\\')

internal fun resolveEntryHref(
    root: String,
    relativePath: String,
): String =
    root
        .toHttpUrl()
        .newBuilder()
        .apply { relativePath.split('/').forEach(::addPathSegment) }
        .build()
        .toString()
