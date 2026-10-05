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
                        dav.list(root.toString(), authorization = access.authorization, recognizedVaultRoot = true).root
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
                    dav.list(root.toString(), authorization = access.authorization, recognizedVaultRoot = true).root
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

            val rootListing = dav.inspectOrdinaryDirectory(root.toString(), authorization = access.authorization)
            access.requireCurrent()
            if (rootListing.requestedIsVaultMarker || !graphRootMatchesDav(space.rootId, rootListing.root.id)) {
                throw OpenCloudException(OpenCloudError.PreconditionFailed)
            }
            val listing =
                if (path.isEmpty()) {
                    rootListing
                } else {
                    dav.inspectOrdinaryDirectory(root.toString(), path, access.authorization)
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
                    val proof = dav.list(root.toString(), vaultPath, access.authorization, recognizedVaultRoot = true)
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
                        dav.list(
                            root.toString(),
                            authorization = access.authorization,
                            recognizedVaultRoot = true,
                        )
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
                            dav.list(
                                root.toString(),
                                authorization = access.authorization,
                                recognizedVaultRoot = true,
                            )
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

    /** Plain locations expose directories only; vault locations expose raw encrypted children. */
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
        val listing =
            dav.list(
                root.toString(),
                path,
                access.authorization,
                recognizedVaultRoot =
                    location.isVaultRoot || location.kind == VaultLocationKind.SPACE_VAULT || path.isNotEmpty(),
            )
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
        val folder =
            dav
                .list(
                    root.toString(),
                    location.vaultPath,
                    access.authorization,
                    recognizedVaultRoot = true,
                ).root
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

    /** Graph elides a space root's repeated opaque ID; DAV retains it as `!spaceId`. */
    private fun graphRootMatchesDav(
        graphRootId: String,
        davRootId: String,
    ): Boolean =
        graphRootId == davRootId ||
            run {
                val parts = graphRootId.split('$')
                val isShortRoot =
                    parts.size == 2 &&
                        parts.all(String::isNotEmpty) &&
                        '!' !in graphRootId
                isShortRoot && davRootId == "$graphRootId!${parts[1]}"
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
        val listing =
            dav.list(
                root.toString(),
                location.vaultPath,
                access.authorization,
                recognizedVaultRoot = true,
            )
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

private fun RcloneVaultCipher.asVaultCipher(): VaultCipherEngine =
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
        ) = this@asVaultCipher.decryptContent(input, output, maximumPlaintextBytes)

        override fun exportKeyMaterial() = this@asVaultCipher.exportKeyMaterial()

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
    private val stateLock = Any()

    suspend fun list(path: String = ""): List<VaultFolder> {
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
        withContext(Dispatchers.IO) {
            requireLease()
            val parent = validatePlainPath(parentPath)
            val safeName = validateSingleName(name)
            verifyWritableVaultRoot()
            val encryptedName = cipher.encryptName(safeName)
            val destination = joinDavPaths(location.vaultPath, joinDavPaths(cipher.encryptPath(parent), encryptedName))
            dav.createCollection(location.rootWebDavUrl, destination, access.authorization)
            access.requireCurrent()
            requireLease()
            verifyVaultRoot()
            list(parent).firstOrNull { it.rawName == encryptedName && it.isFolder }
                ?: throw OpenCloudException(OpenCloudError.InvalidResponse)
        }

    suspend fun delete(entry: VaultFolder) {
        var mutationAttempted = false
        try {
            withContext(Dispatchers.IO) {
                requireLease()
                requireIssuedEntry(entry)
                verifyWritableVaultRoot()
                val etag = entry.strongETag ?: throw OpenCloudException(OpenCloudError.PreconditionFailed)
                mutationAttempted = true
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
                val before = dav.list(location.rootWebDavUrl, oldPath, access.authorization, recognizedVaultRoot = true)
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
                val after = dav.list(location.rootWebDavUrl, newPath, access.authorization, recognizedVaultRoot = true)
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
            withContext(Dispatchers.IO) {
                requireLease()
                requireIssuedEntry(entry)
                val parent = validatePlainPath(destinationPath)
                requireMoveDestination(entry, parent)
                verifyWritableVaultRoot()
                val encryptedName = cipher.encryptName(newName)
                val destination =
                    joinDavPaths(location.vaultPath, joinDavPaths(cipher.encryptPath(parent), encryptedName))
                val etag = requiredEntryETag(entry)
                mutationAttempted = true
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
                requireListedDestination(list(parent), encryptedName)
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
    ): VaultFolder =
        withContext(Dispatchers.IO) {
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
                            cipher.encryptContent(
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
                    mutationAttempted = true
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
                            val written = cipher.encryptContent(guardedSource, guardedOutput, size)
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
            list(parent).firstOrNull { it.rawName == encryptedName && !it.isFolder }
                ?: throw OpenCloudException(OpenCloudError.InvalidResponse)
        }

    /** Streams authenticated blocks to the caller's new destination; caller removes it on failure. */
    suspend fun download(
        entry: VaultFolder,
        sink: OutputStream,
        maxPlaintextBytes: Long = Long.MAX_VALUE,
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
                    cipher.decryptContent(
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

    /** Authenticated snapshot metadata stays in memory while the live encrypted session is unlocked. */
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
        if (entry.leaseId?.let(issuedEntries::get) != entry || entry.isVaultRoot) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
        requireEntryInsideVault(entry)
    }

    private fun removeIssuedEntry(entry: VaultFolder) {
        synchronized(stateLock) {
            entry.leaseId?.let { token ->
                if (issuedEntries[token] === entry) issuedEntries.remove(token)
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
    internal fun issuedEntryCountForTesting(): Int = issuedEntries.size

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
        val shouldClose =
            synchronized(stateLock) {
                if (!closed.compareAndSet(false, true)) {
                    false
                } else {
                    issuedEntries.clear()
                    true
                }
            }
        if (shouldClose) {
            cipher.close()
        }
    }

    private suspend fun requireLease() {
        if (closed.get() || !access.permit() || !generationIsCurrent()) {
            throw OpenCloudException(OpenCloudError.AccessDenied)
        }
        access.requireCurrent()
    }

    private suspend fun verifyVaultRoot() {
        requireLease()
        val root = location.rootWebDavUrl.toHttpUrl()
        val listing =
            dav.list(
                root.toString(),
                location.vaultPath,
                access.authorization,
                recognizedVaultRoot = true,
            )
        access.requireCurrent()
        requireLease()
        if (!listing.root.isFolder || listing.root.id != identity.remoteVaultId) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
    }

    /** Writes require a fresh authenticated token; read-only unlock may still use file-block proof. */
    private suspend fun verifyWritableVaultRoot() {
        requireLease()
        val listing =
            dav.list(
                location.rootWebDavUrl,
                location.vaultPath,
                access.authorization,
                recognizedVaultRoot = true,
            )
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

private fun isFolderVault(entry: VaultDavEntry): Boolean =
    entry.isFolder && (entry.rawName.endsWith(".vault") || entry.isVaultMarker)

private fun joinDavPaths(
    first: String,
    second: String,
): String = listOf(first, second).filter(String::isNotEmpty).joinToString("/")

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

private fun requireListedDestination(
    entries: List<VaultFolder>,
    encryptedName: String,
): VaultFolder =
    entries.firstOrNull { it.rawName == encryptedName }
        ?: throw OpenCloudException(OpenCloudError.InvalidResponse)

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

private fun resolveEntryHref(
    root: String,
    relativePath: String,
): String =
    root
        .toHttpUrl()
        .newBuilder()
        .apply { relativePath.split('/').forEach(::addPathSegment) }
        .build()
        .toString()
