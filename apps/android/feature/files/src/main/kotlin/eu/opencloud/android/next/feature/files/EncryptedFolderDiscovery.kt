package eu.opencloud.android.next.feature.files

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultLocationKind
import eu.opencloud.android.next.core.sync.VaultOfflineStore
import eu.opencloud.android.next.core.sync.VaultRepository
import eu.opencloud.android.next.core.sync.VaultRootCatalog
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Transient discovery state: encrypted entries never enter the ordinary resource database. */
@Suppress("LongParameterList")
internal class EncryptedFolderDiscovery(
    private val context: Context,
    private val store: FileBrowserStore,
    private val scope: CoroutineScope,
    private val reads: EncryptedFolderRootReads? = null,
    private val mainDispatcher: CoroutineDispatcher = Dispatchers.Main.immediate,
    private val update: (List<VaultLocation>, String?) -> Unit,
) {
    private val vaults = VaultRepository(context, store)
    private val offlineVaults = VaultOfflineStore(context)
    private val rootCatalog = VaultRootCatalog(context)

    private var job: Job? = null
    private var generation = 0L

    /** Called on Main for every real account load, including accounts with no available Space. */
    fun invalidate() {
        generation = Math.incrementExact(generation)
        job?.cancel()
        job = null
        update(emptyList(), null)
    }

    @Suppress("TooGenericExceptionCaught") // UI boundary preserves cancellation and exposes safe errors.
    fun refresh(
        accountId: String,
        spaceId: String,
        folderId: String?,
    ) {
        invalidate()
        val token = generation
        job =
            scope.launch {
                try {
                    val roots =
                        withContext(Dispatchers.IO) {
                            if (reads != null) {
                                reads.load(accountId, spaceId, folderId) { cached -> publish(token, cached, null) }
                            } else {
                                val path =
                                    folderId
                                        ?.let { requireNotNull(store.resource(accountId, spaceId, it)).path.trim('/') }
                                        .orEmpty()
                                discoverEncryptedFolderRoots(
                                    accountId = accountId,
                                    driveId = spaceId,
                                    parentPath = path,
                                    loadOffline = { offlineVaults.locations(accountId) },
                                    loadRemembered = { rootCatalog.folderRoots(accountId, spaceId, path) },
                                    loadOnline = { vaults.encryptedFolders(accountId, spaceId, path) },
                                    rememberOnline = { online ->
                                        rootCatalog.replaceFolderRoots(accountId, spaceId, path, online)
                                    },
                                    onCached = { cached ->
                                        publish(token, cached, null)
                                    },
                                )
                            }
                        }
                    publish(token, roots, null)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: Exception) {
                    publish(token, emptyList(), failure.toOpenCloudError().safeMessage(context))
                }
            }
    }

    private suspend fun publish(
        token: Long,
        roots: List<VaultLocation>,
        error: String?,
    ) {
        withContext(mainDispatcher) {
            if (generation == token) update(roots, error)
        }
    }
}

internal fun interface EncryptedFolderRootReads {
    suspend fun load(
        account: String,
        space: String,
        folder: String?,
        cached: suspend (List<VaultLocation>) -> Unit,
    ): List<VaultLocation>
}

/** Uses saved roots only when live discovery is unavailable; online absence remains authoritative. */
@Suppress(
    "TooGenericExceptionCaught",
    "LongParameterList",
    "CyclomaticComplexMethod",
    "ThrowsCount",
) // This boundary coordinates independent sources while preserving cancellation and authoritative denial semantics.
internal suspend fun discoverEncryptedFolderRoots(
    accountId: String,
    driveId: String,
    parentPath: String,
    loadOffline: suspend () -> List<VaultLocation>,
    loadRemembered: suspend () -> List<VaultLocation> = { emptyList() },
    loadOnline: suspend () -> List<VaultLocation>,
    rememberOnline: suspend (List<VaultLocation>) -> Unit = {},
    onCached: suspend (List<VaultLocation>) -> Unit = {},
): List<VaultLocation> {
    val saved =
        try {
            offlineFolderRoots(loadOffline(), accountId, driveId, parentPath)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            emptyList()
        }
    val remembered =
        try {
            offlineFolderRoots(loadRemembered(), accountId, driveId, parentPath)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            emptyList()
        }
    val cached = offlineRootAvailability(mergeRootDescriptors(remembered, saved), saved)
    if (cached.isNotEmpty()) onCached(cached)
    return try {
        val online = loadOnline().map { it.copy(offlineOnly = false, offlineUnavailable = false) }
        try {
            rememberOnline(online)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            // Persistent offline discovery is optional; live roots remain usable if the cache cannot be written.
        }
        online
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (failure: Exception) {
        when (val error = failure.toOpenCloudError()) {
            OpenCloudError.Connectivity, OpenCloudError.Timeout -> if (cached.isNotEmpty()) cached else throw failure
            is OpenCloudError.ServerFailure ->
                if (error.statusCode in 500..599 &&
                    cached.isNotEmpty()
                ) {
                    cached
                } else {
                    throw failure
                }
            else -> throw failure
        }
    }
}

internal fun mergeRootDescriptors(
    preferred: List<VaultLocation>,
    other: List<VaultLocation>,
): List<VaultLocation> = (preferred + other).distinctBy(::rootIdentityKey)

internal fun offlineRootAvailability(
    remembered: List<VaultLocation>,
    saved: List<VaultLocation>,
): List<VaultLocation> {
    val savedKeys = saved.mapTo(mutableSetOf(), ::rootDescriptorKey)
    return remembered.map { root ->
        root.copy(offlineOnly = true, offlineUnavailable = rootDescriptorKey(root) !in savedKeys)
    }
}

internal fun rootDescriptorKey(location: VaultLocation) =
    listOf(
        location.accountId,
        location.canonicalServer,
        location.driveId,
        location.remoteVaultId,
        location.rootWebDavUrl,
        location.vaultPath.trim('/'),
    )

private fun rootIdentityKey(location: VaultLocation) =
    listOf(location.accountId, location.canonicalServer, location.driveId, location.remoteVaultId)

internal fun offlineFolderRoots(
    locations: List<VaultLocation>,
    accountId: String,
    driveId: String,
    parentPath: String?,
): List<VaultLocation> {
    val parent = parentPath.orEmpty().trim('/')
    return locations
        .filter { location ->
            val vaultPath = location.vaultPath.trim('/')
            location.accountId == accountId &&
                location.driveId == driveId &&
                location.kind == VaultLocationKind.FOLDER_VAULT &&
                location.isVaultRoot &&
                vaultPath.substringBeforeLast('/', "") == parent
        }.map { it.copy(offlineOnly = true) }
}
