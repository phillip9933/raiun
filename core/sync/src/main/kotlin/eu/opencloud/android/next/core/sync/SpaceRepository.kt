package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.network.LibreGraphSpacesClient
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** A locally superseded discovery result must never be reported as a remote conflict. */
class SupersededDiscovery : Exception()

class SpaceRepository(
    private val store: FileBrowserStore,
    private val remote: LibreGraphSpacesClient? = null,
    private val pendingCreations: PendingSpaceCreationStore = InMemoryPendingSpaceCreationStore(),
) {
    fun observe(accountId: String): Flow<List<SpaceEntity>> = store.observeSpaces(accountId)

    fun observeProjectSpaces(accountId: String): Flow<List<SpaceEntity>> =
        observe(accountId).map { spaces ->
            spaces.filter { space ->
                space.type.equals(PROJECT_DRIVE_TYPE, ignoreCase = true) &&
                    !space.isDisabled &&
                    !space.isDeleted
            }
        }

    suspend fun synchronize(
        accountId: String,
        serverUrl: String,
        authorization: String,
        includeAllSpaces: Boolean = false,
    ): List<SpaceEntity> {
        val token = store.beginSnapshot(accountId)
        val discovery =
            requireNotNull(remote) { "The Libre Graph Spaces client is unavailable." }
                .snapshot(serverUrl, authorization, includeAllSpaces)
        return discovery.spaces
            .map { space ->
                SpaceEntity(
                    accountId = accountId,
                    driveId = space.id,
                    name = space.name,
                    type = space.type,
                    description = space.description,
                    ownerName = space.ownerName,
                    rootId = space.rootId,
                    rootWebDavUrl = space.rootWebDavUrl,
                    rootETag = space.rootETag,
                    quotaBytes = space.quotaTotalBytes,
                    isDisabled = space.disabled,
                    isDeleted = space.deleted,
                    driveAlias = space.driveAlias,
                    webUrl = space.webUrl,
                    ownerId = space.ownerId,
                    lastModifiedDateTime = space.lastModifiedDateTime,
                    quotaUsedBytes = space.quotaUsedBytes,
                    quotaRemainingBytes = space.quotaRemainingBytes,
                    quotaState = space.quotaState,
                )
            }.also {
                if (!store.replaceRemoteSpaces(accountId, it, token, discovery.excludedVaultIds)) {
                    throw SupersededDiscovery()
                }
            }
    }

    /** Refreshes only one management target while preserving the rest of the ordinary account snapshot. */
    internal suspend fun synchronizeManagedSpace(request: ManagedSpaceRefresh): SpaceEntity? {
        val token = store.beginSnapshot(request.accountId)
        val discovery =
            requireNotNull(remote) { "The Libre Graph Spaces client is unavailable." }
                .snapshot(request.serverUrl, request.authorization, includeAllSpaces = true)
        val target = discovery.spaces.firstOrNull { it.id == request.driveId }
        val confirmedTarget = target?.toEntity(request.accountId)
        if ((target == null && !request.allowMissing) || !request.validate(confirmedTarget)) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
        val wasStored = store.space(request.accountId, request.driveId) != null
        val retained = observe(request.accountId).first().filterNot { it.driveId == request.driveId }
        val merged = retained + listOfNotNull(confirmedTarget?.takeIf { wasStored })
        if (!store.replaceRemoteSpaces(
                request.accountId,
                merged,
                token,
            )
        ) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
        return confirmedTarget
    }

    suspend fun createProjectSpace(
        accountId: String,
        serverUrl: String,
        authorization: String,
        name: String,
    ): SpaceCreationResult {
        require(name.isNotBlank()) { "Enter a space name." }
        val client = requireNotNull(remote) { "The Libre Graph Spaces client is unavailable." }
        val key = PendingSpaceCreationKey.create(accountId, serverUrl, name)
        val mutex = SpaceCreationLocks.forKey(key)
        return mutex.withLock {
            val pendingId = pendingCreations.get(key)
            val driveId = pendingId ?: client.createProjectSpace(serverUrl, authorization, key.normalizedName)
            if (pendingId == null) {
                try {
                    // Record the acknowledgement before the next suspension point.
                    pendingCreations.put(key, driveId)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Exception) {
                    // The server has accepted the create; never report it as safely retryable.
                    return@withLock SpaceCreationResult.AwaitingDiscovery(driveId, retrySafe = false)
                }
            }

            val spaces =
                try {
                    synchronize(accountId, serverUrl, authorization)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Exception) {
                    return@withLock SpaceCreationResult.AwaitingDiscovery(driveId)
                }
            val visible =
                spaces.firstOrNull { it.driveId == driveId }
                    ?: return@withLock SpaceCreationResult.AwaitingDiscovery(driveId)
            forgetAcknowledgement(key)
            SpaceCreationResult.Created(visible)
        }
    }

    private fun forgetAcknowledgement(key: PendingSpaceCreationKey) {
        try {
            pendingCreations.remove(key)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            // A stale journal entry only causes another GET of the authoritative visible drive.
        }
    }

    private companion object {
        const val PROJECT_DRIVE_TYPE = "project"
    }
}

internal data class ManagedSpaceRefresh(
    val accountId: String,
    val serverUrl: String,
    val authorization: String,
    val driveId: String,
    val allowMissing: Boolean = false,
    val validate: (SpaceEntity?) -> Boolean = { true },
)

internal fun eu.opencloud.android.next.core.network.RemoteSpace.toEntity(accountId: String) =
    SpaceEntity(
        accountId = accountId,
        driveId = id,
        name = name,
        type = type,
        description = description,
        ownerName = ownerName,
        rootId = rootId,
        rootWebDavUrl = rootWebDavUrl,
        rootETag = rootETag,
        quotaBytes = quotaTotalBytes,
        isDisabled = disabled,
        isDeleted = deleted,
        driveAlias = driveAlias,
        webUrl = webUrl,
        ownerId = ownerId,
        lastModifiedDateTime = lastModifiedDateTime,
        quotaUsedBytes = quotaUsedBytes,
        quotaRemainingBytes = quotaRemainingBytes,
        quotaState = quotaState,
    )

private object SpaceCreationLocks {
    private val mutexes = Array(64) { Mutex() }

    fun forKey(key: PendingSpaceCreationKey): Mutex = mutexes[(key.hashCode() and Int.MAX_VALUE) % mutexes.size]
}
