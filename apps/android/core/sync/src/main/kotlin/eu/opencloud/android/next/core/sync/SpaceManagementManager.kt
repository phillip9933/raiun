package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.LibreGraphSpacesClient
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.ProjectSpaceUpdate
import eu.opencloud.android.next.core.security.TlsPolicy
import okhttp3.OkHttpClient
import java.util.concurrent.ConcurrentHashMap

/** Performs authorized space management and refreshes local state only after server confirmation. */
class SpaceManagementManager private constructor(
    private val store: FileBrowserStore,
    private val authorizationFor: (AccountEntity) -> String,
    private val clientFor: (AccountEntity) -> OkHttpClient,
    private val endpointPolicy: EndpointPolicy,
) {
    private val managedSpaces = ConcurrentHashMap<Pair<String, String>, SpaceEntity>()

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
    )

    internal constructor(
        @Suppress("UNUSED_PARAMETER")
        context: Context,
        store: FileBrowserStore,
        authorizationFor: (AccountEntity) -> String,
        clientFor: (AccountEntity) -> OkHttpClient,
        endpointPolicy: EndpointPolicy,
    ) : this(store, authorizationFor, clientFor, endpointPolicy)

    /** Returns the authoritative management listing without replacing the member-space cache. */
    suspend fun listSpaces(accountId: String): List<SpaceEntity> {
        val session = session(accountId)
        val spaces =
            session.client
                .snapshot(session.account.serverUrl, session.authorization, includeAllSpaces = true)
                .spaces
                .filter { it.type.equals(PROJECT_DRIVE_TYPE, ignoreCase = true) }
                .map { it.toEntity(accountId) }
        managedSpaces.keys.filter { it.first == accountId }.forEach(managedSpaces::remove)
        spaces.forEach { managedSpaces[accountId to it.driveId] = it }
        return spaces
    }

    suspend fun refreshMembership(accountId: String) {
        val session = session(accountId)
        session.repository.synchronize(accountId, session.account.serverUrl, session.authorization)
    }

    suspend fun update(
        accountId: String,
        driveId: String,
        name: String? = null,
        subtitle: String? = null,
        quotaBytes: Long? = null,
    ): SpaceEntity {
        require(name != null || subtitle != null || quotaBytes != null) { "Choose a space property to change." }
        require(name == null || name.isNotBlank()) { "Enter a space name." }
        require(quotaBytes == null || quotaBytes >= 0) { "Quota must be zero or greater." }
        val session = session(accountId)
        val current = requireProjectSpace(accountId, driveId)
        if (current.isDisabled || current.isDeleted) throw OpenCloudException(OpenCloudError.PreconditionFailed)
        val update = ProjectSpaceUpdate(name = name, description = subtitle, quotaBytes = quotaBytes)
        val response =
            session.client.updateProjectSpace(
                session.account.serverUrl,
                session.authorization,
                driveId,
                update,
            )
        if (!update.matches(response)) throw OpenCloudException(OpenCloudError.PreconditionFailed)
        return refreshConfirmed(session, accountId, driveId) { update.matches(it) }
    }

    suspend fun disable(
        accountId: String,
        driveId: String,
    ): SpaceEntity {
        val session = session(accountId)
        val current = requireProjectSpace(accountId, driveId)
        if (current.isDisabled || current.isDeleted) throw OpenCloudException(OpenCloudError.PreconditionFailed)
        session.client.disableProjectSpace(session.account.serverUrl, session.authorization, driveId)
        return refreshConfirmed(session, accountId, driveId) { it != null && it.isDisabled && !it.isDeleted }
    }

    suspend fun enable(
        accountId: String,
        driveId: String,
    ): SpaceEntity {
        val session = session(accountId)
        val current = requireProjectSpace(accountId, driveId)
        if (!current.isDisabled || current.isDeleted) throw OpenCloudException(OpenCloudError.PreconditionFailed)
        session.client.enableProjectSpace(session.account.serverUrl, session.authorization, driveId)
        return refreshConfirmed(session, accountId, driveId) { it != null && !it.isDisabled && !it.isDeleted }
    }

    suspend fun permanentlyDelete(
        accountId: String,
        driveId: String,
    ) {
        val session = session(accountId)
        val current = requireProjectSpace(accountId, driveId)
        if (!current.isDisabled || current.isDeleted) throw OpenCloudException(OpenCloudError.PreconditionFailed)
        session.client.permanentlyDeleteProjectSpace(session.account.serverUrl, session.authorization, driveId)
        session.repository.synchronizeManagedSpace(
            ManagedSpaceRefresh(
                accountId,
                session.account.serverUrl,
                session.authorization,
                driveId,
                allowMissing = true,
                validate = { it == null },
            ),
        )
        managedSpaces.remove(accountId to driveId)
    }

    private suspend fun refreshConfirmed(
        session: SpaceManagementSession,
        accountId: String,
        driveId: String,
        validate: (SpaceEntity?) -> Boolean,
    ): SpaceEntity {
        val confirmed =
            session.repository.synchronizeManagedSpace(
                ManagedSpaceRefresh(
                    accountId,
                    session.account.serverUrl,
                    session.authorization,
                    driveId,
                    validate = validate,
                ),
            ) ?: throw OpenCloudException(OpenCloudError.PreconditionFailed)
        managedSpaces[accountId to driveId] = confirmed
        return confirmed
    }

    private suspend fun requireProjectSpace(
        accountId: String,
        driveId: String,
    ): SpaceEntity {
        val space =
            managedSpaces[accountId to driveId] ?: store.space(accountId, driveId)
                ?: throw OpenCloudException(OpenCloudError.PreconditionFailed)
        if (!space.type.equals(PROJECT_DRIVE_TYPE, ignoreCase = true)) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
        return space
    }

    private suspend fun session(accountId: String): SpaceManagementSession {
        val account = requireNotNull(store.account(accountId)) { "The account is unavailable." }
        val authorization = authorizationFor(account)
        val client = LibreGraphSpacesClient(clientFor(account), endpoints = endpointPolicy)
        return SpaceManagementSession(account, authorization, client, SpaceRepository(store, client))
    }

    private companion object {
        const val PROJECT_DRIVE_TYPE = "project"
    }
}

private fun ProjectSpaceUpdate.matches(space: eu.opencloud.android.next.core.network.RemoteSpace): Boolean =
    (name == null || space.name == name?.trim()) &&
        (description == null || space.description == description) &&
        (quotaBytes == null || space.quotaTotalBytes == quotaBytes)

private fun ProjectSpaceUpdate.matches(space: SpaceEntity?): Boolean =
    space != null &&
        (name == null || space.name == name?.trim()) &&
        (description == null || space.description == description) &&
        (quotaBytes == null || space.quotaBytes == quotaBytes)

private data class SpaceManagementSession(
    val account: AccountEntity,
    val authorization: String,
    val client: LibreGraphSpacesClient,
    val repository: SpaceRepository,
)
