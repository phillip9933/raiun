package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.LibreGraphSpacesClient
import eu.opencloud.android.next.core.network.OcsShareType
import eu.opencloud.android.next.core.network.OcsSharingClient
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.ProjectSpaceUpdate
import eu.opencloud.android.next.core.network.RemoteShare
import eu.opencloud.android.next.core.network.RemoteSpace
import eu.opencloud.android.next.core.network.ShareRecipient
import eu.opencloud.android.next.core.network.SpaceMembers
import eu.opencloud.android.next.core.network.SpaceMembersClient
import eu.opencloud.android.next.core.security.AppLock
import eu.opencloud.android.next.core.security.TlsPolicy
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import okhttp3.OkHttpClient

/** Graph management for vault Spaces, kept outside ordinary SpaceEntity and file APIs. */
class EncryptedLocationManagementRepository internal constructor(
    private val dependencies: EncryptedManagementDependencies,
) {
    constructor(context: Context) : this(EncryptedManagementDependencies.live(context))

    private val endpoints = dependencies.endpoints

    /** Lists disabled encrypted Spaces using Graph metadata only; it never opens DAV or a vault session. */
    suspend fun disabledSpaces(accountId: String): List<VaultLocation> {
        val account = requireManagementAccount(accountId)
        val auth = dependencies.authorizationFor(account)
        val graph = LibreGraphSpacesClient(dependencies.clientFor(account), endpoints = endpoints)
        val snapshot = graph.snapshot(account.serverUrl, auth, includeAllSpaces = true, includeVaultDetails = true)
        if (dependencies.accountFor(accountId) != account) failChanged()
        return snapshot.vaultSpaces
            .filter { it.type.equals("project", true) && it.disabled && !it.deleted }
            .map {
                it.toVaultLocation(
                    accountId,
                    endpoints.endpoint(account.serverUrl, allowQuery = false).toString(),
                    disabled = true,
                )
            }
    }

    /** Disables an unlocked encrypted Space while leaving all key material local and untouched. */
    suspend fun disableSpace(
        accountId: String,
        location: VaultLocation,
        isUnlocked: () -> Boolean,
    ): VaultLocation {
        val scope = lifecycleScope(accountId, location, isUnlocked = isUnlocked, requireDisabled = false)
        scope.requireFreshTarget()
        // Graph's mutation endpoint is authoritative for manager, custom-role, and administrator access.
        // Guessing from the local role name would reject users the server explicitly permits.
        scope.graph.disableProjectSpace(scope.server, scope.auth, location.driveId)
        scope.checkCurrent()
        val disabled = scope.currentSpace(true)
        return disabled.toVaultLocation(accountId, location.canonicalServer, disabled = true)
    }

    /** Restores a disabled encrypted Space from Graph metadata without opening its encrypted content. */
    suspend fun restoreDisabledSpace(
        accountId: String,
        location: VaultLocation,
    ): VaultLocation {
        val scope = lifecycleScope(accountId, location, isUnlocked = null, requireDisabled = true)
        scope.requireFreshTarget()
        scope.graph.enableProjectSpace(scope.server, scope.auth, location.driveId)
        scope.checkCurrent()
        return scope
            .currentSpace(false)
            .toVaultLocation(accountId, location.canonicalServer, disabled = false)
    }

    /** Permanently removes an already disabled encrypted Space using the server's Purge operation. */
    suspend fun permanentlyDeleteDisabledSpace(
        accountId: String,
        location: VaultLocation,
    ) {
        val scope = lifecycleScope(accountId, location, isUnlocked = null, requireDisabled = true)
        scope.requireFreshTarget()
        scope.graph.permanentlyDeleteProjectSpace(scope.server, scope.auth, location.driveId)
        scope.checkCurrent()
        val after = scope.graph.snapshot(scope.server, scope.auth, includeAllSpaces = true, includeVaultDetails = true)
        val remains =
            (after.vaultSpaces + after.spaces).any {
                it.id == location.driveId && it.rootId == location.sourceRootId
            }
        scope.checkCurrent()
        if (remains) failChanged()
    }

    suspend fun spaceDetails(
        accountId: String,
        location: VaultLocation,
        isUnlocked: () -> Boolean,
    ): EncryptedSpaceDetails =
        withSpace(accountId, location, isUnlocked) { scope ->
            requireNotNull(scope.space).toDetails(scope.location)
        }

    @Suppress("LongParameterList") // Explicit scoped target, unlock lease and three independent Graph fields.
    suspend fun updateSpace(
        accountId: String,
        location: VaultLocation,
        isUnlocked: () -> Boolean,
        name: String? = null,
        subtitle: String? = null,
        quotaBytes: Long? = null,
    ): EncryptedSpaceDetails =
        withSpace(accountId, location, isUnlocked) { scope ->
            require(name != null || subtitle != null || quotaBytes != null)
            require(name == null || name.isNotBlank())
            require(quotaBytes == null || quotaBytes >= 0)
            val update = ProjectSpaceUpdate(name = name, description = subtitle, quotaBytes = quotaBytes)
            scope.requireFreshTarget()
            val result = scope.graph.updateProjectSpace(scope.server, scope.auth, location.driveId, update)
            scope.checkCurrent()
            if (!update.matches(result)) failChanged()
            val confirmed = scope.currentSpace()
            if (!update.matches(confirmed)) failChanged()
            confirmed.toDetails(scope.location.copy(title = confirmed.name))
        }

    suspend fun listMembers(
        accountId: String,
        location: VaultLocation,
        isUnlocked: () -> Boolean,
    ): SpaceMembers =
        withSpace(accountId, location, isUnlocked) { scope ->
            scope.members.list(scope.server, scope.auth, location.driveId).also { scope.checkCurrent() }
        }

    suspend fun searchRecipients(
        accountId: String,
        location: VaultLocation,
        query: String,
        isUnlocked: () -> Boolean,
    ): List<ShareRecipient> =
        if (location.kind == VaultLocationKind.FOLDER_VAULT) {
            searchFolderRootRecipients(accountId, location, query, isUnlocked)
        } else {
            withSpace(accountId, location, isUnlocked) { scope ->
                require(query.trim().length >= 2)
                scope.ocs
                    .searchRecipients(scope.server, scope.auth, query.trim())
                    .filter { it.type in setOf(OcsShareType.USER, OcsShareType.GROUP) }
                    .also { scope.checkCurrent() }
            }
        }

    suspend fun searchFolderRootRecipients(
        accountId: String,
        location: VaultLocation,
        query: String,
        isUnlocked: () -> Boolean,
    ): List<ShareRecipient> =
        withFolderRoot(accountId, location, isUnlocked) { scope ->
            require(query.trim().length >= 2)
            scope.ocs
                .searchRecipients(scope.server, scope.auth, query.trim())
                .filter { it.type in setOf(OcsShareType.USER, OcsShareType.GROUP) }
                .also { scope.checkCurrent() }
        }

    suspend fun addMember(
        accountId: String,
        location: VaultLocation,
        recipient: ShareRecipient,
        role: String,
        isUnlocked: () -> Boolean,
    ) = withSpace(accountId, location, isUnlocked) { scope ->
        require(recipient.type in setOf(OcsShareType.USER, OcsShareType.GROUP))
        require(
            scope.members
                .list(scope.server, scope.auth, location.driveId)
                .roles
                .any { it.id == role },
        )
        scope.requireFreshTarget()
        scope.members.add(scope.server, scope.auth, location.driveId, recipient, role)
        scope.checkCurrent()
    }

    suspend fun changeMemberRole(
        accountId: String,
        location: VaultLocation,
        permissionId: String,
        role: String,
        isUnlocked: () -> Boolean,
    ) = withSpace(accountId, location, isUnlocked) { scope ->
        val current = scope.members.list(scope.server, scope.auth, location.driveId)
        require(current.members.any { it.id == permissionId } && current.roles.any { it.id == role })
        scope.requireFreshTarget()
        scope.members.update(scope.server, scope.auth, location.driveId, permissionId, role)
        scope.checkCurrent()
    }

    suspend fun removeMember(
        accountId: String,
        location: VaultLocation,
        permissionId: String,
        isUnlocked: () -> Boolean,
    ) = withSpace(accountId, location, isUnlocked) { scope ->
        require(
            scope.members
                .list(scope.server, scope.auth, location.driveId)
                .members
                .any { it.id == permissionId },
        )
        scope.requireFreshTarget()
        scope.members.remove(scope.server, scope.auth, location.driveId, permissionId)
        scope.checkCurrent()
    }

    /** Only named shares of this exact encrypted folder root are exposed. */
    suspend fun listFolderRootShares(
        accountId: String,
        location: VaultLocation,
        isUnlocked: () -> Boolean,
    ): List<RemoteShare> = withFolderRoot(accountId, location, isUnlocked) { scope -> scope.folderShares() }

    suspend fun addFolderRootShare(
        accountId: String,
        location: VaultLocation,
        recipient: ShareRecipient,
        permissions: Int,
        isUnlocked: () -> Boolean,
    ): RemoteShare =
        withFolderRoot(accountId, location, isUnlocked) { scope ->
            require(recipient.type in setOf(OcsShareType.USER, OcsShareType.GROUP))
            require(permissions in setOf(1, 15, 31))
            scope.requireFreshTarget()
            val created =
                scope.ocs.createShare(
                    scope.server,
                    scope.auth,
                    eu.opencloud.android.next.core.network.CreateShareRequest(
                        path = location.vaultPath,
                        resourceId = location.remoteVaultId,
                        type = recipient.type,
                        shareWith = recipient.shareWith,
                        permissions = permissions,
                    ),
                )
            scope.checkCurrent()
            if (!created.isExactFolderShare(location)) failChanged()
            created
        }

    suspend fun updateFolderRootShare(
        accountId: String,
        location: VaultLocation,
        shareId: String,
        permissions: Int,
        isUnlocked: () -> Boolean,
    ): RemoteShare =
        withFolderRoot(accountId, location, isUnlocked) { scope ->
            require(permissions in setOf(1, 15, 31))
            require(scope.folderShares().any { it.id == shareId })
            scope.requireFreshTarget()
            val updated =
                scope.ocs.updateShare(
                    scope.server,
                    scope.auth,
                    shareId,
                    eu.opencloud.android.next.core.network
                        .UpdateShareRequest(permissions = permissions),
                )
            scope.checkCurrent()
            if (!updated.isExactFolderShare(location)) failChanged()
            updated
        }

    suspend fun removeFolderRootShare(
        accountId: String,
        location: VaultLocation,
        shareId: String,
        isUnlocked: () -> Boolean,
    ) = withFolderRoot(accountId, location, isUnlocked) { scope ->
        require(scope.folderShares().any { it.id == shareId })
        scope.requireFreshTarget()
        scope.ocs.revokeShare(scope.server, scope.auth, shareId)
        scope.checkCurrent()
    }

    @Suppress("CyclomaticComplexMethod", "ComplexCondition") // Fail-closed account, kind, root and lease checks.
    private suspend fun <T> withSpace(
        accountId: String,
        expected: VaultLocation,
        isUnlocked: () -> Boolean,
        action: suspend (SpaceScope) -> T,
    ): T {
        if (expected.accountId != accountId ||
            expected.kind != VaultLocationKind.SPACE_VAULT ||
            !expected.isVaultRoot ||
            expected.vaultPath.isNotEmpty()
        ) {
            failChanged()
        }
        val permit = dependencies.permitFor()

        fun checkLease() {
            if (!permit() || !isUnlocked()) throw OpenCloudException(OpenCloudError.AccessDenied)
        }
        checkLease()
        val account =
            dependencies.accountFor(accountId) ?: throw OpenCloudException(OpenCloudError.AuthenticationRequired)
        if (!account.isActive ||
            endpoints.endpoint(account.serverUrl, allowQuery = false).toString() != expected.canonicalServer
        ) {
            failChanged()
        }
        // VaultRepository rediscovers the Graph marker and validates the DAV root's stable ID.
        val current = dependencies.spaceRootsFor(accountId).firstOrNull { it.sameRoot(expected) } ?: failChanged()
        checkLease()
        if (dependencies.accountFor(accountId) != account) failChanged()
        val auth = dependencies.authorizationFor(account)
        checkLease()
        val http = dependencies.clientFor(account)
        val scope =
            SpaceScope(
                server = account.serverUrl,
                auth = auth,
                location = current,
                graph = LibreGraphSpacesClient(http, endpoints = endpoints),
                members = SpaceMembersClient(http, endpoints),
                ocs = OcsSharingClient(http),
                checkCurrent = {
                    currentCoroutineContext().ensureActive()
                    checkLease()
                    if (dependencies.accountFor(accountId) != account) failChanged()
                },
                requireFreshTarget = {
                    currentCoroutineContext().ensureActive()
                    checkLease()
                    if (dependencies.spaceRootsFor(accountId).none { it.sameRoot(expected) }) failChanged()
                    checkLease()
                    if (dependencies.accountFor(accountId) != account) failChanged()
                },
            )
        val verified = scope.copy(space = scope.currentSpace())
        val result = action(verified)
        verified.checkCurrent()
        return result
    }

    // Explicit account, root, app-lock, unlock, and current Graph identity checks form one fail-closed scope.
    @Suppress("CyclomaticComplexMethod", "ComplexCondition")
    private suspend fun lifecycleScope(
        accountId: String,
        expected: VaultLocation,
        isUnlocked: (() -> Boolean)?,
        requireDisabled: Boolean,
    ): LifecycleScope {
        if (expected.accountId != accountId ||
            expected.kind != VaultLocationKind.SPACE_VAULT ||
            !expected.isVaultRoot ||
            expected.vaultPath.isNotEmpty() ||
            expected.offlineOnly ||
            expected.isDisabled != requireDisabled
        ) {
            failChanged()
        }
        val permit = dependencies.permitFor()

        fun checkAccess() {
            if (!permit() || (isUnlocked != null && !isUnlocked())) {
                throw OpenCloudException(OpenCloudError.AccessDenied)
            }
        }
        checkAccess()
        val account = requireManagementAccount(accountId)
        if (endpoints.endpoint(account.serverUrl, allowQuery = false).toString() !=
            expected.canonicalServer
        ) {
            failChanged()
        }
        val auth = dependencies.authorizationFor(account)
        val graph = LibreGraphSpacesClient(dependencies.clientFor(account), endpoints = endpoints)

        suspend fun currentSpace(disabled: Boolean = requireDisabled): RemoteSpace {
            checkAccess()
            if (dependencies.accountFor(accountId) != account) failChanged()
            val result = graph.snapshot(account.serverUrl, auth, includeAllSpaces = true, includeVaultDetails = true)
            checkAccess()
            return result.vaultSpaces.firstOrNull {
                it.id == expected.driveId &&
                    it.rootId == expected.sourceRootId &&
                    it.rootWebDavUrl == expected.rootWebDavUrl &&
                    it.type.equals("project", true) &&
                    it.disabled == disabled &&
                    !it.deleted
            } ?: failChanged()
        }
        val initial = currentSpace()
        return LifecycleScope(
            account = account,
            server = account.serverUrl,
            auth = auth,
            graph = graph,
            space = initial,
            currentSpace = { disabled -> currentSpace(disabled) },
            checkCurrent = {
                checkAccess()
                if (dependencies.accountFor(accountId) != account) failChanged()
            },
            requireFreshTarget = { currentSpace() },
        )
    }

    private suspend fun requireManagementAccount(accountId: String): AccountEntity {
        val account =
            dependencies.accountFor(accountId)
                ?: throw OpenCloudException(OpenCloudError.AuthenticationRequired)
        if (!account.isActive) throw OpenCloudException(OpenCloudError.AuthenticationRequired)
        return account
    }

    @Suppress("CyclomaticComplexMethod", "ComplexCondition") // Fail-closed account, kind, root and lease checks.
    private suspend fun <T> withFolderRoot(
        accountId: String,
        expected: VaultLocation,
        isUnlocked: () -> Boolean,
        action: suspend (FolderScope) -> T,
    ): T {
        if (expected.accountId != accountId ||
            expected.kind != VaultLocationKind.FOLDER_VAULT ||
            !expected.isVaultRoot ||
            expected.vaultPath.isEmpty()
        ) {
            failChanged()
        }
        val permit = dependencies.permitFor()

        fun checkLease() {
            if (!permit() || !isUnlocked()) throw OpenCloudException(OpenCloudError.AccessDenied)
        }
        checkLease()
        val account =
            dependencies.accountFor(accountId) ?: throw OpenCloudException(OpenCloudError.AuthenticationRequired)
        if (!account.isActive ||
            endpoints.endpoint(account.serverUrl, allowQuery = false).toString() != expected.canonicalServer
        ) {
            failChanged()
        }
        val parentPath = expected.vaultPath.substringBeforeLast('/', "")
        val current =
            dependencies
                .folderRootsFor(accountId, expected.driveId, parentPath)
                .firstOrNull { it.sameRoot(expected) } ?: failChanged()
        checkLease()
        if (dependencies.accountFor(accountId) != account) failChanged()
        val auth = dependencies.authorizationFor(account)
        checkLease()
        val http = dependencies.clientFor(account)
        val scope =
            FolderScope(
                server = account.serverUrl,
                auth = auth,
                location = current,
                ocs = OcsSharingClient(http),
                checkCurrent = {
                    currentCoroutineContext().ensureActive()
                    checkLease()
                    if (dependencies.accountFor(accountId) != account) failChanged()
                },
                requireFreshTarget = {
                    currentCoroutineContext().ensureActive()
                    checkLease()
                    if (dependencies
                            .folderRootsFor(
                                accountId,
                                expected.driveId,
                                parentPath,
                            ).none { it.sameRoot(expected) }
                    ) {
                        failChanged()
                    }
                    checkLease()
                    if (dependencies.accountFor(accountId) != account) failChanged()
                },
            )
        scope.checkCurrent()
        val result = action(scope)
        scope.checkCurrent()
        return result
    }

    private suspend fun SpaceScope.currentSpace(): RemoteSpace {
        checkCurrent()
        val candidate =
            graph
                .snapshot(server, auth, includeVaultDetails = true)
                .vaultSpaces
                .firstOrNull {
                    it.id == location.driveId &&
                        it.rootId == location.sourceRootId &&
                        it.rootWebDavUrl == location.rootWebDavUrl &&
                        it.type.equals("project", true) &&
                        !it.disabled &&
                        !it.deleted
                } ?: failChanged()
        checkCurrent()
        return candidate
    }

    private fun failChanged(): Nothing = throw OpenCloudException(OpenCloudError.PreconditionFailed)
}

internal fun VaultLocation.sameRoot(other: VaultLocation) =
    accountId == other.accountId &&
        canonicalServer == other.canonicalServer &&
        driveId == other.driveId &&
        remoteVaultId == other.remoteVaultId &&
        sourceRootId == other.sourceRootId &&
        rootWebDavUrl == other.rootWebDavUrl &&
        kind == other.kind &&
        vaultPath == other.vaultPath &&
        isVaultRoot

@Suppress("LongParameterList") // Test boundary injects each external authority separately.
internal class EncryptedManagementDependencies(
    val accountFor: suspend (String) -> AccountEntity?,
    val spaceRootsFor: suspend (String) -> List<VaultLocation>,
    val folderRootsFor: suspend (String, String, String) -> List<VaultLocation>,
    val authorizationFor: (AccountEntity) -> String,
    val clientFor: (AccountEntity) -> OkHttpClient,
    val permitFor: () -> () -> Boolean,
    val endpoints: EndpointPolicy = EndpointPolicy(),
) {
    companion object {
        fun live(context: Context): EncryptedManagementDependencies {
            val store = FileBrowserStore(FileBrowserDatabase.create(context))
            val vaults = VaultRepository(context, store)
            return EncryptedManagementDependencies(
                accountFor = store::account,
                spaceRootsFor = vaults::encryptedSpaces,
                folderRootsFor = vaults::encryptedFolders,
                authorizationFor = { WorkerAuthorizationProvider(context).authorization(it) },
                clientFor = { TlsPolicy(context).applyTo(OkHttpClient(), it.serverUrl) },
                permitFor = { AppLock(context).beginAppAction() },
            )
        }
    }
}

private data class FolderScope(
    val server: String,
    val auth: String,
    val location: VaultLocation,
    val ocs: OcsSharingClient,
    val checkCurrent: suspend () -> Unit,
    val requireFreshTarget: suspend () -> Unit,
)

private suspend fun FolderScope.folderShares(): List<RemoteShare> {
    checkCurrent()
    return ocs
        .listShares(server, auth, resourceId = location.remoteVaultId)
        .filter { it.isExactFolderShare(location) }
        .also { checkCurrent() }
}

internal fun RemoteShare.isExactFolderShare(location: VaultLocation): Boolean =
    isFolder && resourceId == location.remoteVaultId && type in setOf(OcsShareType.USER, OcsShareType.GROUP)

data class EncryptedSpaceDetails(
    val location: VaultLocation,
    val name: String,
    val subtitle: String?,
    val ownerName: String?,
    val quotaBytes: Long?,
    val quotaUsedBytes: Long?,
    val quotaRemainingBytes: Long?,
)

private data class SpaceScope(
    val server: String,
    val auth: String,
    val location: VaultLocation,
    val graph: LibreGraphSpacesClient,
    val members: SpaceMembersClient,
    val ocs: OcsSharingClient,
    val checkCurrent: suspend () -> Unit,
    val requireFreshTarget: suspend () -> Unit,
    val space: RemoteSpace? = null,
)

private data class LifecycleScope(
    val account: AccountEntity,
    val server: String,
    val auth: String,
    val graph: LibreGraphSpacesClient,
    val space: RemoteSpace,
    val currentSpace: suspend (Boolean) -> RemoteSpace,
    val checkCurrent: suspend () -> Unit,
    val requireFreshTarget: suspend () -> Unit,
)

private fun RemoteSpace.toVaultLocation(
    accountId: String,
    canonicalServer: String,
    disabled: Boolean,
) = VaultLocation(
    accountId = accountId,
    title = name,
    kind = VaultLocationKind.SPACE_VAULT,
    driveId = id,
    remoteVaultId = rootId,
    sourceRootId = rootId,
    canonicalServer = canonicalServer,
    rootWebDavUrl = rootWebDavUrl,
    vaultPath = "",
    isVaultRoot = true,
    isDisabled = disabled,
)

private fun RemoteSpace.toDetails(location: VaultLocation) =
    EncryptedSpaceDetails(
        location,
        name,
        description,
        ownerName,
        quotaTotalBytes,
        quotaUsedBytes,
        quotaRemainingBytes,
    )

private fun ProjectSpaceUpdate.matches(space: RemoteSpace): Boolean =
    (name == null || space.name == name?.trim()) &&
        (description == null || space.description == description) &&
        (quotaBytes == null || space.quotaTotalBytes == quotaBytes)
